/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "bearssl.h"
#include "inner.h"
#include "stm32wrapper.h"
#define U2      (4 + ((BR_MAX_RSA_FACTOR + 30) / 31))
#define TLEN_TMP  (((BR_MAX_RSA_FACTOR + 2*BR_RSA_RAND_FACTOR + 93) / 31 + 7) & ~1u)
#define ROTATE (1 << (3))


/*
 * Constant-time swap.
 *
 * If mask is 0xFFFFFFFF, then the arrays 'a' and 'b' (of 'n' words each)
 * are swapped.
 * If mask is 0x00000000, then the arrays are left unchanged.
 *
 * 'mask' MUST be either 0xFFFFFFFF or 0x00000000.
 */
static inline void
cswap(uint32_t *a, uint32_t *b, uint32_t mask, size_t n)
{
    // mask must be 0x00000000 or 0xFFFFFFFF
    for (size_t i = 0; i < n; i++) {
        uint32_t x = a[i] ^ b[i];
        x &= mask;
        a[i] ^= x;
        b[i] ^= x;
    }
}



/*
 * Randomly rotate the window contents.
 *
 * This function rotates the 'size' elements in the 'base' array by 'offset'
 * positions. The rotation is performed in constant time with respect to
 * 'offset'.
 *
 * offset: rotation amount (must be less than size).
 * winlen: window length in bits (size = 2^winlen - 1).
 * mwlen: length of each element in words.
 * base: pointer to the start of the array.
 */
void rand_swap(uint32_t offset, uint32_t winlen, size_t mwlen, uint32_t* base){
	uint32_t size = (1U << winlen) - 1;
    
    for (uint32_t k = 0; k < size; k++) {
        uint32_t do_rotate = -LT(k, offset);

        for (uint32_t i = size - 1; i > 0; i--) {
            uint32_t* left  = base + ((i - 1) * mwlen);
            uint32_t* right = base + (i * mwlen);
            
            cswap(left, right, do_rotate, mwlen);
        }
    }
}

/*
 * Reduce x modulo 2^k - 1.
 *
 * This function computes x mod (2^k - 1).
 * It is used to keep indices within the valid range for the window.
 */
static inline uint32_t
reduce(uint32_t x, int k)
{
	uint32_t mask, i;

	mask = ((uint32_t)1 << k) - 1;
	
	
	for (i = 0; i < 16; i ++) {
		x = (x >> k) + (x & mask);
	}

	
	return MUX(EQ(x, mask), 0, x);
}


void rand_perm(uint32_t idx, uint32_t update_idx, uint32_t winlen, size_t mwlen, uint32_t *idxs, uint32_t *base) {
    uint32_t size = (1U << winlen) - 1;
    uint32_t * left  = base;
	uint32_t * right = left + mwlen;
	uint32_t * new_val = base - mwlen;

	
    for (uint32_t i = 0; i < size -1; i++) {
        // Create an all-ones mask if i == idx
        uint32_t m_swap = -EQ(i, idx);
		uint32_t m_update = -EQ(idxs[i], update_idx);
        
        // Swap the big integer data
        //cswap(left, left + mwlen, mask, mwlen);
        for (size_t j = 0; j < mwlen; j++) {
            // 1. Conditional Update: inject new_val into 'left' if i == update_idx
            uint32_t val_x = (left[j] ^ new_val[j]) & m_update;
            left[j] ^= val_x;



            // 2. Conditional Swap: swap 'left' and 'right' if i == swap_idx
            uint32_t swap_x = (left[j] ^ right[j]) & m_swap;
            left[j] ^= swap_x;
            right[j] ^= swap_x;
        }
        // Swap the tracking index
      	cswap(idxs + i, idxs + i + 1, m_swap, 1);

        left += mwlen;
		right += mwlen;
    }
	uint32_t m_update = -EQ(idxs[size -1], update_idx);
	for (size_t j = 0; j < mwlen; j++) {
        // 1. Conditional Update: inject new_val into 'left' if i == update_idx
        uint32_t val_x = (left[j] ^ new_val[j]) & m_update;
        left[j] ^= val_x;
	}	
}

void sort3(uint32_t *arr, uint32_t * idxs, uint32_t* vals, size_t mwlen) {
    cswap(arr, arr + mwlen, -LE(idxs[0], idxs[1]), mwlen); cswap(vals, vals + 1, -LE(idxs[0], idxs[1]), 1);
	cswap(arr, arr + (2*mwlen), -LE(idxs[0], idxs[2]), mwlen); cswap(vals, vals + 2, -LE(idxs[0], idxs[2]), 1);
	cswap(arr + mwlen, arr + (2*mwlen), -LE(idxs[1], idxs[2]), mwlen); cswap(vals + 1, vals + 2, -LE(idxs[1], idxs[2]), 1);
} 


void sort7(uint32_t *arr, uint32_t *idxs, uint32_t *vals, size_t mwlen) {
#define CS7(i, j) \
    cswap(arr+(i)*mwlen, arr+(j)*mwlen, -LE(idxs[i], idxs[j]), mwlen); \
    cswap(vals+(i), vals+(j), -LE(idxs[i], idxs[j]), 1);
    CS7(0,1); CS7(2,3); CS7(4,5);
    CS7(0,2); CS7(1,3); CS7(4,6);
    CS7(1,2); CS7(5,6);
    CS7(0,4); CS7(1,5); CS7(2,6);
    CS7(1,4); CS7(3,6);
    CS7(2,4); CS7(3,5);
    CS7(3,4);
#undef CS7
}


void sort15(uint32_t *arr, uint32_t *idxs, uint32_t *vals, size_t mwlen) {
#define CS15(i, j) \
    cswap(arr+(i)*mwlen, arr+(j)*mwlen, -LE(idxs[i], idxs[j]), mwlen); \
    cswap(vals+(i), vals+(j), -LE(idxs[i], idxs[j]), 1);
    /* Layer 1 */
    CS15(0,1);  CS15(2,3);  CS15(4,5);  CS15(6,7);
    CS15(8,9);  CS15(10,11); CS15(12,13);
    /* Layer 2 */
    CS15(0,2);  CS15(1,3);  CS15(4,6);  CS15(5,7);
    CS15(8,10); CS15(9,11); CS15(12,14);
    /* Layer 3 */
    CS15(1,2);  CS15(5,6);  CS15(9,10); CS15(13,14);
    /* Layer 4 */
    CS15(0,4);  CS15(1,5);  CS15(2,6);  CS15(3,7);
    CS15(8,12); CS15(9,13); CS15(10,14);
    /* Layer 5 */
    CS15(2,4);  CS15(3,5);  CS15(10,12); CS15(11,13);
    /* Layer 6 */
    CS15(1,2);  CS15(3,4);  CS15(5,6);  CS15(9,10);
    CS15(11,12); CS15(13,14);
    /* Layer 7 */
    CS15(0,8);  CS15(1,9);  CS15(2,10); CS15(3,11);
    CS15(4,12); CS15(5,13); CS15(6,14);
    /* Layer 8 */
    CS15(4,8);  CS15(5,9);  CS15(6,10); CS15(7,11);
    /* Layer 9 */
    CS15(2,4);  CS15(3,5);  CS15(6,8);  CS15(7,9);
    CS15(10,12); CS15(11,13);
    /* Layer 10 */
    CS15(1,2);  CS15(3,4);  CS15(5,6);  CS15(7,8);
    CS15(9,10); CS15(11,12); CS15(13,14);
#undef CS15
}


/*
 * Sample a uniform random integer in [0, i) in constant time.
 *
 * Algorithm: always runs exactly N iterations (no early exit).
 * Each iteration draws k random bits, masks to k' = ceil(log2(i+1)) bits,
 * and conditionally updates r if the sample falls in [0, i).
 * k must satisfy 2^k > i; N must be large enough that (2^k' - i) / 2^k'
 * raised to the power N is negligible.
 */
static uint32_t
sample_uniform_ct(uint32_t i, int N)
{
    /* k' = number of bits needed: smallest k' s.t. 2^k' > i */
    uint32_t kp = 0;
    uint32_t tmp = i;
    while (tmp > 0) { kp++; tmp >>= 1; }
    uint32_t mask = (1U << kp) - 1;

    uint32_t r = 0;
    for (int n = 0; n < N; n++) {
        uint32_t x;
        make_rand(&x, 32);
        x &= mask;
        /* r = (i > x) ? x : r, constant-time via MUX */
        r = MUX(GT(i, x), x, r);
    }
    return r;
}


/*
 * Constant-time Fisher-Yates shuffle.
 *
 * For each step i from (n-1) down to 1, pick j uniformly in [0, i+1) using
 * sample_uniform_ct, then scan all positions k in [0, i] and conditionally
 * swap arr[i] with arr[k] when k == j.  The inner loop always touches every
 * element so no data-dependent memory access pattern is visible.
 */
static void
fisher_yates_ct(uint32_t *arr, int n)
{
    for (int i = n - 1; i >= 1; i--) {
        uint32_t j = sample_uniform_ct((uint32_t)(i + 1), 1);
        for (int k = 0; k <= i; k++) {
            /* swap arr[i] and arr[k] iff k == j, constant-time */
            int t = (arr[i] ^ arr[k]) & -(int)EQ((uint32_t)k, j);
            arr[i] ^= t;
            arr[k] ^= t;
        }
    }
}


/* see inner.h */
uint32_t
br_i31_modpow_opt_rand(uint32_t *x,
	const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *tmp, size_t twlen)
{	
	size_t mlen, mwlen;
	uint32_t *t1, *t2, *base;
	size_t u, v;
	uint32_t acc;
	int acc_len, win_len, prev_bitlen;
	uint32_t BUFF[TLEN_TMP];
	uint32_t ONE[TLEN_TMP];

	uint32_t r[(((4*BR_RSA_RAND_FACTOR)) + 63) >> 5];
	uint32_t new_r[(BR_RSA_RAND_FACTOR + 63) >> 5];
	
	make_rand( r, (BR_RSA_RAND_FACTOR + 32));
	r[1] |= 1;

	uint32_t* curr_m = BUFF;
	uint32_t* one = ONE;

	br_i31_zero(curr_m, m[0]);
	br_i31_mulacc(curr_m, m, r);




	m0i = br_i31_ninv31(curr_m[1]);
	
	
	/*
	 * Get modulus size.
	 */
	mwlen = ( curr_m[0] + BR_RSA_RAND_FACTOR + 61) / 31;
	mlen = mwlen * sizeof curr_m[0];
	mwlen += (mwlen & 1);
	t1 = tmp;
	t2 = tmp + mwlen;
    
	
	
    /*
     * We increased the moudulus size, now we zero words in x up to the modulus size
     */
	uint32_t x_length = (x[0] + 63) >> 5;
	for(;x_length < (curr_m[0] + 63 + BR_RSA_RAND_FACTOR) >> 5; ++x_length){
		x[x_length] = 0;
	}
	x[0] = curr_m[0];

	
	/*
	 * Compute possible window size, with a maximum of 5 bits.
	 * When the window has size 1 bit, we use a specific code
	 * that requires only two temporaries. Otherwise, for a
	 * window of k bits, we need 2^k+1 temporaries.
	 */
	if (twlen < (mwlen << 1)) {
		return 0;
	}
	for (win_len = 4; win_len > 1; win_len --) {
		
		if ((((uint32_t)1 << win_len) + 1) * mwlen <= twlen) {
			break;
		}
	}
	
	
	
	m0i = br_i31_ninv31(curr_m[1]);

	/*
	 * Everything is done in Montgomery representation.
	 */
	
	prev_bitlen = curr_m[0];
	br_i31_to_monty(x, curr_m);	
	
	
	/*
	 * Compute window contents. If the window has size one bit only,
	 * then t2 is set to x; otherwise, t2[0] is left untouched, and
	 * t2[k] is set to x^k (for k >= 1).
	 */
	if (win_len == 1) {
		memcpy(t2, x, mlen);
	} else {
		memcpy(t2 + mwlen, x, mlen);
		base = t2 + mwlen;
		for (u = 2; u < ((unsigned)1 << win_len); u ++) {

			//make_rand(  new_r, BR_RSA_RAND_FACTOR  );
			//new_r[1] |= 1;

			//br_i31_zero(curr_m, curr_m[0] + 4*BR_RSA_RAND_FACTOR);
			//br_i31_mulacc(curr_m, m, new_r);
			//m0i = br_i31_ninv31(curr_m[1]);
			//curr_m[0] = prev_bitlen;			

			br_i31_montymul(base + mwlen, base, x, curr_m, m0i);
			

			base += mwlen;
		}
	}

	
	

	uint32_t idxs[15]; 
	uint32_t vals[15]; 
	uint32_t num_elements = (1U << win_len) - 1;
	base = t2 + mwlen;

	for (uint32_t i = 0; i < num_elements; i++) {
		vals[i] = (i + 1);
		idxs[i] = (i + 1);
	}
	

	//rand_perm(perm_rand, -1, win_len, mwlen, idxs, t2 + mwlen);
	
	fisher_yates_ct(idxs, num_elements);
	
	base = t2 + mwlen;
	if(num_elements == 15){
		sort15(base, idxs, vals, mwlen);
	}

	if(num_elements == 7){
		sort7(base, idxs, vals, mwlen);
	}

	if(num_elements == 3){
		sort3(base, idxs, vals, mwlen);
	}
	
	br_i31_zero(curr_m, prev_bitlen);
	br_i31_mulacc(curr_m, m, r);

	

	m0i = br_i31_ninv31(curr_m[1]);
	prev_bitlen = curr_m[0];

	/*
	 * We need to set x to 1, in Montgomery representation. This can
	 * be done efficiently by setting the high word to 1, then doing
	 * one word-sized shift.
	 */

	br_i31_zero(x, curr_m[0]);
	x[(curr_m[0] + 31) >> 5] = 1;
	br_i31_muladd_small(x, 0, curr_m);


	br_i31_zero(one, curr_m[0]);
	one[(curr_m[0] + 31) >> 5] = 1;
	br_i31_muladd_small(one, 0, curr_m);
	/*
	 * We process bits from most to least significant. At each
	 * loop iteration, we have acc_len bits in acc.
	 */
	acc = 0;
	acc_len = 0;
	int swap_count = 0;

	while (acc_len > 0 || elen > 0) {
		int i, k;
		uint32_t bits;

		/*
		 * Get the next bits.
		 */
		k = win_len;
		if (acc_len < win_len) {
			if (elen > 0) {
				acc = (acc << 8) | *e ++;
				elen --;
				acc_len += 8;
			} else {
				k = acc_len;
			}
		}
		bits = (acc >> (acc_len - k)) & (((uint32_t)1 << k) - 1);
		acc_len -= k;

		make_rand( new_r, BR_RSA_RAND_FACTOR  );
		new_r[1] |= 1;

		br_i31_zero(curr_m, curr_m[0]);
		br_i31_mulacc(curr_m, m, new_r);
		m0i = br_i31_ninv31(curr_m[1]);
		curr_m[0] = prev_bitlen;
		


		/*
		 * We could get exactly k bits. Compute k squarings.
		 */

		for (i = 0; i < k; i ++) {
			br_i31_montymul(t1, x, x, curr_m, m0i);
			memcpy(x, t1, mlen);
		}


		/*
		 * Window lookup: we want to set t2 to the window
		 * lookup value, assuming the bits are non-zero. If
		 * the window length is 1 bit only, then t2 is
		 * already set; otherwise, we do a constant-time lookup.
		 */
		if (win_len > 1) {
			memset(t2, 0, mlen);
			t2[0] = curr_m[0];
			base = t2 + mwlen;
			int offset = 0;
			uint32_t * perm_base = base + (offset * mwlen);
			for (u = 1; u < ((uint32_t)1 << win_len); u ++) {
				uint32_t mask;
				mask = -EQ(vals[u - 1], bits);
				for (v = 1; v < mwlen; v ++) {
					t2[v] |= mask & perm_base[v];
				}
				
				offset += 1;
				//offset = reduce(offset, win_len);
				perm_base = base + (offset * mwlen);
			}
		}

		/*
		 * Multiply with the looked-up value. We keep the
		 * product only if the exponent bits are not all-zero.
		 */

		
		br_i31_montymul(t1, x, t2, curr_m, m0i);
		CCOPY(NEQ(bits, 0), x, t1, mlen);
		
		br_i31_montymul(t1, one, t2, curr_m, m0i);
		CCOPY(NEQ(bits, 0), t2, t1, mlen);
		base = t2 + mwlen;
		for (u = 1; u < ((uint32_t)1 << win_len); u ++) {
			CCOPY(EQ(bits, vals[u - 1]), base, t2, mlen);
			base = base + mwlen;
		}
		base = t2 + mwlen;
		//make_rand( rng, new_r, 32 );
		//uint32_t r1 = reduce(new_r[1], win_len);
		//rand_perm(r1, bits, win_len, mwlen, idxs, t2 + mwlen);
		if (++swap_count == 1){
			fisher_yates_ct(idxs, num_elements);
		
			base = t2 + mwlen;
			if(num_elements == 15){
				sort15(base, idxs, vals, mwlen);
			}

			if(num_elements == 7){
				sort7(base, idxs, vals, mwlen);
			}

			if(num_elements == 3){
				sort3(base, idxs, vals, mwlen);
			}
			swap_count = 0;
		}

	}
	/*
	 * Convert back from Montgomery representation, and exit.
	 */

	br_i31_zero(curr_m, prev_bitlen);
	br_i31_mulacc(curr_m, m, r);
	curr_m[0] = prev_bitlen;
	m0i = br_i31_ninv31(curr_m[1]);
	memcpy(t1 + 1, x + 1, (curr_m[0] + 7) >> 3);
	t1[0] = x[0];
	br_i31_from_monty(t1, curr_m, m0i);
	
	br_i31_reduce(x, t1, m);
	
	return 1;
}


