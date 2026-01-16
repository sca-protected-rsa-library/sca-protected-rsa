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
#define TLEN_TMP   (6 * U2)
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
	uint32_t r[(((4*BR_RSA_RAND_FACTOR)) + 63) >> 5];
	uint32_t new_r[(BR_RSA_RAND_FACTOR + 63) >> 5];
	
	make_rand( r, (BR_RSA_RAND_FACTOR + 32));
	r[1] |= 1;

	uint32_t* curr_m = BUFF;
	br_i31_zero(curr_m, m[0]);
	br_i31_mulacc(curr_m, m, r);




	m0i = br_i31_ninv31(curr_m[1]);
	
	
	/*
	 * Get modulus size.
	 */
	mwlen = ( curr_m[0] + 4*BR_RSA_RAND_FACTOR + 61) / 31;
	mlen = mwlen * sizeof curr_m[0];
	mwlen += (mwlen & 1);
	t1 = tmp + mwlen;
	t2 = tmp + 2 * mwlen;
    
	
	
    /*
     * We increased the moudulus size, now we zero words in x up to the modulus size
     */
	uint32_t x_length = (x[0] + 63) >> 5;
	for(;x_length < (curr_m[0] + 63 + 4*BR_RSA_RAND_FACTOR) >> 5; ++x_length){
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
		
		if ((((uint32_t)1 << win_len) + 2) * mwlen <= twlen) {
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

			make_rand(  new_r, BR_RSA_RAND_FACTOR  );
			new_r[1] |= 1;

			br_i31_zero(curr_m, curr_m[0] + 4*BR_RSA_RAND_FACTOR);
			br_i31_mulacc(curr_m, m, new_r);
			m0i = br_i31_ninv31(curr_m[1]);
			curr_m[0] = prev_bitlen;			

			br_i31_montymul(base + mwlen, base, x, curr_m, m0i);
			

			base += mwlen;
		}
	}

	
	make_rand(  new_r, 32 );

	uint32_t perm_rand = reduce(new_r[1], win_len);

	
	rand_swap(perm_rand, win_len, mwlen, t2 + mwlen);

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
			int offset = perm_rand;
			uint32_t * perm_base = base + (offset * mwlen);
			for (u = 1; u < ((uint32_t)1 << k); u ++) {
				uint32_t mask;
				mask = -EQ(u, bits);
				for (v = 1; v < mwlen; v ++) {
					t2[v] |= mask & perm_base[v];
				}
				
				offset += 1;
				offset = reduce(offset, win_len);
				perm_base = base + (offset * mwlen);
			}
		}

		/*
		 * Multiply with the looked-up value. We keep the
		 * product only if the exponent bits are not all-zero.
		 */

		
		br_i31_montymul(t1, x, t2, curr_m, m0i);
		CCOPY(NEQ(bits, 0), x, t1, mlen);
		if (++swap_count == ROTATE){
			make_rand( new_r, 32 );
			uint32_t r1 = reduce(new_r[1], win_len);
		 	perm_rand += r1;
		 	perm_rand = reduce(perm_rand, win_len);
			rand_swap(r1, win_len, mwlen, t2 + mwlen);
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
	br_i31_from_monty(t1, curr_m, m0i);
	
	br_i31_reduce(x, t1, m);
	
	return 1;
}


