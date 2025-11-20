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
#define NUM_OF_CUMMULT 3
#define U2      (4 + ((BR_MAX_RSA_FACTOR + 30) / 31))
#define TLEN_TMP   (4 * U2)

static void cummult(const uint32_t * orig_m, uint32_t * rand_m, uint32_t* tmp, uint32_t * r){

		make_rand(  r, (BR_RSA_RAND_FACTOR / (NUM_OF_CUMMULT)) );
		r[1] |= 1;
		r[0] = br_i31_bit_length(r + 1, ((BR_RSA_RAND_FACTOR / NUM_OF_CUMMULT) + 31) >> 5);

		br_i31_zero(rand_m, rand_m[0]);
		br_i31_mulacc(rand_m, orig_m, r);

		for (int i = 1; i < NUM_OF_CUMMULT; ++i){
			make_rand( r, (BR_RSA_RAND_FACTOR / (NUM_OF_CUMMULT)) );
			r[1] |= 1;
			r[0] = br_i31_bit_length(r + 1, ((BR_RSA_RAND_FACTOR / (NUM_OF_CUMMULT)) + 31) >> 5);
			br_i31_zero(tmp, rand_m[0]);
			br_i31_mulacc(tmp, rand_m, r);
			br_i31_zero(rand_m, tmp[0]);
			memcpy(rand_m + 1, tmp +1, (tmp[0] + 7) >> 3);
			rand_m[0] = tmp[0];
			rand_m[0] = br_i31_bit_length(rand_m + 1 , (rand_m[0] + 31) >> 5);
		}
}


void cswap(uint32_t *a, uint32_t *b, uint32_t mask, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint32_t x = a[i] ^ b[i];
        x &= mask;
        a[i] ^= x;
        b[i] ^= x;
    }
}


void rand_swap(uint32_t offset, uint32_t winlen, size_t mwlen, uint32_t* base){
	uint32_t j = offset;
	uint32_t * left = base;
	uint32_t * right;
	uint32_t size = (1<<winlen);
	uint32_t s1   = size - 1u;

    for (uint32_t i = 0u; i < size - 2; i++){        
	    for (uint32_t u = 0u; u < size - 1; u++){
	        right = (base + (u*mwlen));
	        uint32_t mask = -EQ(j, u);
            cswap(left, right, mask, mwlen); 
        }        
		j += offset;
	    uint32_t ge = GE(j, s1);        
        j -= ge * s1;  
	}  
}


/* see inner.h */
uint32_t
br_i31_modpow_opt_rand2(uint32_t n_size, uint32_t *x,
	const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *tmp, size_t twlen)
{	
	size_t mlen, mwlen;
	uint32_t *t1, *t2, *base;
	size_t u, v;
	uint32_t acc;
	int acc_len, win_len, prev_bitlen;
	uint32_t BUFF[2*TLEN_TMP];
	uint32_t r[(((4*BR_RSA_RAND_FACTOR)) + 63) >> 5];
	uint32_t new_r[(BR_RSA_RAND_FACTOR + 63) >> 5];
	
	make_rand(r, (BR_RSA_RAND_FACTOR + 32));
	r[1] |= 1;
	

	uint32_t* curr_m = BUFF;
	
	br_i31_zero(curr_m, m[0]);
	br_i31_mulacc(curr_m, m, r);

	
	


	m0i = br_i31_ninv31(curr_m[1]);
	prev_bitlen = curr_m[0];
	
	/*
	 * Get modulus size.
	 */
	mwlen = ( curr_m[0] + 63 + 4*BR_RSA_RAND_FACTOR) >> 5;
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
	for (win_len = 5; win_len > 1; win_len --) {
		if ((((uint32_t)1 << win_len) + 1) * mwlen <= twlen) {
			break;
		}
	}
	
	
	
	m0i = br_i31_ninv31(curr_m[1]);
	prev_bitlen = curr_m[0];
	/*
	 * Everything is done in Montgomery representation.
	 */
	
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

			make_rand( new_r, BR_RSA_RAND_FACTOR  );
			new_r[1] |= 1;

			br_i31_zero(curr_m, curr_m[0]);
			br_i31_mulacc(curr_m, m, new_r);
			m0i = br_i31_ninv31(curr_m[1]);
			curr_m[0] = prev_bitlen;			

			br_i31_montymul(base + mwlen, base, x, curr_m, m0i);
			base += mwlen;
		}
	}

	make_rand( new_r, 32 );
	uint32_t M = (uint32_t)(((uint64_t)1u << win_len) - 1u);
	uint32_t perm_rand = br_rem(0, new_r[1], M);
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
	char str[100];
	acc = 0;
	acc_len = 0;
	int o = 0;
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
			br_i31_zero(t2, curr_m[0]);
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
				offset = br_rem(0, offset, M);
				perm_base = base + (offset * mwlen);
			}
		}

		/*
		 * Multiply with the looked-up value. We keep the
		 * product only if the exponent bits are not all-zero.
		 */

		
		br_i31_montymul(t1, x, t2, curr_m, m0i);
		CCOPY(NEQ(bits, 0), x, t1, mlen);

		
		make_rand(  new_r, 32 );
		uint32_t r1 = br_rem(0, new_r[1], M);
	 	perm_rand += r1;
	 	perm_rand = br_rem(0, perm_rand, M);
		rand_swap(r1, win_len, mwlen, t2 + mwlen);
		o++;
	}
		
	sprintf(str, "Cost of cycle: %d", o);
 	send_USART_str((unsigned char*)str);
	/*
	 * Convert back from Montgomery representation, and exit.
	 */

	br_i31_zero(curr_m, prev_bitlen);
	br_i31_mulacc(curr_m, m, r);
		
	m0i = br_i31_ninv31(curr_m[1]);
	prev_bitlen = curr_m[0];

	br_i31_from_monty(t1, curr_m, m0i);
	br_i31_zero(curr_m, curr_m[0]);
	memcpy(curr_m + 1, m + 1, (m[0] + 7) >> 3);
	curr_m[0] = br_i31_bit_length(curr_m + 1, (curr_m[0] + 31) >> 5);

	
	br_i31_reduce(x, t1, curr_m);
	
	return 1;
}



/* see inner.h */
uint32_t
br_i31_modpow_opt_rand( uint32_t *x,
	const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *tmp, size_t twlen)
{	
	size_t mlen, mwlen;
	uint32_t *t1, *t2, *base;
	size_t u, v;
	uint32_t acc;
	int acc_len, win_len, prev_bitlen;
	uint32_t BUFF[2*TLEN_TMP];
	uint32_t r[(((4*BR_RSA_RAND_FACTOR)) + 63) >> 5];
	uint32_t new_r[(BR_RSA_RAND_FACTOR + 63) >> 5];
	
	make_rand(r, (BR_RSA_RAND_FACTOR + 32));
	r[1] |= 1;
	r[0] = br_i31_bit_length(r + 1, (((BR_RSA_RAND_FACTOR + 32)) + 31) >> 5);


	
	uint32_t* curr_m = BUFF;
	
	br_i31_zero(curr_m, m[0]);
	br_i31_mulacc(curr_m, m, r);
	curr_m[0] = br_i31_bit_length(curr_m + 1 , (curr_m[0] + 31) >> 5);




	m0i = br_i31_ninv31(curr_m[1]);
	prev_bitlen = curr_m[0];
	
	/*
	 * Get modulus size.
	 */
	mwlen = (curr_m[0] + 63 + BR_RSA_RAND_FACTOR) >> 5;
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
	for (win_len = 3; win_len > 1; win_len --) {
		if ((((uint32_t)1 << win_len) + 1) * mwlen <= twlen) {
			break;
		}
	}
	
	
	
	m0i = br_i31_ninv31(curr_m[1]);
	prev_bitlen = curr_m[0];
	/*
	 * Everything is done in Montgomery representation.
	 */
	
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

			//cummult(rng, m, curr_m, t2, new_r);
			make_rand( new_r, BR_RSA_RAND_FACTOR  );
			new_r[1] |= 1;
			new_r[0] = br_i31_bit_length(new_r + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);

			br_i31_zero(curr_m, curr_m[0]);
			br_i31_mulacc(curr_m, m, new_r);
			m0i = br_i31_ninv31(curr_m[1]);
			curr_m[0] = prev_bitlen;			

			br_i31_montymul(base + mwlen, base, x, curr_m, m0i);
			base += mwlen;
		}
	}

	make_rand( new_r, 32 );
	uint32_t perm_rand = 0;new_r[1] % ((1<<win_len)  -1);
	rand_swap(perm_rand, win_len, mwlen, t2 + mwlen);

	br_i31_zero(curr_m, prev_bitlen);
	br_i31_mulacc(curr_m, m, r);
	curr_m[0] = br_i31_bit_length(curr_m + 1 , (curr_m[0] + 31) >> 5);

	

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
	int o = 0;
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
		new_r[0] = br_i31_bit_length(new_r + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);

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
			br_i31_zero(t2, curr_m[0]);
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
				offset %=  (1<<win_len) - 1;
				perm_base = base + (offset * mwlen);
			}
		}

		/*
		 * Multiply with the looked-up value. We keep the
		 * product only if the exponent bits are not all-zero.
		 */

		
		br_i31_montymul(t1, x, t2, curr_m, m0i);
		CCOPY(NEQ(bits, 0), x, t1, mlen);

		
		make_rand(  new_r, 32 );
		new_r[1] %= ((1<<win_len) - 1);
	 	perm_rand += new_r[1];
	 	perm_rand %= ((1<<win_len) - 1);
		rand_swap(new_r[1], win_len, mwlen, t2 + mwlen);
	}

	/*
	 * Convert back from Montgomery representation, and exit.
	 */

	br_i31_zero(curr_m, prev_bitlen);
	br_i31_mulacc(curr_m, m, r);
	curr_m[0] = br_i31_bit_length(curr_m + 1 , (curr_m[0] + 31) >> 5);
	
	
	
	m0i = br_i31_ninv31(curr_m[1]);
	prev_bitlen = curr_m[0];

	br_i31_from_monty(t1, curr_m, m0i);
	br_i31_zero(curr_m, curr_m[0]);
	memcpy(curr_m + 1, m + 1, (m[0] + 7) >> 3);
	curr_m[0] = br_i31_bit_length(curr_m + 1, (curr_m[0] + 31) >> 5);
	br_i31_reduce(x, t1, curr_m);
	
	return 1;
}


