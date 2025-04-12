/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
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

#define U      (2 + ((BR_MAX_RSA_FACTOR + 30) / 31))
#define TLEN   (36 * U)



/* see bearssl_rsa.h */
uint32_t
br_rsa_i31_private_blind_mod(unsigned char *x, const br_rsa_private_key *sk)
{
	const unsigned char *p, *q;
	size_t plen, qlen;
	size_t fwlen;
	uint32_t p0i, q0i;
	size_t xlen, u;
	uint32_t tmp[1 + TLEN];
	long z;
	uint32_t *mp, *mq, *s1, *s2, *t1, *t2, *t3;
	uint32_t r;

	mq = tmp;
	

	uint32_t r1[4];
	make_rand( r1, 64);
	r1[0] = br_i31_bit_length(r1 + 1, 2);
	

	/*
	 * Compute the actual lengths of p and q, in bytes.
	 * These lengths are not considered secret (we cannot really hide
	 * them anyway in constant-time code).
	 */
	p = sk->p;
	plen = sk->plen;
	while (plen > 0 && *p == 0) {
		p ++;
		plen --;
	}
	q = sk->q;
	qlen = sk->qlen;
	while (qlen > 0 && *q == 0) {
		q ++;
		qlen --;
	}

	/*
	 * Compute the maximum factor length, in words.
	 */
	z = (long)(plen > qlen ? plen : qlen) << 3;
	fwlen = 1 + 3 + 8;
	while (z > 0) {
		z -= 31;
		fwlen ++;
	}

	/*
	 * Round up the word length to an even number.
	 */
	fwlen += (fwlen & 1);

	/*
	 * We need to fit at least 6 values in the stack buffer.
	 */
	if (20 * fwlen > TLEN) {
		return 0;
	}

	/*
	 * Compute modulus length (in bytes).
	 */
	xlen = (sk->n_bitlen + 7) >> 3;

	/*
	 * Decode q.
	 */
	mq = tmp;
	br_i31_decode(mq, q, qlen);
	/*
	 * Decode p.
	 */
	t1 = mq + fwlen;
	br_i31_decode(t1, p, plen);
	/*
	 * Compute the modulus (product of the two factors), to compare
	 * it with the source value. We use br_i31_mulacc(), since it's
	 * already used later on.
	 */
	t2 = mq + 2 * fwlen;
	br_i31_zero(t2, mq[0]);
	br_i31_mulacc(t2, mq, t1);
	uint32_t len = br_i31_bit_length(t2 , (t2[0] + 63) >> 5);
	if(t2[0] + 32 > len){
		t2[0] = len - 32;
	}
	else{
		t2[0] = t2[0];
	}
	/*
	 * We encode the modulus into bytes, to perform the comparison
	 * with bytes. We know that the product length, in bytes, is
	 * exactly xlen.
	 * The comparison actually computes the carry when subtracting
	 * the modulus from the source value; that carry must be 1 for
	 * a value in the correct range. We keep it in r, which is our
	 * accumulator for the error code.
	 */
	t3 = mq + 4 * fwlen;
	br_i31_encode(t3, xlen, t2);
	u = xlen;
	r = 0;
	while (u > 0) {
		uint32_t wn, wx;

		u --;
		wn = ((unsigned char *)t3)[u];
		wx = x[u];
		r = ((wx - (wn + r)) >> 8) & 1;
	}
	
	
	/*
	 * Compute (r^e * C) (mod n)
	 */	
	
	uint32_t *n = t2;
	uint32_t *c = t3;
	uint32_t *c_prime = mq + 6 * fwlen;
	uint32_t * r_to_e = mq;	
	
	br_i31_zero(c, n[0]);
	br_i31_decode_reduce(c, x, xlen, n);
	
	br_i31_zero(r_to_e, n[0]);
	memcpy(r_to_e + 1, r1 + 1,  ((*r1 + 7) >> 3));
	r_to_e[0] = n[0];

	r &= br_i31_modpow_opt(r_to_e, sk->e,sk->elen, n,  br_i31_ninv31(n[1]), mq + 8 * fwlen, TLEN - 8 * fwlen);

	
	br_i31_zero(c_prime, n[0]);
	c[0] = c_prime[0];
	br_i31_mulacc(c_prime, c, r_to_e);
	
	
	mq = tmp + 4 * fwlen;
	mp = tmp + 5 * fwlen;



	br_i31_decode(mq, sk->q, sk->qlen);
	br_i31_decode(mp, sk->p, sk->plen);
	

	s2 = tmp;
	s1 = tmp + fwlen;
	/*
	 * store C' = r^e * C in s1 (mod p)
	 * store C' = r^e * C in s2 (mod q)
	 */

	br_i31_reduce(s1, c_prime, mp);
	br_i31_reduce(s2, c_prime, mq);
	
	/*
	 * Move the decoded p to another temporary buffer.
	 */
	
	

	/*
	 * Compute s2 = x^dq mod q.
	 */
	q0i = br_i31_ninv31(mq[1]);

	unsigned char* dq = (unsigned char *) (tmp + 6 *fwlen); 
	mq[1] ^= 1; 
	size_t dqlen = blind_exponent( dq, sk->dq, sk->dqlen, mq, tmp + 7 * fwlen);
	mq[1] ^= 1; 
	r &= br_i31_modpow_opt_rand( s2, dq, dqlen, mq, q0i,
		tmp + 7 * fwlen, TLEN - 7 * fwlen);


	/*
	 * Compute s1 = x^dp mod p.
	 */
	p0i = br_i31_ninv31(mp[1]);
	unsigned char* dp = (unsigned char *) (tmp + 6 *fwlen);
	mp[1] ^= 1; 
	size_t dplen = blind_exponent( dp, sk->dp, sk->dplen, mp, tmp + 7 * fwlen);
	mp[1] ^= 1; 

	r &= br_i31_modpow_opt_rand( s1, dp, dplen, mp, p0i,
		tmp + 7 * fwlen, TLEN - 7 * fwlen);
	
	/*
	 * Compute:
	 *   h = (s1 - s2)*(1/q) mod p
	 * s1 is an integer modulo p, but s2 is modulo q. PKCS#1 is
	 * unclear about whether p may be lower than q (some existing,
	 * widely deployed implementations of RSA don't tolerate p < q),
	 * but we want to support that occurrence, so we need to use the
	 * reduction function.
	 *
	 * Since we use br_i31_decode_reduce() for iq (purportedly, the
	 * inverse of q modulo p), we also tolerate improperly large
	 * values for this parameter.
	 */
	t1 = tmp + 6 * fwlen;
	t2 = tmp + 7 * fwlen;
	br_i31_reduce(t2, s2, mp); 
	br_i31_add(s1, mp, br_i31_sub(s1, t2, 1));
	br_i31_to_monty(s1, mp);
	br_i31_decode_reduce(t1, sk->iq, sk->iqlen, mp);
	br_i31_montymul(t2, s1, t1, mp, p0i);
	
	/*
	 * h is now in t2. We compute the final result:
	 *   s = s2 + q*h
	 * All these operations are non-modular.
	 *
	 * We need mq, s2 and t2. We use the t3 buffer as destination.
	 * The buffers mp, s1 and t1 are no longer needed, so we can
	 * reuse them for t3. Moreover, the first step of the computation
	 * is to copy s2 into t3, after which s2 is not needed. Right
	 * now, mq is in slot 0, s2 is in slot 1, and t2 is in slot 5.
	 * Therefore, we have ample room for t3 by simply using s2.
	 */
	t3 = s2;
	br_i31_mulacc(t3, mq, t2);
	t1 = tmp + 4 * fwlen;
	br_i31_zero(t1, n[0]);
	memcpy(t1 + 1, r1 + 1, (*r1 + 7) >> 3);
	t3[0] = n[0];
	t1[0] = n[0];
	r &= br_i31_moddiv(t3, t1, n, br_i31_ninv31(n[1]), tmp + 6 * fwlen);

	/*
	 * Encode the result. Since we already checked the value of xlen,
	 * we can just use it right away.
	 */
	br_i31_encode(x, xlen, t3);

	/*
	 * The only error conditions remaining at that point are invalid
	 * values for p and q (even integers).
	 */
	return p0i & q0i & r;
}
