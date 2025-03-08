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

#include "../stm32wrapper.h"
#include "bearssl.h"
#include "inner.h"
#define U      (2 + ((BR_MAX_RSA_FACTOR + 30) / 31))
#define TLEN   (24 * U)


/* see bearssl_rsa.h */
uint32_t
br_rsa_i31_private_FI(unsigned char *x, const br_rsa_private_key *sk)
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
        fwlen =  1 + 18;
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
        if (6 * fwlen > TLEN) {
                return 0;
        }

        /*
         * Compute modulus length (in bytes).
         */
        xlen = (sk->n_bitlen + 7) >> 3;
    
  
        br_rsa_private_key rsa_sk;
        mq = tmp;
        uint32_t r2[(BR_RSA_RAND_FACTOR + 63) >> 5];
        uint32_t r3[(BR_RSA_RAND_FACTOR + 63) >> 5];
        uint32_t phi_p[(BR_MAX_RSA_SIZE + BR_RSA_RAND_FACTOR +  63) >> 5];
        uint32_t phi_q[(BR_MAX_RSA_SIZE + BR_RSA_RAND_FACTOR + 63) >> 5];
        unsigned char n_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
        unsigned char p_buf[(BR_MAX_RSA_SIZE + BR_RSA_RAND_FACTOR + 15) >> 3];
        unsigned char q_buf[(BR_MAX_RSA_SIZE + BR_RSA_RAND_FACTOR + 15) >> 3];
        unsigned char dp_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
        unsigned char dq_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
        unsigned char iq_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
        unsigned char e_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
        rsa_sk.r1 = r2;
        rsa_sk.r2 = r3;
        rsa_sk.n = n_buf;
        rsa_sk.p = p_buf;
        rsa_sk.q = q_buf;
        rsa_sk.dp = dp_buf;
        rsa_sk.dq = dq_buf;
        rsa_sk.iq = iq_buf;
        rsa_sk.phi_p = phi_p;
        rsa_sk.phi_q = phi_q;
        rsa_sk.e = e_buf;
    
       

       
    
        uint32_t r1[(BR_RSA_RAND_FACTOR + 63) >> 5];

        make_rand( r1, BR_RSA_RAND_FACTOR);
        r1[1] |= 1;
        r1[0] = br_i31_bit_length(r1 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);
        
        rsa_sk.n_bitlen = sk->n_bitlen;
        memcpy(rsa_sk.n, sk->n, (sk->n_bitlen +7) >> 3);
        memcpy(rsa_sk.e, sk->e, sk->elen);
        rsa_sk.elen = sk->elen;
        memcpy(rsa_sk.p, sk->p, sk->plen);
        rsa_sk.plen = sk->plen;
        memcpy(rsa_sk.q, sk->q, sk->qlen);
        rsa_sk.qlen = sk->qlen;
        memcpy(rsa_sk.iq, sk->iq, sk->iqlen);
        rsa_sk.iqlen = sk->iqlen;
        memcpy(rsa_sk.dp, sk->dp, sk->dplen);
        rsa_sk.dplen = sk->dplen;
        memcpy(rsa_sk.dq, sk->dq, sk->dqlen);
        rsa_sk.dqlen = sk->dqlen;

        memcpy(rsa_sk.r1 + 1, sk->r1 + 1, (sk->r1[0] + 7) >> 3);
        rsa_sk.r1[0] = sk->r1[0];

        memcpy(rsa_sk.r2 + 1, sk->r2 + 1, (sk->r2[0] + 7) >> 3);
        rsa_sk.r2[0] = sk->r2[0];

        memcpy(rsa_sk.phi_p + 1, sk->phi_p + 1, (sk->phi_p[0] + 7) >> 3);
        rsa_sk.phi_p[0] = sk->phi_p[0];

        memcpy(rsa_sk.phi_q + 1, sk->phi_q + 1, (sk->phi_q[0] + 7) >> 3);
        rsa_sk.phi_q[0] = sk->phi_q[0];

        //br_i31_init_key( sk, &rsa_sk, tmp, fwlen);

        br_i31_update_key( &rsa_sk, tmp, fwlen);
        /*
         * Decode q.
         */

        mq = tmp;

        /*
         * Decode p.
         */
        
        t1 = mq + fwlen;
        
        /*
         * Compute the modulus (product of the two factors), to compare
         * it with the source value. We use br_i31_mulacc(), since it's
         * already used later on.
         */
        
        t2 = mq + 2 * fwlen;
        br_i31_zero(t2, mq[0]);
        br_i31_decode(t2, rsa_sk.n, (rsa_sk.n_bitlen + 7) >> 3);
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
        br_i31_decode(n, rsa_sk.n, (rsa_sk.n_bitlen + 7) >> 3);
        uint32_t *c = t3;
        uint32_t *c_prime = mq + 6 * fwlen;
        uint32_t * r_to_e = mq; 
        
        br_i31_zero(c, n[0]);
        br_i31_decode_reduce(c, x, xlen, n);
        
        br_i31_zero(r_to_e, n[0]);
        memcpy(r_to_e + 1, r1 + 1,  ((*r1 + 7) >> 3));
        r_to_e[0] = n[0];

        r &= br_i31_modpow_opt(r_to_e, rsa_sk.e, rsa_sk.elen, n,  br_i31_ninv31(n[1]), mq + 8 * fwlen, TLEN - 8 * fwlen);

        br_i31_zero(c_prime, n[0]);
        c[0] = c_prime[0];
        br_i31_mulacc(c_prime, c, r_to_e);
        
        mq = tmp + 4 * fwlen;
        mp = tmp + 5 * fwlen;


        br_i31_decode(mq,  rsa_sk.q,  rsa_sk.qlen);
        br_i31_decode(mp,  rsa_sk.p,  rsa_sk.plen);
    
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

        
        unsigned char* dq = (unsigned char *) (tmp + 6 *fwlen); 
        size_t dqlen = blind_exponent( dq, rsa_sk.dq, rsa_sk.dqlen, rsa_sk.phi_q, tmp + 7 * fwlen);


        uint32_t * s2_prime = tmp + 2 * fwlen;
       

        br_i31_zero(s2_prime, mq[0]);
        br_i31_reduce(s2_prime, s2, rsa_sk.r2);
        

        /*
         * Compute s2 = x^dq mod q.
         */
        q0i = br_i31_ninv31(mq[1]);


        r &= br_i31_modpow_opt_rand( s2, dq, dqlen, mq, q0i,
                tmp + 7 * fwlen, TLEN - 7 * fwlen);
        
         /*
         * Compute s2' = x^dq mod r2.
         */

        uint32_t r20i = br_i31_ninv31(rsa_sk.r2[1]);

        r &= br_i31_modpow_opt_rand( s2_prime, dq, dqlen, rsa_sk.r2, r20i,
                tmp + 7 * fwlen, TLEN - 7 * fwlen);

       
        /*
         * Compute s1 = x^dp mod p.
         */
        
        unsigned char* dp = (unsigned char *) (tmp + 6 *fwlen); 
        size_t dplen = blind_exponent(dp, rsa_sk.dp, rsa_sk.dplen, rsa_sk.phi_p, tmp + 7 * fwlen);

        uint32_t * s1_prime = tmp + 3 * fwlen;
       

        br_i31_zero(s1_prime, mp[0]);
        br_i31_reduce(s1_prime, s1, rsa_sk.r1);
     
        
        p0i = br_i31_ninv31(mp[1]);
        
       
        r &= br_i31_modpow_opt_rand( s1, dp, dplen, mp, p0i,
                tmp + 7 * fwlen, TLEN - 7 * fwlen);
        
         /*
         * Compute s1' = x^dp mod r1.
         */

        uint32_t r10i = br_i31_ninv31(rsa_sk.r1[1]);

        r &= br_i31_modpow_opt_rand( s1_prime, dp, dplen, rsa_sk.r1, r10i,
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
        t2 = tmp + 8 * fwlen;
        br_i31_reduce(t2, s2, mp); 
        br_i31_add(s1, mp, br_i31_sub(s1, t2, 1));
        br_i31_to_monty(s1, mp);
      
        br_i31_decode_reduce(t1, rsa_sk.iq, rsa_sk.iqlen, mp);
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
        

        uint32_t * s_r2 = mq;
        uint32_t * s_r1 = mp;

        br_i31_reduce(s_r2, t3, rsa_sk.r2);
        br_i31_reduce(s_r1, t3, rsa_sk.r1);

        br_i31_sub(s_r2, s2_prime, 1);
        br_i31_sub(s_r1, s1_prime, 1);

        if(!br_i31_iszero(s_r2)  || !br_i31_iszero(s_r1)){
                r = 0;
        }
       
        t1 = tmp + 4 * fwlen;
        br_i31_decode(n, rsa_sk.n, (rsa_sk.n_bitlen + 7) >> 3);
        br_i31_zero(t1, n[0]);
        br_i31_reduce(t1, t3, n); 
        

        

        t2 = tmp + 6 * fwlen;
        br_i31_zero(t2, n[0]);
        memcpy(t2 + 1, r1 + 1, (*r1 + 7) >> 3);
        t2[0] = n[0];
        t1[0] = n[0];
        
        r &= br_i31_moddiv(t1, t2, n, br_i31_ninv31(n[1]), tmp + 8 * fwlen);
        
        /*
         * Encode the result. Since we already checked the value of xlen,
         * we can just use it right away.
         */
        

        br_i31_encode(x, xlen, t1);


        /*
         * The only error conditions remaining at that point are invalid
         * values for p and q (even integers).
         */
        return p0i & q0i & r;
}
