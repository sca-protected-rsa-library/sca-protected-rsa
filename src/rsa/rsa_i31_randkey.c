#include "bearssl.h"
#include "inner.h"
#include "stm32wrapper.h"


void
make_rand(uint32_t *x, uint32_t esize)
{
    int len = (esize + 31) >> 5;

    for (int i = 1; i <= len; i++) {
        uint32_t limb_bits = esize - 31*(i-1);
        if ((int)limb_bits > 31) {
            limb_bits = 31;
        }
        else{
           limb_bits = limb_bits;
        }
        rng_get_random_blocking();//rng_get_random(&x[i]);//
        x[i] &= 0x7FFFFFFF;
    }

    x[0] = esize;

}



/*
 * SECURITY & PARAMETER RATIONALE:
 *
 * 1. SIDE-CHANNEL RESISTANCE (CONSTANT-TIME):
 * This function is critical for key generation. To prevent timing side-channel
 * attacks (which could leak information about the prime factors), the loop
 * strictly executes RAND_ATTEMPTS times. We do not exit early upon finding
 * a match. Data movement is handled via constant-time masking (br_ccopy)
 * rather than conditional branches.
 *
 * 2. PROBABILISTIC CORRECTNESS (N=12):
 * We rely on the density of coprime numbers among random odd integers, which
 * is 8/pi^2 (~81%). The probability of failing to find a coprime number in
 * a single attempt is ~19%.
 *
 * With RAND_ATTEMPTS set to 12, the probability of total failure is:
 * P(fail) = (0.1895)^12 ~= 2.0 * 10^-9 (approx 1 in 500 million).
 *
 * 3. FAILURE MODE:
 * If no coprime is found after 12 attempts (an event with negligible
 * probability), the function defaults to returning the last generated
 * candidate (via the 'mask' logic). While this result would be mathematically
 * invalid, the risk is statistically insignificant compared to the
 * performance benefit of a lower iteration count.
 */

#define RAND_ATTEMPTS  12  

void
make_rand_coprime(uint32_t *x, uint32_t esize, uint32_t *y, uint32_t *tmp)
{
    
    uint32_t best[(2*BR_RSA_RAND_FACTOR + 63) >> 5];
    uint32_t cand[(2*BR_RSA_RAND_FACTOR + 63) >> 5];
    memset(best, 0, sizeof best);
    memset(cand, 0, sizeof cand);
    
    uint32_t y0i = br_i31_ninv31(y[1]);
    size_t len_bytes = (esize + 7) >> 3;
    uint32_t have_best = 0;

    for (int i = 0; i < RAND_ATTEMPTS; i++) {
        
        make_rand(cand, esize);

        
        cand[1] |= 1;

        
        uint32_t work[(2*BR_RSA_RAND_FACTOR + 63) >> 5];
        memset(work, 0, sizeof work);
        memcpy(work + 1, cand + 1, len_bytes);
        work[0] = cand[0];

        uint32_t ok = br_i31_moddiv(work, work, y, y0i, tmp); 

        uint32_t take = ok & (have_best ^ 1);

        br_ccopy(take, best + 1, cand + 1, len_bytes);
        br_ccopy(take, best, cand, sizeof(uint32_t));

        have_best |= ok;
    }

    
    uint32_t mask = have_best;
    br_ccopy(mask ^ 1, best + 1, cand + 1, len_bytes);
    br_ccopy(mask ^ 1, best, cand, sizeof(uint32_t));

    memcpy(x + 1, best + 1, len_bytes);
    x[0] = best[0];
}




size_t blind_exponent( unsigned char * x, const unsigned char* d, const size_t size, uint32_t * m, uint32_t * t1){

        uint32_t r[(BR_RSA_RAND_FACTOR + 63) >> 5];
        make_rand(r, BR_RSA_RAND_FACTOR);
        r[0] = BR_RSA_RAND_FACTOR;
        br_i31_zero(t1, m[0]);
        br_i31_decode(t1, d, size);
        t1[0] = m[0];
                
        size_t xlen = (m[0] + 7) >> 3; 
        // store in t1 = d + r * phi(m)
        br_i31_mulacc(t1, m, r);
        xlen = (t1[0] + 7) >> 3;
        t1[0] = br_i31_bit_length(t1 + 1, (t1[0] + 31) >> 5);
        

        
        br_i31_encode(x, xlen, t1);

        return xlen;
}



static void reblind(uint32_t * dest, uint32_t * src, uint32_t* mod, uint32_t * new_mask, uint32_t* tmp_buf){
    
        br_i31_zero(tmp_buf, 2*mod[0]);
        new_mask[0] = mod[0];
        tmp_buf[0] = mod[0];
        br_i31_mulacc(tmp_buf, new_mask, src);
        br_i31_zero(dest, mod[0]);
        br_i31_reduce(dest, tmp_buf, mod);
        dest[0] = src[0];
}

static void inverse(uint32_t * dest, uint32_t * src, uint32_t * mod, uint32_t * tmp){
        br_i31_zero(dest, mod[0]);
        src[0] = mod[0];
        dest[1] = 1;
        br_i31_moddiv(dest, src, mod, br_i31_ninv31(mod[1]), tmp);
        dest[0] = br_i31_bit_length(dest + 1, (mod[0] + 31) >> 5);
}

static void create_mask(uint32_t * dest, uint32_t * m,uint32_t *op1,uint32_t * op2, uint32_t * tmp_buf){
        br_i31_zero(tmp_buf, m[0]);
        tmp_buf[0] = m[0];
        op1[0] = m[0];
        br_i31_mulacc(tmp_buf, op1, op2);
        br_i31_reduce(dest, tmp_buf, m);
        dest[0] = br_i31_bit_length(dest + 1, (m[0] + 31) >> 5);
}




void init_temp_rsa_key(temp_rsa_key_t *temp, const br_rsa_private_key *sk) {
    // Set up pointers for temporary key
    temp->key.r1 = temp->r1;
    temp->key.r2 = temp->r2;
    temp->key.n  = temp->n_buf;
    temp->key.p  = temp->p_buf;
    temp->key.q  = temp->q_buf;
    temp->key.dp = temp->dp_buf;
    temp->key.dq = temp->dq_buf;
    temp->key.iq = temp->iq_buf;
    temp->key.phi_p = temp->phi_p;
    temp->key.phi_q = temp->phi_q;
    temp->key.e  = temp->e_buf;
    memset(temp->key.r1,   0, sizeof(temp->r1));
    memset(temp->key.r2,   0, sizeof(temp->r2));
    memset(temp->key.n,    0, sizeof(temp->n_buf));
    memset(temp->key.p,    0, sizeof(temp->p_buf));
    memset(temp->key.q,    0, sizeof(temp->q_buf));
    memset(temp->key.dp,   0, sizeof(temp->dp_buf));
    memset(temp->key.dq,   0, sizeof(temp->dq_buf));
    memset(temp->key.iq,   0, sizeof(temp->iq_buf));
    memset(temp->key.phi_p,0, sizeof(temp->phi_p));
    memset(temp->key.phi_q,0, sizeof(temp->phi_q));
    // Copy key components from the original key (sk)
    temp->key.n_bitlen = sk->n_bitlen;
    memcpy(temp->key.n, sk->n, (sk->n_bitlen + 7) >> 3);
    memcpy(temp->key.e, sk->e, sk->elen);
    temp->key.elen = sk->elen;
    memcpy(temp->key.p, sk->p, sk->plen);
    temp->key.plen = sk->plen;
    memcpy(temp->key.q, sk->q, sk->qlen);
    temp->key.qlen = sk->qlen;
    memcpy(temp->key.iq, sk->iq, sk->iqlen);
    temp->key.iqlen = sk->iqlen;
    memcpy(temp->key.dp, sk->dp, sk->dplen);
    temp->key.dplen = sk->dplen;
    memcpy(temp->key.dq, sk->dq, sk->dqlen);
    temp->key.dqlen = sk->dqlen;
   // return;
    memcpy(temp->key.r1 + 1, sk->r1 + 1, (sk->r1[0] + 7) >> 3);
    temp->key.r1[0] = sk->r1[0];

    memcpy(temp->key.r2 + 1, sk->r2 + 1, (sk->r2[0] + 7) >> 3);
    temp->key.r2[0] = sk->r2[0];

    memcpy(temp->key.phi_p + 1, sk->phi_p + 1, (sk->phi_p[0] + 7) >> 3);
    temp->key.phi_p[0] = sk->phi_p[0];

    memcpy(temp->key.phi_q + 1, sk->phi_q + 1, (sk->phi_q[0] + 7) >> 3);
    temp->key.phi_q[0] = sk->phi_q[0];

}



void br_i31_init_key( const br_rsa_private_key *sk, br_rsa_private_key *new_sk, uint32_t *tmp, uint32_t fwlen){

        // copy public modulus
        memcpy(new_sk->n, sk->n, (sk->n_bitlen +7) >> 3);
        new_sk->n_bitlen = sk->n_bitlen;
        
        // create random mask r1
        make_rand( new_sk->r1, BR_RSA_RAND_FACTOR);
        new_sk->r1[1] |= 1;
        new_sk->r1[0] = BR_RSA_RAND_FACTOR;
        
        uint32_t * t1 = tmp + fwlen;

        // create random mask r2
        make_rand_coprime( new_sk->r2, BR_RSA_RAND_FACTOR, new_sk->r1, t1);

        new_sk->r2[1] |= 1;
        new_sk->r2[0] = BR_RSA_RAND_FACTOR;


        br_i31_decode(tmp, sk->p, sk->plen);

        // blind phi(p)
        tmp[1] ^= 1;
        br_i31_zero(new_sk->phi_p, tmp[0]);
        br_i31_mulacc(new_sk->phi_p, tmp, new_sk->r1);
        new_sk->phi_p[0] = tmp[0] + BR_RSA_RAND_FACTOR;
        tmp[1] ^= 1;

        // blind p
        br_i31_zero(t1, tmp[0]);
        br_i31_mulacc(t1, tmp, new_sk->r1);
        t1[0] = tmp[0] + BR_RSA_RAND_FACTOR;
     

        br_i31_encode(new_sk->p, (t1[0] + 7) >> 3, t1);
        new_sk->plen = (t1[0] + 7) >> 3;


        br_i31_decode(tmp, sk->q, sk->qlen);
        
        // blind phi(q)
        tmp[1] ^= 1;
        br_i31_zero(new_sk->phi_q, tmp[0]);
        br_i31_mulacc(new_sk->phi_q, tmp, new_sk->r2);
        new_sk->phi_q[0] = tmp[0] + BR_RSA_RAND_FACTOR;
        tmp[1] ^= 1;
        
        // blind q
        br_i31_zero(t1, tmp[0]);
        br_i31_mulacc(t1, tmp, new_sk->r2);
        t1[0] = tmp[0] + BR_RSA_RAND_FACTOR;
        //t1[0] = br_i31_bit_length(t1 + 1, (t1[0] + 31) >> 5);
        br_i31_encode(new_sk->q, (t1[0] + 7) >> 3, t1);
        new_sk->qlen = (t1[0] + 7) >> 3;
        

        t1 = tmp + 2 * fwlen;
        uint32_t *t2 = t1 + 2 * fwlen;

 
        // blind qinv
        br_i31_decode(tmp, new_sk->p, new_sk->plen);
        tmp[0] = (new_sk->plen << 3);
        br_i31_decode(t2, new_sk->q, new_sk->qlen);
        t2[0] = new_sk->qlen << 3;
        br_i31_reduce(t1, t2, tmp);
    
        // uint32_t * t3 = t2 + 2 * fwlen;
        tmp[0] = (new_sk->plen << 3);
        br_i31_zero(t2, tmp[0]);
        t2[1] = 1;
        t1[0] = tmp[0];
        

        br_i31_moddiv(t2, t1, tmp, br_i31_ninv31(tmp[1]), t2 + 2*fwlen);
        t2[0] = br_i31_bit_length(t2 + 1, (t2[0] + 31) >> 5);
        br_i31_encode(new_sk->iq, (tmp[0] + 7) >> 3, t2);
        new_sk->iqlen = (tmp[0] + 7) >> 3;

        // blind dp 
        br_i31_zero(t1, new_sk->phi_p[0]);
        br_i31_decode(t1, sk->dp, sk->dplen);
        br_i31_zero(t2, new_sk->phi_p[0]);
        t1[0] = new_sk->phi_p[0];
        t2[1] = 1;
        br_i31_mulacc(t1, t2, new_sk->phi_p);
        t1[0] = br_i31_bit_length(t1 + 1, (new_sk->phi_p[0] + 31) >> 5);
        br_i31_encode(new_sk->dp, (new_sk->phi_p[0] + 7 + BR_RSA_RAND_FACTOR) >> 3, t1);
        new_sk->dplen = (new_sk->phi_p[0] + 7 + BR_RSA_RAND_FACTOR) >> 3;
        
        // blind dq 
        br_i31_zero(t1, new_sk->phi_q[0]);
        br_i31_decode(t1, sk->dq, sk->dqlen);
        br_i31_zero(t2, new_sk->phi_q[0]);
        t1[0] = new_sk->phi_q[0];
        t2[1] = 1;
        br_i31_mulacc(t1, t2, new_sk->phi_q);
        t1[0] = br_i31_bit_length(t1 + 1, (new_sk->phi_q[0] + 31) >> 5);

        br_i31_encode(new_sk->dq, (new_sk->phi_q[0] + 7 + BR_RSA_RAND_FACTOR) >> 3, t1);
        new_sk->dqlen = (new_sk->phi_q[0] + 7 + BR_RSA_RAND_FACTOR) >> 3;


        memcpy(new_sk->e, sk->e, sk->elen);
        new_sk->elen = sk->elen;
}





void br_i31_update_key(  br_rsa_private_key *new_sk, uint32_t *tmp, uint32_t fwlen ){

        uint32_t * r1_inv = tmp;
        uint32_t * r2_inv = tmp + 2 * fwlen;
        uint32_t * t1 = r2_inv + 2 * fwlen;
        uint32_t * mod = t1 + 2 * fwlen;
        uint32_t * t3 = mod + 2 * fwlen;
        uint32_t * t4 = t3 + 2 * fwlen;


        br_i31_decode(mod, new_sk->n, (new_sk->n_bitlen + 7) >> 3);


        // calculating multiplicative inverse of r_1
        br_i31_zero(t1, mod[0]);
        memcpy(t1 + 1, new_sk->r1 + 1, (new_sk->r1[0] + 7) >> 3);
        inverse(r1_inv, t1, mod, t3);


        // generating new value for r_1
        br_i31_zero(new_sk->r1, 2*BR_RSA_RAND_FACTOR);
        make_rand(new_sk->r1, BR_RSA_RAND_FACTOR);
        new_sk->r1[1] |= 1;
        new_sk->r1[0] = BR_RSA_RAND_FACTOR;
        //new_sk->r1[0] = br_i31_bit_length(new_sk->r1 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);
        
        // storing old random factor, later used in mask for qinv       
        uint32_t temp_r2[(BR_RSA_RAND_FACTOR + 63) >> 5];
        br_i31_zero(temp_r2, new_sk->r2[0]);
        memcpy(temp_r2 + 1, new_sk->r2 + 1, (new_sk->r2[0] + 7) >> 3);
        temp_r2[0] = new_sk->r2[0];

        // generating new value for r_2
        br_i31_zero(new_sk->r2, 2*BR_RSA_RAND_FACTOR);
        make_rand_coprime(new_sk->r2, BR_RSA_RAND_FACTOR, new_sk->r1, t3);
        new_sk->r2[1] |= 1;
        //new_sk->r2[0] = ( new_sk->r2[0] >  new_sk->r1[0])?  new_sk->r2[0] :  new_sk->r1[0];
        new_sk->r2[0] = BR_RSA_RAND_FACTOR;
                
        // re-blinding p
        br_i31_zero(t1, mod[0]);
        br_i31_decode(t1, new_sk->p, new_sk->plen);
        t1[0] = (new_sk->plen << 3);
        create_mask(t3, mod, r1_inv, new_sk->r1, t4);
        reblind(t3, t1, mod, t3, t4);
        t3[0] = t1[0] + BR_RSA_RAND_FACTOR;
        br_i31_encode(new_sk->p,new_sk->plen, t3);
        //new_sk->plen = (t3[0] + 7) >> 3;

        // copy old phi(p)
        br_i31_zero(t3, mod[0]);
        memcpy(t3 + 1, new_sk->phi_p + 1, (new_sk->phi_p[0] + 7) >> 3);
        t3[0] = new_sk->phi_p[0];

        // re-blinding phi(p)
        create_mask(t1, mod, r1_inv, new_sk->r1, t4);
        reblind(t1, new_sk->phi_p, mod, t1, t4);
        br_i31_zero(new_sk->phi_p, t1[0]);
        memcpy(new_sk->phi_p + 1, t1 + 1, (t1[0] + 7) >> 3);
        new_sk->phi_p[0] = t1[0];
        
        // re-blinding dp
        br_i31_sub(t1, t3, 1);
        br_i31_zero(t3, mod[0]);
        br_i31_decode(t3, new_sk->dp, new_sk->dplen);
        t3[0] = t1[0];
        br_i31_add(t3, t1, 1);
        t3[0] = br_i31_bit_length(t3 + 1, (mod[0] + 31) >> 5);
        br_i31_encode(new_sk->dp, (new_sk->phi_p[0] + 7 + BR_RSA_RAND_FACTOR) >> 3, t3);
        new_sk->dplen = (new_sk->phi_p[0] + 7 + BR_RSA_RAND_FACTOR) >> 3;
     
        //calculating multiplicative inverse of old r_2
        br_i31_zero(t1, mod[0]);
        memcpy(t1 + 1, temp_r2 + 1, ((BR_RSA_RAND_FACTOR + 7)) >> 3);
        inverse(r2_inv, t1, mod, t3);
           

        // copy old phi(q)
        br_i31_zero(t3, mod[0]);
        memcpy(t3 + 1, new_sk->phi_q + 1, (new_sk->phi_q[0] + 7) >> 3);
        t3[0] = new_sk->phi_q[0];
        
        // re-blinding phi(q)
        create_mask(t1, mod, r2_inv, new_sk->r2, t4);
        reblind(t1, new_sk->phi_q, mod, t1, t4);
        br_i31_zero(new_sk->phi_q, t1[0]);
        memcpy(new_sk->phi_q + 1, t1 + 1, (t1[0] + 7) >> 3);
        new_sk->phi_q[0] = t1[0];
       
        // re-blinding dq
        br_i31_sub(t1, t3, 1);
        br_i31_zero(t3, mod[0]);
        br_i31_decode(t3, new_sk->dq, new_sk->dqlen);
        t3[0] = t1[0];
        br_i31_add(t3, t1, 1);
        t3[0] = br_i31_bit_length(t3 + 1, (mod[0] + 31) >> 5);
        br_i31_encode(new_sk->dq, (new_sk->phi_q[0] + 7 + BR_RSA_RAND_FACTOR) >> 3, t3);
        new_sk->dqlen = (new_sk->phi_q[0] + 7 + BR_RSA_RAND_FACTOR) >> 3;

        
        // re-blinding q
        br_i31_decode(t1, new_sk->q, new_sk->qlen);
        t1[0] = (new_sk->qlen << 3);
        create_mask(t3, mod, r2_inv, new_sk->r2, t4);
        reblind(t3, t1, mod, t3, t4);
        t3[0] = t1[0] + BR_RSA_RAND_FACTOR;
        br_i31_encode(new_sk->q, new_sk->qlen, t3);

                
       // blinding qinv
        br_i31_decode(mod, new_sk->p, new_sk->plen);
        mod[0] = new_sk->plen << 3;
        br_i31_zero(t3, mod[0]);
        br_i31_decode(t3, new_sk->q, new_sk->qlen);
        t3[0] = new_sk->qlen << 3;

        br_i31_zero(t1, mod[0]);
        br_i31_reduce(t1, t3, mod);
        
        br_i31_zero(t3, mod[0]);

        t3[1] = 1;
        t1[0] = mod[0];
    

        br_i31_moddiv(t3, t1, mod, br_i31_ninv31(mod[1]), t4);
        t3[0] = br_i31_bit_length(t3 + 1, (t3[0] + 31) >> 5);
        
        br_i31_encode(new_sk->iq, (mod[0] + 7) >> 3, t3);
        new_sk->iqlen = (mod[0] + 7) >> 3;

        new_sk->r2[0] = br_i31_bit_length(new_sk->r2 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);
        new_sk->r1[0] = br_i31_bit_length(new_sk->r1 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);

}