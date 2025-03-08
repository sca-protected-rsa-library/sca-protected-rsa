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

#ifndef BR_BEARSSL_RSA_H__
#define BR_BEARSSL_RSA_H__

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/** \file bearssl_rsa.h
 *
 * # RSA
 *
 * This file documents the RSA implementations provided with BearSSL.
 * Note that the SSL engine accesses these implementations through a
 * configurable API, so it is possible to, for instance, run a SSL
 * server which uses a RSA engine which is not based on this code.
 *
 * ## Key Elements
 *
 * RSA public and private keys consist in lists of big integers. All
 * such integers are represented with big-endian unsigned notation:
 * first byte is the most significant, and the value is positive (so
 * there is no dedicated "sign bit"). Public and private key structures
 * thus contain, for each such integer, a pointer to the first value byte
 * (`unsigned char *`), and a length (`size_t`) which is the number of
 * relevant bytes. As a general rule, minimal-length encoding is not
 * enforced: values may have extra leading bytes of value 0.
 *
 * RSA public keys consist in two integers:
 *
 *   - the modulus (`n`);
 *   - the public exponent (`e`).
 *
 * RSA private keys, as defined in
 * [PKCS#1](https://tools.ietf.org/html/rfc3447), contain eight integers:
 *
 *   - the modulus (`n`);
 *   - the public exponent (`e`);
 *   - the private exponent (`d`);
 *   - the first prime factor (`p`);
 *   - the second prime factor (`q`);
 *   - the first reduced exponent (`dp`, which is `d` modulo `p-1`);
 *   - the second reduced exponent (`dq`, which is `d` modulo `q-1`);
 *   - the CRT coefficient (`iq`, the inverse of `q` modulo `p`).
 *
 * However, the implementations defined in BearSSL use only five of
 * these integers: `p`, `q`, `dp`, `dq` and `iq`.
 * 
 * 
 *
 * ## Security Features and Limitations
 *
 * The implementations contained in BearSSL have the following limitations
 * and features:
 *
 *   - They are constant-time. This means that the execution time and
 *     memory access pattern may depend on the _lengths_ of the private
 *     key components, but not on their value, nor on the value of
 *     the operand. Note that this property is not achieved through
 *     random masking, but "true" constant-time code.
 *
 *   - They support only private keys with two prime factors. RSA private
 *     keys with three or more prime factors are nominally supported, but
 *     rarely used; they may offer faster operations, at the expense of
 *     more code and potentially a reduction in security if there are
 *     "too many" prime factors.
 *
 *   - The public exponent may have arbitrary length. Of course, it is
 *     a good idea to keep public exponents small, so that public key
 *     operations are fast; but, contrary to some widely deployed
 *     implementations, BearSSL has no problem with public exponents
 *     longer than 32 bits.
 *
 *   - The two prime factors of the modulus need not have the same length
 *     (but severely imbalanced factor lengths might reduce security).
 *     Similarly, there is no requirement that the first factor (`p`)
 *     be greater than the second factor (`q`).
 *
 *   - Prime factors and modulus must be smaller than a compile-time limit.
 *     This is made necessary by the use of fixed-size stack buffers, and
 *     the limit has been adjusted to keep stack usage under 2 kB for the
 *     RSA operations. Currently, the maximum modulus size is 4096 bits,
 *     and the maximum prime factor size is 2080 bits.
 *
 *   - The RSA functions themselves do not enforce lower size limits,
 *     except that which is absolutely necessary for the operation to
 *     mathematically make sense (e.g. a PKCS#1 v1.5 signature with
 *     SHA-1 requires a modulus of at least 361 bits). It is up to users
 *     of this code to enforce size limitations when appropriate (e.g.
 *     the X.509 validation engine, by default, rejects RSA keys of
 *     less than 1017 bits).
 *
 *   - Within the size constraints expressed above, arbitrary bit lengths
 *     are supported. There is no requirement that prime factors or
 *     modulus have a size multiple of 8 or 16.
 *
 *   - When verifying PKCS#1 v1.5 signatures, both variants of the hash
 *     function identifying header (with and without the ASN.1 NULL) are
 *     supported. When producing such signatures, the variant with the
 *     ASN.1 NULL is used.
 *
 * ## Implementations
 *
 * Three RSA implementations are included:
 *
 *   - The **i31** implementation uses 32-bit integers, each containing
 *     31 bits worth of integer data. The i31 implementation is somewhat
 *     faster than the i32 implementation (the reduced integer size makes
 *     carry propagation easier) for a similar code footprint, but uses
 *     very slightly larger stack buffers (about 4% bigger).
 *  
 */

/**
 * \brief RSA public key.
 *
 * The structure references the modulus and the public exponent. Both
 * integers use unsigned big-endian representation; extra leading bytes
 * of value 0 are allowed.
 */
typedef struct {
	/** \brief Modulus. */
	unsigned char *n;
	/** \brief Modulus length (in bytes). */
	size_t nlen;
	/** \brief Public exponent. */
	unsigned char *e;
	/** \brief Public exponent length (in bytes). */
	size_t elen;
} br_rsa_public_key;

/**
 * \brief RSA private key.
 *
 * The structure references the private factors, reduced private
 * exponents, and CRT coefficient. It also contains the bit length of
 * the modulus. The big integers use unsigned big-endian representation;
 * extra leading bytes of value 0 are allowed. However, the modulus bit
 * length (`n_bitlen`) MUST be exact.
 */
typedef struct {
	/** \brief Modulus. */
	unsigned char *n;
	/** \brief Modulus bit length (in bits, exact value). */
	uint32_t n_bitlen;
	/** \brief First prime factor. */
	unsigned char *p;
	/** \brief First prime factor length (in bytes). */
	size_t plen;
	/** \brief Second prime factor. */
	unsigned char *q;
	/** \brief Second prime factor length (in bytes). */
	size_t qlen;
	/** \brief First reduced private exponent. */
	unsigned char *dp;
	/** \brief First reduced private exponent length (in bytes). */
	size_t dplen;
	/** \brief Second reduced private exponent. */
	unsigned char *dq;
	/** \brief Second reduced private exponent length (in bytes). */
	size_t dqlen;
	/** \brief CRT coefficient. */
	unsigned char *iq;
	/** \brief CRT coefficient length (in bytes). */
	size_t iqlen;
	/** \brief Public exponent. */
	unsigned char *e;
	/** \brief Public exponent length (in bytes). */
	size_t elen;
	/** \brief random factor of p. */
	uint32_t *r1;
	/** \brief random factor of q. */
	uint32_t *r2;
	/** \brief randomized phi(p). */
	uint32_t *phi_p;
	/** \brief randomized phi(q). */
	uint32_t *phi_q;
} br_rsa_private_key;


/*
 * RSA "i31" engine. Similar to i32, but only 31 bits are used per 32-bit
 * word. This uses slightly more stack space (about 4% more) and code
 * space, but it quite faster.
 */

/**
 * \brief RSA public key engine "i31".
 *
 * \see br_rsa_public
 *
 * \param x      operand to exponentiate.
 * \param xlen   length of the operand (in bytes).
 * \param pk     RSA public key.
 * \return  1 on success, 0 on error.
 */
uint32_t br_rsa_i31_public(unsigned char *x, size_t xlen,
	const br_rsa_public_key *pk);

/**
 * \brief RSA private key engine "i31".
 *
 * \see br_rsa_private
 *
 * \param x    operand to exponentiate.
 * \param sk   RSA private key.
 * \return  1 on success, 0 on error.
 */
uint32_t br_rsa_i31_private(unsigned char *x,
	const br_rsa_private_key *sk);
/**
 * \brief RSA private key engine "i31" with Message and Exponent Blinding.
 *
 * This function implements the RSA private key operation with the message and exponent blinding countermeasure.
 * The blinding randomizes the message and exponent values during RSA operations to mitigate first-order side-channel attacks.
 *
 * \see br_rsa_private
 *
 * \param x    Operand to exponentiate.
 * \param sk   RSA private key.
 * \return  1 on success, 0 on error.
 */
uint32_t br_rsa_i31_private_msg_blind(unsigned char *x,
	const br_rsa_private_key *sk);

/**
 * \brief RSA private key engine "i31" with Modulus Randomization.
 *
 * This function implements the RSA private key operation using modulus randomization.
 * The algorithm randomizes the modulus during each iteration of exponentiation, adding an extra layer of protection against side-channel leakage.
 *
 * \see br_rsa_private
 *
 * \param x    Operand to exponentiate.
 * \param sk   RSA private key.
 * \return  1 on success, 0 on error.
 */
uint32_t br_rsa_i31_private_mod_rand(unsigned char *x,
	const br_rsa_private_key *sk);

/**
 * \brief RSA private key engine "i31" with Modulus Randomization and Key Pre-Randomization.
 *
 * This function extends the modulus randomization countermeasure by incorporating key pre-randomization.
 * In addition to message/exponent blinding and modulus re-randomization, it randomizes key components (e.g., pre-masking the key)
 * to further enhance protection against both side-channel and fault injection attacks.
 *
 * \see br_rsa_private
 *
 * \param x    Operand to exponentiate.
 * \param sk   RSA private key.
 * \return  1 on success, 0 on error.
 */
uint32_t br_rsa_i31_private_mod_prerand(unsigned char *x,
	const br_rsa_private_key *sk);

/**
 * \brief RSA private key engine "i31" with Fault Injection Countermeasures.
 *
 * This function implements additional fault injection (FI) countermeasures into the RSA private key operation.
 * It integrates protections designed to detect and mitigate hardware fault attacks alongside the existing side-channel countermeasures.
 *
 * \see br_rsa_private
 *
 * \param x    Operand to exponentiate.
 * \param sk   RSA private key.
 * \return  1 on success, 0 on error.
 */
uint32_t br_rsa_i31_private_FI(unsigned char *x,
		const br_rsa_private_key *sk);


#ifdef __cplusplus
}
#endif

#endif
