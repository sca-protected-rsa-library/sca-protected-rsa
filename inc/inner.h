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

#ifndef INNER_H__
#define INNER_H__

#include <string.h>
#include <limits.h>

#include "config.h"
#include "bearssl.h"

/*
 * On MSVC, disable the warning about applying unary minus on an
 * unsigned type: it is standard, we do it all the time, and for
 * good reasons.
 */
#if _MSC_VER
#pragma warning( disable : 4146 )
#endif

/*
 * Maximum size for a RSA modulus (in bits). Allocated stack buffers
 * depend on that size, so this value should be kept small. Currently,
 * 2048-bit RSA keys offer adequate security, and should still do so for
 * the next few decades; however, a number of widespread PKI have
 * already set their root keys to RSA-4096, so we should be able to
 * process such keys.
 *
 * This value MUST be a multiple of 64. This value MUST NOT exceed 47666
 * (some computations in RSA key generation rely on the factor size being
 * no more than 23833 bits). RSA key sizes beyond 3072 bits don't make a
 * lot of sense anyway.
 */
#define BR_MAX_RSA_SIZE   4096

/*
 * Minimum size for a RSA modulus (in bits); this value is used only to
 * filter out invalid parameters for key pair generation. Normally,
 * applications should not use RSA keys smaller than 2048 bits; but some
 * specific cases might need shorter keys, for legacy or research
 * purposes.
 */
#define BR_MIN_RSA_SIZE   512

/*
 * Maximum size for a RSA factor (in bits). This is for RSA private-key
 * operations. Default is to support factors up to a bit more than half
 * the maximum modulus size.
 *
 * This value MUST be a multiple of 32.
 */
#define BR_MAX_RSA_FACTOR   ((BR_MAX_RSA_SIZE + 64) >> 1)

/*
 * Bit len of random number used as mask
 */
#define BR_RSA_RAND_FACTOR 62



/* ==================================================================== */
/*
 * Encoding/decoding functions.
 *
 * 32-bit and 64-bit decoding, both little-endian and big-endian, is
 * implemented with the inline functions below.
 *
 * When allowed by some compile-time options (autodetected or provided),
 * optimised code is used, to perform direct memory access when the
 * underlying architecture supports it, both for endianness and
 * alignment. This, however, may trigger strict aliasing issues; the
 * code below uses unions to perform (supposedly) safe type punning.
 * Since the C aliasing rules are relatively complex and were amended,
 * or at least re-explained with different phrasing, in all successive
 * versions of the C standard, it is always a bit risky to bet that any
 * specific version of a C compiler got it right, for some notion of
 * "right".
 */

typedef union {
	uint16_t u;
	unsigned char b[sizeof(uint16_t)];
} br_union_u16;

typedef union {
	uint32_t u;
	unsigned char b[sizeof(uint32_t)];
} br_union_u32;

typedef union {
	uint64_t u;
	unsigned char b[sizeof(uint64_t)];
} br_union_u64;

static inline void
br_enc16le(void *dst, unsigned x)
{
#if BR_LE_UNALIGNED
	((br_union_u16 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)x;
	buf[1] = (unsigned char)(x >> 8);
#endif
}

static inline void
br_enc16be(void *dst, unsigned x)
{
#if BR_BE_UNALIGNED
	((br_union_u16 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)(x >> 8);
	buf[1] = (unsigned char)x;
#endif
}

static inline unsigned
br_dec16le(const void *src)
{
#if BR_LE_UNALIGNED
	return ((const br_union_u16 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return (unsigned)buf[0] | ((unsigned)buf[1] << 8);
#endif
}

static inline unsigned
br_dec16be(const void *src)
{
#if BR_BE_UNALIGNED
	return ((const br_union_u16 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return ((unsigned)buf[0] << 8) | (unsigned)buf[1];
#endif
}

static inline void
br_enc32le(void *dst, uint32_t x)
{
#if BR_LE_UNALIGNED
	((br_union_u32 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)x;
	buf[1] = (unsigned char)(x >> 8);
	buf[2] = (unsigned char)(x >> 16);
	buf[3] = (unsigned char)(x >> 24);
#endif
}

static inline void
br_enc32be(void *dst, uint32_t x)
{
#if BR_BE_UNALIGNED
	((br_union_u32 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	buf[0] = (unsigned char)(x >> 24);
	buf[1] = (unsigned char)(x >> 16);
	buf[2] = (unsigned char)(x >> 8);
	buf[3] = (unsigned char)x;
#endif
}

static inline uint32_t
br_dec32le(const void *src)
{
#if BR_LE_UNALIGNED
	return ((const br_union_u32 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return (uint32_t)buf[0]
		| ((uint32_t)buf[1] << 8)
		| ((uint32_t)buf[2] << 16)
		| ((uint32_t)buf[3] << 24);
#endif
}

static inline uint32_t
br_dec32be(const void *src)
{
#if BR_BE_UNALIGNED
	return ((const br_union_u32 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return ((uint32_t)buf[0] << 24)
		| ((uint32_t)buf[1] << 16)
		| ((uint32_t)buf[2] << 8)
		| (uint32_t)buf[3];
#endif
}

static inline void
br_enc64le(void *dst, uint64_t x)
{
#if BR_LE_UNALIGNED
	((br_union_u64 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	br_enc32le(buf, (uint32_t)x);
	br_enc32le(buf + 4, (uint32_t)(x >> 32));
#endif
}

static inline void
br_enc64be(void *dst, uint64_t x)
{
#if BR_BE_UNALIGNED
	((br_union_u64 *)dst)->u = x;
#else
	unsigned char *buf;

	buf = dst;
	br_enc32be(buf, (uint32_t)(x >> 32));
	br_enc32be(buf + 4, (uint32_t)x);
#endif
}

static inline uint64_t
br_dec64le(const void *src)
{
#if BR_LE_UNALIGNED
	return ((const br_union_u64 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return (uint64_t)br_dec32le(buf)
		| ((uint64_t)br_dec32le(buf + 4) << 32);
#endif
}

static inline uint64_t
br_dec64be(const void *src)
{
#if BR_BE_UNALIGNED
	return ((const br_union_u64 *)src)->u;
#else
	const unsigned char *buf;

	buf = src;
	return ((uint64_t)br_dec32be(buf) << 32)
		| (uint64_t)br_dec32be(buf + 4);
#endif
}

/*
 * Range decoding and encoding (for several successive values).
 */
void br_range_dec16le(uint16_t *v, size_t num, const void *src);
void br_range_dec16be(uint16_t *v, size_t num, const void *src);
void br_range_enc16le(void *dst, const uint16_t *v, size_t num);
void br_range_enc16be(void *dst, const uint16_t *v, size_t num);

void br_range_dec32le(uint32_t *v, size_t num, const void *src);
void br_range_dec32be(uint32_t *v, size_t num, const void *src);
void br_range_enc32le(void *dst, const uint32_t *v, size_t num);
void br_range_enc32be(void *dst, const uint32_t *v, size_t num);

void br_range_dec64le(uint64_t *v, size_t num, const void *src);
void br_range_dec64be(uint64_t *v, size_t num, const void *src);
void br_range_enc64le(void *dst, const uint64_t *v, size_t num);
void br_range_enc64be(void *dst, const uint64_t *v, size_t num);

/*
 * Byte-swap a 32-bit integer.
 */
static inline uint32_t
br_swap32(uint32_t x)
{
	x = ((x & (uint32_t)0x00FF00FF) << 8)
		| ((x >> 8) & (uint32_t)0x00FF00FF);
	return (x << 16) | (x >> 16);
}


/* ==================================================================== */
/*
 * Constant-time primitives. These functions manipulate 32-bit values in
 * order to provide constant-time comparisons and multiplexers.
 *
 * Boolean values (the "ctl" bits) MUST have value 0 or 1.
 *
 * Implementation notes:
 * =====================
 *
 * The uintN_t types are unsigned and with width exactly N bits; the C
 * standard guarantees that computations are performed modulo 2^N, and
 * there can be no overflow. Negation (unary '-') works on unsigned types
 * as well.
 *
 * The intN_t types are guaranteed to have width exactly N bits, with no
 * padding bit, and using two's complement representation. Casting
 * intN_t to uintN_t really is conversion modulo 2^N. Beware that intN_t
 * types, being signed, trigger implementation-defined behaviour on
 * overflow (including raising some signal): with GCC, while modular
 * arithmetics are usually applied, the optimizer may assume that
 * overflows don't occur (unless the -fwrapv command-line option is
 * added); Clang has the additional -ftrapv option to explicitly trap on
 * integer overflow or underflow.
 */

/*
 * Negate a boolean.
 */
static inline uint32_t
NOT(uint32_t ctl)
{
	return ctl ^ 1;
}

/*
 * Multiplexer: returns x if ctl == 1, y if ctl == 0.
 */
static inline uint32_t
MUX(uint32_t ctl, uint32_t x, uint32_t y)
{
	return y ^ (-ctl & (x ^ y));
}

/*
 * Equality check: returns 1 if x == y, 0 otherwise.
 */
static inline uint32_t
EQ(uint32_t x, uint32_t y)
{
	uint32_t q;

	q = x ^ y;
	return NOT((q | -q) >> 31);
}

/*
 * Inequality check: returns 1 if x != y, 0 otherwise.
 */
static inline uint32_t
NEQ(uint32_t x, uint32_t y)
{
	uint32_t q;

	q = x ^ y;
	return (q | -q) >> 31;
}

/*
 * Comparison: returns 1 if x > y, 0 otherwise.
 */
static inline uint32_t
GT(uint32_t x, uint32_t y)
{
	/*
	 * If both x < 2^31 and x < 2^31, then y-x will have its high
	 * bit set if x > y, cleared otherwise.
	 *
	 * If either x >= 2^31 or y >= 2^31 (but not both), then the
	 * result is the high bit of x.
	 *
	 * If both x >= 2^31 and y >= 2^31, then we can virtually
	 * subtract 2^31 from both, and we are back to the first case.
	 * Since (y-2^31)-(x-2^31) = y-x, the subtraction is already
	 * fine.
	 */
	uint32_t z;

	z = y - x;
	return (z ^ ((x ^ y) & (x ^ z))) >> 31;
}

/*
 * Other comparisons (greater-or-equal, lower-than, lower-or-equal).
 */
#define GE(x, y)   NOT(GT(y, x))
#define LT(x, y)   GT(y, x)
#define LE(x, y)   NOT(GT(x, y))

/*
 * General comparison: returned value is -1, 0 or 1, depending on
 * whether x is lower than, equal to, or greater than y.
 */
static inline int32_t
CMP(uint32_t x, uint32_t y)
{
	return (int32_t)GT(x, y) | -(int32_t)GT(y, x);
}

/*
 * Returns 1 if x == 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
EQ0(int32_t x)
{
	uint32_t q;

	q = (uint32_t)x;
	return ~(q | -q) >> 31;
}

/*
 * Returns 1 if x > 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
GT0(int32_t x)
{
	/*
	 * High bit of -x is 0 if x == 0, but 1 if x > 0.
	 */
	uint32_t q;

	q = (uint32_t)x;
	return (~q & -q) >> 31;
}

/*
 * Returns 1 if x >= 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
GE0(int32_t x)
{
	return ~(uint32_t)x >> 31;
}

/*
 * Returns 1 if x < 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
LT0(int32_t x)
{
	return (uint32_t)x >> 31;
}

/*
 * Returns 1 if x <= 0, 0 otherwise. Take care that the operand is signed.
 */
static inline uint32_t
LE0(int32_t x)
{
	uint32_t q;

	/*
	 * ~-x has its high bit set if and only if -x is nonnegative (as
	 * a signed int), i.e. x is in the -(2^31-1) to 0 range. We must
	 * do an OR with x itself to account for x = -2^31.
	 */
	q = (uint32_t)x;
	return (q | ~-q) >> 31;
}

/*
 * Conditional copy: src[] is copied into dst[] if and only if ctl is 1.
 * dst[] and src[] may overlap completely (but not partially).
 */
void br_ccopy(uint32_t ctl, void *dst, const void *src, size_t len);

#define CCOPY   br_ccopy

/*
 * Compute the bit length of a 32-bit integer. Returned value is between 0
 * and 32 (inclusive).
 */
static inline uint32_t
BIT_LENGTH(uint32_t x)
{
	uint32_t k, c;

	k = NEQ(x, 0);
	c = GT(x, 0xFFFF); x = MUX(c, x >> 16, x); k += c << 4;
	c = GT(x, 0x00FF); x = MUX(c, x >>  8, x); k += c << 3;
	c = GT(x, 0x000F); x = MUX(c, x >>  4, x); k += c << 2;
	c = GT(x, 0x0003); x = MUX(c, x >>  2, x); k += c << 1;
	k += GT(x, 0x0001);
	return k;
}

/*
 * Compute the minimum of x and y.
 */
static inline uint32_t
MIN(uint32_t x, uint32_t y)
{
	return MUX(GT(x, y), y, x);
}

/*
 * Compute the maximum of x and y.
 */
static inline uint32_t
MAX(uint32_t x, uint32_t y)
{
	return MUX(GT(x, y), x, y);
}

/*
 * Multiply two 32-bit integers, with a 64-bit result. This default
 * implementation assumes that the basic multiplication operator
 * yields constant-time code.
 */
#define MUL(x, y)   ((uint64_t)(x) * (uint64_t)(y))

#if BR_CT_MUL31

/*
 * Alternate implementation of MUL31, that will be constant-time on some
 * (old) platforms where the default MUL31 is not. Unfortunately, it is
 * also substantially slower, and yields larger code, on more modern
 * platforms, which is why it is deactivated by default.
 *
 * MUL31_lo() must do some extra work because on some platforms, the
 * _signed_ multiplication may return early if the top bits are 1.
 * Simply truncating (casting) the output of MUL31() would not be
 * sufficient, because the compiler may notice that we keep only the low
 * word, and then replace automatically the unsigned multiplication with
 * a signed multiplication opcode.
 */
#define MUL31(x, y)   ((uint64_t)((x) | (uint32_t)0x80000000) \
                       * (uint64_t)((y) | (uint32_t)0x80000000) \
                       - ((uint64_t)(x) << 31) - ((uint64_t)(y) << 31) \
                       - ((uint64_t)1 << 62))
static inline uint32_t
MUL31_lo(uint32_t x, uint32_t y)
{
	uint32_t xl, xh;
	uint32_t yl, yh;

	xl = (x & 0xFFFF) | (uint32_t)0x80000000;
	xh = (x >> 16) | (uint32_t)0x80000000;
	yl = (y & 0xFFFF) | (uint32_t)0x80000000;
	yh = (y >> 16) | (uint32_t)0x80000000;
	return (xl * yl + ((xl * yh + xh * yl) << 16)) & (uint32_t)0x7FFFFFFF;
}

#else

/*
 * Multiply two 31-bit integers, with a 62-bit result. This default
 * implementation assumes that the basic multiplication operator
 * yields constant-time code.
 * The MUL31_lo() macro returns only the low 31 bits of the product.
 */
#define MUL31(x, y)     ((uint64_t)(x) * (uint64_t)(y))
#define MUL31_lo(x, y)  (((uint32_t)(x) * (uint32_t)(y)) & (uint32_t)0x7FFFFFFF)

#endif

/*
 * Multiply two words together; the sum of the lengths of the two
 * operands must not exceed 31 (for instance, one operand may use 16
 * bits if the other fits on 15). If BR_CT_MUL15 is non-zero, then the
 * macro will contain some extra operations that help in making the
 * operation constant-time on some platforms, where the basic 32-bit
 * multiplication is not constant-time.
 */
#if BR_CT_MUL15
#define MUL15(x, y)   (((uint32_t)(x) | (uint32_t)0x80000000) \
                       * ((uint32_t)(y) | (uint32_t)0x80000000) \
		       & (uint32_t)0x7FFFFFFF)
#else
#define MUL15(x, y)   ((uint32_t)(x) * (uint32_t)(y))
#endif

/*
 * Arithmetic right shift (sign bit is copied). What happens when
 * right-shifting a negative value is _implementation-defined_, so it
 * does not trigger undefined behaviour, but it is still up to each
 * compiler to define (and document) what it does. Most/all compilers
 * will do an arithmetic shift, the sign bit being used to fill the
 * holes; this is a native operation on the underlying CPU, and it would
 * make little sense for the compiler to do otherwise. GCC explicitly
 * documents that it follows that convention.
 *
 * Still, if BR_NO_ARITH_SHIFT is defined (and non-zero), then an
 * alternate version will be used, that does not rely on such
 * implementation-defined behaviour. Unfortunately, it is also slower
 * and yields bigger code, which is why it is deactivated by default.
 */
#if BR_NO_ARITH_SHIFT
#define ARSH(x, n)   (((uint32_t)(x) >> (n)) \
                      | ((-((uint32_t)(x) >> 31)) << (32 - (n))))
#else
#define ARSH(x, n)   ((*(int32_t *)&(x)) >> (n))
#endif

/*
 * Constant-time division. The dividend hi:lo is divided by the
 * divisor d; the quotient is returned and the remainder is written
 * in *r. If hi == d, then the quotient does not fit on 32 bits;
 * returned value is thus truncated. If hi > d, returned values are
 * indeterminate.
 */
uint32_t br_divrem(uint32_t hi, uint32_t lo, uint32_t d, uint32_t *r);

/*
 * Wrapper for br_divrem(); the remainder is returned, and the quotient
 * is discarded.
 */
static inline uint32_t
br_rem(uint32_t hi, uint32_t lo, uint32_t d)
{
	uint32_t r;

	br_divrem(hi, lo, d, &r);
	return r;
}

/*
 * Wrapper for br_divrem(); the quotient is returned, and the remainder
 * is discarded.
 */
static inline uint32_t
br_div(uint32_t hi, uint32_t lo, uint32_t d)
{
	uint32_t r;

	return br_divrem(hi, lo, d, &r);
}



/* ==================================================================== */

/*
 * Integers 'i31'
 * --------------
 *
 * The 'i31' functions implement computations on big integers using
 * an internal representation as an array of 32-bit integers. For
 * an array x[]:
 *  -- x[0] encodes the array length and the "announced bit length"
 *     of the integer: namely, if the announced bit length is k,
 *     then x[0] = ((k / 31) << 5) + (k % 31).
 *  -- x[1], x[2]... contain the value in little-endian order, 31
 *     bits per word (x[1] contains the least significant 31 bits).
 *     The upper bit of each word is 0.
 *
 * Multiplications rely on the elementary 32x32->64 multiplication.
 *
 * The announced bit length specifies the number of bits that are
 * significant in the subsequent 32-bit words. Unused bits in the
 * last (most significant) word are set to 0; subsequent words are
 * uninitialized and need not exist at all.
 *
 * The execution time and memory access patterns of all computations
 * depend on the announced bit length, but not on the actual word
 * values. For modular integers, the announced bit length of any integer
 * modulo n is equal to the actual bit length of n; thus, computations
 * on modular integers are "constant-time" (only the modulus length may
 * leak).
 */

/*
 * Test whether an integer is zero.
 */
uint32_t br_i31_iszero(const uint32_t *x);

/*
 * Add b[] to a[] and return the carry (0 or 1). If ctl is 0, then a[]
 * is unmodified, but the carry is still computed and returned. The
 * arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
uint32_t br_i31_add(uint32_t *a, const uint32_t *b, uint32_t ctl);

/*
 * Subtract b[] from a[] and return the carry (0 or 1). If ctl is 0,
 * then a[] is unmodified, but the carry is still computed and returned.
 * The arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
uint32_t br_i31_sub(uint32_t *a, const uint32_t *b, uint32_t ctl);

/*
 * Compute the ENCODED actual bit length of an integer. The argument x
 * should point to the first (least significant) value word of the
 * integer. The len 'xlen' contains the number of 32-bit words to
 * access. The upper bit of each value word MUST be 0.
 * Returned value is ((k / 31) << 5) + (k % 31) if the bit length is k.
 *
 * CT: value or length of x does not leak.
 */
uint32_t br_i31_bit_length(uint32_t *x, size_t xlen);

/*
 * Decode an integer from its big-endian unsigned representation. The
 * "true" bit length of the integer is computed and set in the encoded
 * announced bit length (x[0]), but all words of x[] corresponding to
 * the full 'len' bytes of the source are set.
 *
 * CT: value or length of x does not leak.
 */
void br_i31_decode(uint32_t *x, const void *src, size_t len);

/*
 * Decode an integer from its big-endian unsigned representation. The
 * integer MUST be lower than m[]; the (encoded) announced bit length
 * written in x[] will be equal to that of m[]. All 'len' bytes from the
 * source are read.
 *
 * Returned value is 1 if the decode value fits within the modulus, 0
 * otherwise. In the latter case, the x[] buffer will be set to 0 (but
 * still with the announced bit length of m[]).
 *
 * CT: value or length of x does not leak. Memory access pattern depends
 * only of 'len' and the announced bit length of m. Whether x fits or
 * not does not leak either.
 */
uint32_t br_i31_decode_mod(uint32_t *x,
	const void *src, size_t len, const uint32_t *m);

/*
 * Zeroize an integer. The announced bit length is set to the provided
 * value, and the corresponding words are set to 0. The ENCODED bit length
 * is expected here.
 */
static inline void
br_i31_zero(uint32_t *x, uint32_t bit_len)
{
	*x ++ = bit_len;
	memset(x, 0, ((bit_len + 31) >> 5) * sizeof *x);
}

/*
 * Right-shift an integer. The shift amount must be lower than 31
 * bits.
 */
void br_i31_rshift(uint32_t *x, int count);

/*
 * Reduce an integer (a[]) modulo another (m[]). The result is written
 * in x[] and its announced bit length is set to be equal to that of m[].
 *
 * x[] MUST be distinct from a[] and m[].
 *
 * CT: only announced bit lengths leak, not values of x, a or m.
 */
void br_i31_reduce(uint32_t *x, const uint32_t *a, const uint32_t *m);

/*
 * Decode an integer from its big-endian unsigned representation, and
 * reduce it modulo the provided modulus m[]. The announced bit length
 * of the result is set to be equal to that of the modulus.
 *
 * x[] MUST be distinct from m[].
 */
void br_i31_decode_reduce(uint32_t *x,
	const void *src, size_t len, const uint32_t *m);

/*
 * Multiply x[] by 2^31 and then add integer z, modulo m[]. This
 * function assumes that x[] and m[] have the same announced bit
 * length, the announced bit length of m[] matches its true
 * bit length.
 *
 * x[] and m[] MUST be distinct arrays. z MUST fit in 31 bits (upper
 * bit set to 0).
 *
 * CT: only the common announced bit length of x and m leaks, not
 * the values of x, z or m.
 */
void br_i31_muladd_small(uint32_t *x, uint32_t z, const uint32_t *m);

/*
 * Encode an integer into its big-endian unsigned representation. The
 * output length in bytes is provided (parameter 'len'); if the length
 * is too short then the integer is appropriately truncated; if it is
 * too long then the extra bytes are set to 0.
 */
void br_i31_encode(void *dst, size_t len, const uint32_t *x);

/*
 * Compute -(1/x) mod 2^31. If x is even, then this function returns 0.
 */
uint32_t br_i31_ninv31(uint32_t x);

/*
 * Compute a modular Montgomery multiplication. d[] is filled with the
 * value of x*y/R modulo m[] (where R is the Montgomery factor). The
 * array d[] MUST be distinct from x[], y[] and m[]. x[] and y[] MUST be
 * numerically lower than m[]. x[] and y[] MAY be the same array. The
 * "m0i" parameter is equal to -(1/m0) mod 2^31, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer).
 */
void br_i31_montymul(uint32_t *d, const uint32_t *x, const uint32_t *y,
	const uint32_t *m, uint32_t m0i);

/*
 * Convert a modular integer to Montgomery representation. The integer x[]
 * MUST be lower than m[], but with the same announced bit length.
 */
void br_i31_to_monty(uint32_t *x, const uint32_t *m);

/*
 * Convert a modular integer back from Montgomery representation. The
 * integer x[] MUST be lower than m[], but with the same announced bit
 * length. The "m0i" parameter is equal to -(1/m0) mod 2^32, where m0 is
 * the least significant value word of m[] (this works only if m[] is
 * an odd integer).
 */
void br_i31_from_monty(uint32_t *x, const uint32_t *m, uint32_t m0i);

/*
 * Compute a modular exponentiation. x[] MUST be an integer modulo m[]
 * (same announced bit length, lower value). m[] MUST be odd. The
 * exponent is in big-endian unsigned notation, over 'elen' bytes. The
 * "m0i" parameter is equal to -(1/m0) mod 2^31, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer). The t1[] and t2[] parameters must be temporary arrays,
 * each large enough to accommodate an integer with the same size as m[].
 */
void br_i31_modpow(uint32_t *x, const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *t1, uint32_t *t2);

/*
 * Compute a modular exponentiation. x[] MUST be an integer modulo m[]
 * (same announced bit length, lower value). m[] MUST be odd. The
 * exponent is in big-endian unsigned notation, over 'elen' bytes. The
 * "m0i" parameter is equal to -(1/m0) mod 2^31, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer). The tmp[] array is used for temporaries, and has size
 * 'twlen' words; it must be large enough to accommodate at least two
 * temporary values with the same size as m[] (including the leading
 * "bit length" word). If there is room for more temporaries, then this
 * function may use the extra room for window-based optimisation,
 * resulting in faster computations.
 *
 * Returned value is 1 on success, 0 on error. An error is reported if
 * the provided tmp[] array is too short.
 */
uint32_t br_i31_modpow_opt(uint32_t *x, const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *tmp, size_t twlen);


/*
 * Compute a modular exponentiation with module re-randomization.
 *
 * x[] MUST be an integer modulo m[] (same announced bit length, lower value).
 * m[] MUST be odd. The exponent is in big-endian unsigned notation, over 'elen' bytes.
 * The "m0i" parameter is equal to -(1/m0) mod 2^31, where m0 is the least significant
 * value word of m[] (this works only if m[] is an odd integer).
 *
 * This function incorporates module re-randomization techniques, which randomize the modulus 
 * during computation. This additional step enhances protection against side-channel attacks.
 *
 * The tmp[] array is used for temporaries and has size 'twlen' words; it must be large enough
 * to accommodate at least two temporary values with the same size as m[] (including the leading
 * "bit length" word). If there is room for more temporaries, then this function may use the extra
 * space for window-based optimisation, resulting in faster computations.
 *
 * Returned value is 1 on success, 0 on error. An error is reported if the provided tmp[] array
 * is too short.
 */
uint32_t
br_i31_modpow_opt_rand(uint32_t *x,
	const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *tmp, size_t twlen);


/*
 * Compute d+a*b, result in d. The initial announced bit length of d[]
 * MUST match that of a[]. The d[] array MUST be large enough to
 * accommodate the full result, plus (possibly) an extra word. The
 * resulting announced bit length of d[] will be the sum of the announced
 * bit lengths of a[] and b[] (therefore, it may be larger than the actual
 * bit length of the numerical result).
 *
 * a[] and b[] may be the same array. d[] must be disjoint from both a[]
 * and b[].
 */
void br_i31_mulacc(uint32_t *d, const uint32_t *a, const uint32_t *b);

/*
 * Compute x/y mod m, result in x. Values x and y must be between 0 and
 * m-1, and have the same announced bit length as m. Modulus m must be
 * odd. The "m0i" parameter is equal to -1/m mod 2^31. The array 't'
 * must point to a temporary area that can hold at least three integers
 * of the size of m.
 *
 * m may not overlap x and y. x and y may overlap each other (this can
 * be useful to test whether a value is invertible modulo m). t must be
 * disjoint from all other arrays.
 *
 * Returned value is 1 on success, 0 otherwise. Success is attained if
 * y is invertible modulo m.
 */
uint32_t br_i31_moddiv(uint32_t *x, const uint32_t *y,
	const uint32_t *m, uint32_t m0i, uint32_t *t);

/**
 * \brief Initialize a pre-randomized RSA private key.
 *
 * This function takes a plaintext BearSSL RSA private key (`sk`) and converts it into a pre-randomized key (`new_sk`)
 * that is used in our implementation. A temporary buffer (`tmp`) is provided for intermediate computations,
 * and `fwlen` specifies the word length of the largest RSA factor.
 *
 * \param sk      Pointer to the plaintext BearSSL RSA private key.
 * \param new_sk  Pointer to the pre-randomized RSA private key.
 * \param tmp     Temporary buffer for intermediate computations.
 * \param fwlen   Word length of the largest RSA factor.
 */
void br_i31_init_key(const br_rsa_private_key *sk, br_rsa_private_key *new_sk, uint32_t *tmp, uint32_t fwlen);

/**
 * \brief Update (re-randomize) the pre-randomized RSA private key.
 *
 * This function re-randomizes the already pre-randomized RSA private key (`new_sk`). It uses a temporary buffer (`tmp`)
 * for intermediate calculations, where `fwlen` indicates the word length of the largest RSA factor.
 *
 * \param new_sk  Pointer to the RSA private key to be updated.
 * \param tmp     Temporary buffer for intermediate computations.
 * \param fwlen   Word length of the largest RSA factor.
 */
void br_i31_update_key(br_rsa_private_key *new_sk, uint32_t *tmp, uint32_t fwlen);

/**
 * \brief Perform classical exponent blinding.
 *
 * This function applies exponent blinding to protect against side-channel attacks. The original exponent (`d`)
 * is blinded and the result is stored in `x`. The randomized Euler’s totient value (either φ_p or φ_q) from the
 * modified key is provided in `m`, and `t1` serves as a workspace buffer.
 *
 * \param x     Destination buffer for the blinded exponent.
 * \param d     Original exponent.
 * \param size  Size of the exponent in bytes.
 * \param m     Blinded Euler’s totient (either φ_p or φ_q) from the modified key.
 * \param t1    Temporary workspace buffer.
 * \return      The size (in bytes) of the resulting blinded exponent.
 */
size_t blind_exponent(unsigned char *x, const unsigned char *d, const size_t size, uint32_t *m, uint32_t *t1);

/**
 * \brief Generate random numbers.
 *
 * This function generates random numbers and stores them in the destination buffer (`x`). The parameter `esize`
 * specifies the number of bits to generate.
 *
 * \param x      Destination buffer for the generated random numbers.
 * \param esize  Number of bits to generate.
 */
void make_rand(uint32_t *x, uint32_t esize);

/**
 * @brief Initialize a temporary RSA key structure for re-randomization.
 *
 * This function creates a mutable copy of a constant BearSSL RSA private key by populating
 * the provided temporary RSA key structure with the key components and associated buffers.
 * It also initializes the random factor (r1) used for key pre-randomization, which is essential
 * for subsequent operations such as re-randomization of the key to protect against fault injection attacks.
 *
 * @param temp Pointer to the temporary RSA key structure to be initialized.
 * @param sk   Pointer to the original (const) BearSSL RSA private key.
 */
void init_temp_rsa_key(temp_rsa_key_t *temp, const br_rsa_private_key *sk);
#endif
