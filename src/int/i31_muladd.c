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

#include "inner.h"

/* see inner.h */
void
br_i31_muladd_small(uint32_t *x, uint32_t z, const uint32_t *m)
{
	uint32_t ann_bitlen, real_bitlen;
	unsigned real_mblr;
	size_t u, mlen_ann, mlen_real, top;
	uint32_t a0, a1, b0, hi, g, q, tb;
	uint32_t under, over;
	uint32_t cc;

	/*
	 * m[0] now contains the *announced* bit length.
	 * Time will depend on this value (loop bounds, memmove size).
	 */
	ann_bitlen = m[0];
	if (ann_bitlen == 0) {
		return;
	}
	/* Announced length controls the work (runtime). */
	mlen_ann = (ann_bitlen + 31) >> 5;
	/*
	 * Real bit-length is recomputed from the value; it may be
	 * <= announced bit-length. We use it only to locate the
	 * actual top word of the modulus for the quotient estimate.
	 */
	real_bitlen = br_i31_bit_length(m + 1, mlen_ann);
	if (real_bitlen == 0) {
		/* Degenerate modulus; nothing sensible to do. */
		return;
	}

	/*
	 * Small-modulus special case: keep this branch dependent on
	 * the *announced* bit-length, to keep timing tied to it.
	 * If real_bitlen <= 31 but ann_bitlen > 31, we harmlessly
	 * fall back to the generic path (still correct, just slower).
	 */
	if (ann_bitlen <= 31) {
		uint32_t lo;

		hi = x[1] >> 1;
		lo = (x[1] << 31) | z;
		/* For the math we still use the actual modulus word m[1]. */
		x[1] = br_rem(hi, lo, m[1]);
		return;
	}



	/* Real length controls where the *real* top word is. */
	mlen_real = (real_bitlen + 31) >> 5;
	real_mblr = (unsigned)real_bitlen & 31;

	/*
	 * Top word index of the *real* modulus (1-based, i31 format).
	 * We assume real_bitlen > 31 here, so mlen_real >= 2.
	 */
	top = mlen_real;

	/*
	 * hi is taken at the announced length, so that the data
	 * movement and comparisons later run up to mlen_ann and
	 * timing matches the announced size.
	 */
	hi = x[mlen_ann];

	/*
	 * Build a0, a1 and b0 from the *real* top words, but perform
	 * the memmove with the announced length (constant-time in the
	 * announced bit-length).
	 */
	if (real_mblr == 0) {
		/*
		 * Modulus is word-aligned in i31 representation.
		 * Top real word is at index "top".
		 */
		a0 = x[top];
		memmove(x + 2, x + 1, (mlen_ann - 1) * sizeof *x);
		x[1] = z;
		a1 = x[top];
		b0 = m[top];
	} else {
		/*
		 * Top real 31-bit chunk is formed from words "top" and "top-1".
		 * Note: since real_bitlen > 31, we know top >= 2.
		 */
		a0 = ((x[top] << (31 - real_mblr))
			| (x[top - 1] >> real_mblr)) & 0x7FFFFFFF;
		memmove(x + 2, x + 1, (mlen_ann - 1) * sizeof *x);
		x[1] = z;
		a1 = ((x[top] << (31 - real_mblr))
			| (x[top - 1] >> real_mblr)) & 0x7FFFFFFF;
		b0 = ((m[top] << (31 - real_mblr))
			| (m[top - 1] >> real_mblr)) & 0x7FFFFFFF;
	}

	/*
	 * Quotient estimate as in the original code, but now built from
	 * (a0,a1,b0) computed with the real bit-length.
	 */
	g = br_div(a0 >> 1, a1 | (a0 << 31), b0);
	q = MUX(EQ(a0, b0), 0x7FFFFFFF, MUX(EQ(g, 0), 0, g - 1));

	/*
	 * Subtract q*m from x.
	 *
	 * The loop bound is mlen_ann (announced length) so that the
	 * runtime is tied to the announced bit-length. You must ensure
	 * that m[1..mlen_ann] is valid and zero-padded above the real
	 * top word.
	 */
	cc = 0;
	tb = 1;
	for (u = 1; u <= mlen_ann; u ++) {
		uint32_t mw, zw, xw, nxw;
		uint64_t zl;

		mw = m[u];      /* For u > mlen_real this should be 0. */
		zl = MUL31(mw, q) + cc;
		cc = (uint32_t)(zl >> 31);
		zw = (uint32_t)zl & (uint32_t)0x7FFFFFFF;
		xw = x[u];
		nxw = xw - zw;
		cc += nxw >> 31;
		nxw &= 0x7FFFFFFF;
		x[u] = nxw;
		tb = MUX(EQ(nxw, mw), tb, GT(nxw, mw));
	}

	/*
	 * Final correction (same logic as original), but note that
	 * "hi" came from x[mlen_ann], so the comparisons also scale
	 * with the announced size.
	 */
	over = GT(cc, hi);
	under = ~over & (tb | LT(cc, hi));
	br_i31_add(x, m, over);
	br_i31_sub(x, m, under);
}