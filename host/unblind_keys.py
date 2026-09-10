#!/usr/bin/env python3
"""Recover the plain RSA CRT parameters from the blinded test keys.

rsa_test_keys.h stores keys in the blinded form the protected implementation
consumes: p is p*r1, q is q*r2, dp is dp + phi(p*r1), and iq is the inverse in
the blinded ring. Stock br_rsa_i31_private() cannot use those - fed a blinded
key it reports success and returns a wrong plaintext - so the unprotected
baseline needs the original parameters.

r1 and r2 travel with the key, so the primes divide out exactly:

    p  = p_blinded / r1                 dp = dp_blinded mod (p-1)
    q  = q_blinded / r2                 dq = dq_blinded mod (q-1)
    iq = q^-1 mod p

Writes rsa_test_keys_plain.h. Every key is checked (p*q == n, e*dp == 1 mod
p-1, and a full CRT round trip) before it is emitted.
"""
import re
import sys
import os

SRC = os.path.join(os.path.dirname(__file__), "..", "rsa_test_keys.h")
DST = os.path.join(os.path.dirname(__file__), "..", "rsa_test_keys_plain.h")
FIELDS = ("n", "e", "r1", "r2", "p", "q", "dp", "dq", "iq")


def parse(path):
    text = open(path).read()
    blocks = re.split(r"\{\s*/\* key \d+ \*/", text)[1:]
    keys = []
    for b in blocks:
        k = {}
        for f in FIELDS:
            m = re.search(r"\.%s\s*=\s*\{(.*?)\}" % f, b, re.S)
            if not m:
                raise SystemExit("field %s missing" % f)
            data = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))
            m2 = re.search(r"\.%slen\s*=\s*(\d+)" % f, b)
            n = int(m2.group(1)) if m2 else len(data)
            k[f] = int.from_bytes(data[:n], "big")
        k["n_bitlen"] = int(re.search(r"\.n_bitlen\s*=\s*(\d+)", b).group(1))
        keys.append(k)
    return keys


def unblind(k):
    if k["p"] % k["r1"] or k["q"] % k["r2"]:
        raise SystemExit("blinding factor does not divide the blinded prime")
    p, q, e = k["p"] // k["r1"], k["q"] // k["r2"], k["e"]
    dp, dq = k["dp"] % (p - 1), k["dq"] % (q - 1)
    iq = pow(q, -1, p)
    assert p * q == k["n"], "p*q != n"
    assert e * dp % (p - 1) == 1 and e * dq % (q - 1) == 1, "exponent mismatch"
    m = 0xDEADBEEFCAFEBABE
    c = pow(m, e, k["n"])
    s1, s2 = pow(c, dp, p), pow(c, dq, q)
    assert (s2 + q * ((s1 - s2) * iq % p)) % k["n"] == m, "CRT round trip failed"
    return p, q, dp, dq, iq


def carr(name, value, nbytes, indent=8):
    b = value.to_bytes(nbytes, "big")
    pad = " " * indent
    out = ["%s.%s = {" % (pad, name)]
    for i in range(0, len(b), 12):
        out.append(pad + "    " + " ".join("0x%02X," % x for x in b[i:i + 12]))
    out.append(pad + "},")
    return "\n".join(out)


def main():
    keys = parse(SRC)
    nb = max(k["n_bitlen"] for k in keys) // 8
    pb = nb // 2
    with open(DST, "w") as f:
        f.write("""/*
 * rsa_test_keys_plain.h
 * Plain CRT parameters recovered from rsa_test_keys.h by host/unblind_keys.py.
 * Same %d keys, same order, for the unprotected br_rsa_i31_private() baseline.
 * Do not edit by hand; regenerate with the script.
 */
#ifndef RSA_TEST_KEYS_PLAIN_H
#define RSA_TEST_KEYS_PLAIN_H

#include <stdint.h>

#define RSA_PLAIN_NUM_KEYS  %d
#define RSA_PLAIN_N_BYTES   %d
#define RSA_PLAIN_P_BYTES   %d

typedef struct {
    uint8_t  n[RSA_PLAIN_N_BYTES];   uint16_t n_bitlen;
    uint8_t  e[3];                   uint16_t elen;
    uint8_t  p[RSA_PLAIN_P_BYTES];   uint16_t plen;
    uint8_t  q[RSA_PLAIN_P_BYTES];   uint16_t qlen;
    uint8_t  dp[RSA_PLAIN_P_BYTES];  uint16_t dplen;
    uint8_t  dq[RSA_PLAIN_P_BYTES];  uint16_t dqlen;
    uint8_t  iq[RSA_PLAIN_P_BYTES];  uint16_t iqlen;
} rsa4096_plain_key_t;

static const rsa4096_plain_key_t rsa_test_keys_plain[RSA_PLAIN_NUM_KEYS] = {
""" % (len(keys), len(keys), nb, pb))
        for i, k in enumerate(keys):
            p, q, dp, dq, iq = unblind(k)
            f.write("    { /* key %d */\n" % i)
            f.write("        .n_bitlen = %d,\n" % k["n_bitlen"])
            f.write(carr("n", k["n"], nb) + "\n")
            f.write("        .elen = 3,\n")
            f.write(carr("e", k["e"], 3) + "\n")
            for name, v in (("p", p), ("q", q), ("dp", dp), ("dq", dq), ("iq", iq)):
                f.write("        .%slen = %d,\n" % (name, pb))
                f.write(carr(name, v, pb) + "\n")
            f.write("    },\n")
        f.write("};\n\n#endif\n")
    print("wrote %s: %d keys verified (p*q == n, e*d == 1, CRT round trip)"
          % (os.path.relpath(DST), len(keys)))


if __name__ == "__main__":
    main()
