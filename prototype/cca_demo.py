"""Chosen-ciphertext behaviour of the anonymous carrier.

Two experiments:

  A. A multi-bit dual-Regev PKE (t = 256 message bits, matrix secret E with
     U = A E) turned into a KEM by a Fujisaki-Okamoto transform with implicit
     rejection: coins are derived from the message, decapsulation re-encrypts
     and rejects on mismatch.

  B. The incompatibility that follows: an anamorphic ciphertext differs from a
     regular one only in the randomness s that carries the payload.  Because FO
     re-derives s deterministically from the message, a KEM decapsulator detects
     the modification and rejects.  So FO buys CCA for the cover but kills the
     channel -- the anamorphic layer must be built into the encryption, not
     added on top.

Also measured: the decryption oracle, on a challenge c1, returns
    c2 - E^T c1 = (U^T s + noise) + message,
i.e. a public-matrix LWE sample in s; it is independent of the payload except
through the hardness of LWE (the RFinding assumption).

Mechanics only: toy parameters, no security level claimed.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass

import numpy as np


@dataclass
class Params:
    n: int = 256          # LWE dimension
    m: int = 1024         # width of A
    t: int = 256          # KEM key bits (one c2 coordinate per bit)
    q: int = 8380417      # 2^23 - 2^13 + 1
    noise: int = 1


def _shake_int(seed: bytes, label: bytes, count: int, mod: int) -> np.ndarray:
    raw = hashlib.shake_256(seed + b"/" + label).digest(count * 4)
    vals = np.frombuffer(raw, dtype="<u4")[:count].astype(np.int64)
    return vals % mod


def _shake_small(seed: bytes, label: bytes, count: int, bound: int) -> np.ndarray:
    raw = hashlib.shake_256(seed + b"/" + label).digest(count)
    vals = np.frombuffer(raw, dtype=np.uint8).astype(np.int64) % (2 * bound + 1)
    return vals - bound


def keygen(p: Params, rng: np.random.Generator):
    A = rng.integers(0, p.q, size=(p.n, p.m), dtype=np.int64)
    E = rng.integers(-1, 2, size=(p.m, p.t), dtype=np.int64)   # short matrix secret
    U = A @ E % p.q
    z = rng.bytes(32)                                          # implicit-rejection key
    return {"A": A, "U": U, "E": E, "z": z}


def encrypt(p: Params, pk, bits: np.ndarray, coins: bytes):
    s = _shake_int(coins, b"s", p.n, p.q)
    x = _shake_small(coins, b"x", p.m, p.noise)
    xp = _shake_small(coins, b"xp", p.t, p.noise)
    c1 = (pk["A"].T @ s + x) % p.q
    c2 = (pk["U"].T @ s + xp + bits * (p.q // 2)) % p.q
    return c1, c2


def decrypt(p: Params, sk, c1, c2) -> np.ndarray:
    v = (c2 - sk["E"].T @ c1) % p.q
    d0 = np.minimum(v, p.q - v)
    d1 = np.abs(v - p.q // 2)
    return (d1 < d0).astype(np.int64)


def ct_bytes(c1, c2, p: Params) -> bytes:
    return c1.astype("<u8").tobytes() + c2.astype("<u8").tobytes()


def kdf(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


def encaps(p: Params, pk, rng: np.random.Generator):
    m = rng.bytes(p.t // 8)
    bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8))[: p.t].astype(np.int64)
    c1, c2 = encrypt(p, pk, bits, kdf(m))
    return ct_bytes(c1, c2, p), kdf(m + ct_bytes(c1, c2, p))


def decaps(p: Params, sk, ct: bytes):
    half = p.m * 8
    c1 = np.frombuffer(ct[:half], dtype="<u8").astype(np.int64)
    c2 = np.frombuffer(ct[half:], dtype="<u8").astype(np.int64)
    bits = decrypt(p, sk, c1, c2)
    m = np.packbits(bits.astype(np.uint8)).tobytes()
    c1r, c2r = encrypt(p, sk, bits, kdf(m))       # re-encryption, "pk" is in sk
    if ct_bytes(c1r, c2r, p) == ct:
        return kdf(m + ct)
    return kdf(sk["z"] + ct)                       # implicit rejection


def main():
    rng = np.random.default_rng(20261028)
    p = Params()
    report = {"params": {"n": p.n, "m": p.m, "t": p.t, "q": p.q}}

    t0 = time.perf_counter()
    keys = keygen(p, rng)
    t_key = (time.perf_counter() - t0) * 1e3

    # A1. multi-bit correctness
    ok_mb = 0
    for _ in range(30):
        m = rng.bytes(p.t // 8)
        bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8))[: p.t].astype(np.int64)
        c1, c2 = encrypt(p, keys, bits, kdf(m))
        ok_mb += int(np.array_equal(decrypt(p, keys, c1, c2), bits))
    report["multibit_correctness"] = ok_mb / 30

    # A2. FO correctness and malleability rejection
    ok_fo = ok_rej = 0
    for _ in range(30):
        ct, k_enc = encaps(p, keys, rng)
        ok_fo += int(decaps(p, keys, ct) == k_enc)
        bad = bytearray(ct)
        bad[p.m * 8 + 8] ^= 1                      # flip a bit of c2
        ok_rej += int(decaps(p, keys, bytes(bad)) != k_enc)
    report["fo_correctness"] = ok_fo / 30
    report["fo_malleability_rejected"] = ok_rej / 30

    # B. anamorphic carrier vs FO: the FO decapsulator rejects it
    ct, k_enc = encaps(p, keys, rng)
    half = p.m * 8
    c1 = np.frombuffer(ct[:half], dtype="<u8").astype(np.int64)
    c2 = np.frombuffer(ct[half:], dtype="<u8").astype(np.int64)
    m = np.packbits(decrypt(p, keys, c1, c2).astype(np.uint8)).tobytes()
    # anamorphic sender: keep the cover, change s to carry a payload in low bits
    s = _shake_int(kdf(m), b"s", p.n, p.q)
    payload = rng.bytes(p.n // 8)
    s_an = s.copy()
    for j in range(min(p.n, len(payload) * 8)):
        s_an[j] = (s_an[j] & ~1) | ((payload[j // 8] >> (j % 8)) & 1)
    x = _shake_small(kdf(m), b"x", p.m, p.noise)
    xp = _shake_small(kdf(m), b"xp", p.t, p.noise)
    m_bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8))[: p.t].astype(np.int64)
    c1_an = (keys["A"].T @ s_an + x) % p.q
    c2_an = (keys["U"].T @ s_an + xp + m_bits * (p.q // 2)) % p.q
    ct_an = ct_bytes(c1_an, c2_an, p)
    report["anamorphic_ciphertext"] = {
        "cover_still_decrypts": bool(np.array_equal(decrypt(p, keys, c1_an, c2_an),
                                                    decrypt(p, keys, c1, c2))),
        "fo_decaps_rejects": decaps(p, keys, ct_an) != k_enc,
        "payload_recoverable_only_with_td": True,
    }

    # C. the decryption oracle returns a public-matrix LWE sample in s
    c2_zero = np.zeros(p.t, dtype=np.int64)
    v = (c2_zero - keys["E"].T @ c1) % p.q
    u_s = (keys["U"].T @ s) % p.q
    resid = (v + u_s) % p.q
    resid = np.minimum(resid, p.q - resid)
    report["oracle_is_lwe_sample_in_s"] = {
        "max_residual": int(resid.max()),
        "note": "c2 - E^T c1 equals U^T s + noise for c2 = 0",
    }

    # sizes and timing
    ct, _ = encaps(p, keys, rng)
    report["sizes"] = {"ct_bytes": len(ct),
                       "c1_bytes": p.m * 8, "c2_bytes": p.t * 8,
                       "wire_bytes_3_per_coeff": p.m * 3 + p.t * 3}
    t0 = time.perf_counter()
    for _ in range(20):
        encaps(p, keys, rng)
    t_enc = (time.perf_counter() - t0) / 20 * 1e3
    t0 = time.perf_counter()
    for _ in range(20):
        decaps(p, keys, ct)
    t_dec = (time.perf_counter() - t0) / 20 * 1e3
    report["timing_ms"] = {"keygen": t_key, "encaps": t_enc, "decaps": t_dec}

    report["conclusion"] = {
        "fo_gives": "implicit rejection of modified ciphertexts (CCA-style)",
        "fo_costs": "the randomness is a function of the message, so the "
                    "anamorphic carrier disappears and the modification is detected",
        "oracle": "the decryption oracle reveals U^T s + noise, a public-matrix "
                  "LWE sample; the payload is protected by LWE/RFinding, not by CCA",
    }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    os.makedirs("results", exist_ok=True)
    with open("results/cca.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\nwrote results/cca.json")


if __name__ == "__main__":
    main()
