"""Randomness-recovery trapdoor (MP12-style) for the dual-Regev carrier.

What this demonstrates
----------------------
  * A = [A_bar | G - A_bar R] with a short trapdoor R, so that A [R; I] = G.
  * Dual Regev: u = A e (short e), c1 = A^T s + x, c2 = u^T s + x' + b*q/2.
    The cover bit decrypts with e and is *independent of s*.
  * The extractor holding R recovers s from c1 by gadget decoding:
        [R; I]^T c1 = G^T s + noise,
    and s carries the payload.
  * The warden holding only e (the ordinary secret key) has no algorithm for s;
    that is the RFinding / LWE assumption, not something this demo can prove.

Simplifications (labelled, and they matter for the size):
  * s is BINARY, one payload bit per coordinate, so decoding is a two-way
    hypothesis test per block instead of full gadget inversion for uniform s.
    Capacity is n bits = 384, exactly the 48-byte payload (m' || MAC).
  * q = 2^13 and small dimensions: mechanics only, no security level claimed.
  * The gadget blow-up is real: the ciphertext has m = m_bar + n*log2(q)
    coefficients, i.e. about log2(q) times a square dual-Regev ciphertext.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

import numpy as np


@dataclass
class Params:
    n: int = 384          # LWE dimension = payload capacity in bits
    m_bar: int = 192      # width of A_bar
    q: int = 1 << 13      # gadget-friendly modulus
    noise: int = 1        # encryption noise in {-1,0,1}

    @property
    def k(self) -> int:
        return self.q.bit_length() - 1

    @property
    def nk(self) -> int:
        return self.n * self.k

    @property
    def m(self) -> int:
        return self.m_bar + self.nk


def keygen(p: Params, rng: np.random.Generator):
    A_bar = rng.integers(0, p.q, size=(p.n, p.m_bar), dtype=np.int64)
    R = rng.integers(-1, 2, size=(p.m_bar, p.nk), dtype=np.int64)
    # gadget G = I_n (x) g, g = (1, 2, 4, ..., 2^{k-1})
    G = np.zeros((p.n, p.nk), dtype=np.int64)
    for i in range(p.n):
        G[i, i * p.k:(i + 1) * p.k] = [1 << j for j in range(p.k)]
    A = np.concatenate([A_bar, (G - A_bar @ R) % p.q], axis=1)
    e = rng.integers(-1, 2, size=p.m, dtype=np.int64)
    u = A @ e % p.q
    return {"A": A, "A_bar": A_bar, "R": R, "e": e, "u": u}


def encrypt(p: Params, keys, payload_bits: np.ndarray, cover: int,
            rng: np.random.Generator):
    s = payload_bits.astype(np.int64)
    x = rng.integers(-p.noise, p.noise + 1, size=p.m, dtype=np.int64)
    xp = int(rng.integers(-p.noise, p.noise + 1))
    c1 = (keys["A"].T @ s + x) % p.q
    c2 = (int(keys["u"] @ s) + xp + cover * (p.q // 2)) % p.q
    return c1, c2


def decrypt_cover(p: Params, keys, c1, c2) -> int:
    d = (int(c2) - int(keys["e"] @ c1)) % p.q
    dist0 = min(d, p.q - d)
    dist1 = abs(d - p.q // 2)
    return 1 if dist1 < dist0 else 0


def recover_s(p: Params, keys, c1) -> np.ndarray:
    """Gadget decoding with the trapdoor R: [R; I]^T c1 = G^T s + noise."""
    R, m_bar = keys["R"], p.m_bar
    y = (R.T @ c1[:m_bar] + c1[m_bar:]) % p.q
    y = y.reshape(p.n, p.k)
    g = np.array([1 << j for j in range(p.k)], dtype=np.int64)
    bits = np.zeros(p.n, dtype=np.int64)
    for i in range(p.n):
        # distance of y[i, j] to sigma * 2^j, circularly
        best, best_sigma = None, 0
        for sigma in (0, 1):
            diff = (y[i] - sigma * g) % p.q
            diff = np.minimum(diff, p.q - diff)
            cost = int(np.sum(diff.astype(np.int64) ** 2))
            if best is None or cost < best:
                best, best_sigma = cost, sigma
        bits[i] = best_sigma
    return bits


def payload_bits(p: Params, payload: bytes) -> np.ndarray:
    assert len(payload) * 8 <= p.n
    return np.unpackbits(np.frombuffer(payload, dtype=np.uint8)).astype(np.int64)


def main():
    rng = np.random.default_rng(20261027)
    p = Params()
    report = {"params": {"n": p.n, "m_bar": p.m_bar, "m": p.m, "q": p.q,
                         "k": p.k, "capacity_bits": p.n}}

    t0 = time.perf_counter()
    keys = keygen(p, rng)
    t_keygen = (time.perf_counter() - t0) * 1e3

    # correctness of both extraction paths, over random payloads and cover bits
    cover_ok = td_ok = 0
    trials = 50
    for _ in range(trials):
        msg = rng.bytes(p.n // 8)
        bits = payload_bits(p, msg)
        cover = int(rng.integers(0, 2))
        t0 = time.perf_counter()
        c1, c2 = encrypt(p, keys, bits, cover, rng)
        t_enc = (time.perf_counter() - t0) * 1e3
        cover_ok += int(decrypt_cover(p, keys, c1, c2) == cover)
        t0 = time.perf_counter()
        rec = recover_s(p, keys, c1)
        t_rec = (time.perf_counter() - t0) * 1e3
        td_ok += int(np.array_equal(rec, bits))
    report["correctness"] = {"cover_decryption": cover_ok / trials,
                             "trapdoor_recovery": td_ok / trials}

    # sizes
    ct_bytes_packed = (p.m * p.k + 7) // 8 + (p.k + 7) // 8
    ct_bytes_aligned = p.m * 2 + 2
    report["sizes"] = {
        "c1_coeffs": p.m,
        "bits_per_coeff": p.k,
        "ct_bytes_bitpacked": ct_bytes_packed,
        "ct_bytes_byte_aligned": ct_bytes_aligned,
        "square_dual_regev_bytes_at_same_n": (p.n * 3 + 3),
        "blowup_vs_square": p.m / p.n,
    }

    # timing
    msg = rng.bytes(p.n // 8)
    bits = payload_bits(p, msg)
    c1, c2 = encrypt(p, keys, bits, 1, rng)
    t0 = time.perf_counter()
    for _ in range(20):
        encrypt(p, keys, bits, 1, rng)
    t_enc = (time.perf_counter() - t0) / 20 * 1e3
    t0 = time.perf_counter()
    for _ in range(20):
        recover_s(p, keys, c1)
    t_rec = (time.perf_counter() - t0) / 20 * 1e3
    t0 = time.perf_counter()
    for _ in range(100):
        decrypt_cover(p, keys, c1, c2)
    t_dec = (time.perf_counter() - t0) / 100 * 1e3
    report["timing_ms"] = {"keygen": t_keygen, "encrypt": t_enc,
                           "decrypt_cover": t_dec, "recover_s": t_rec}

    report["reading"] = {
        "what_is_shown": "cover decryption with sk=e is independent of s; "
                         "the holder of R recovers s (the payload) from c1",
        "what_is_assumed": "a party holding only e cannot recover s "
                           "(RFinding / LWE); this demo cannot prove hardness",
        "size_note": "the gadget adds a factor k = log2(q): m = m_bar + n*k, "
                     "so the carrier is ~k times a square dual-Regev ciphertext",
    }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    os.makedirs("results", exist_ok=True)
    with open("results/td.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\nwrote results/td.json")


if __name__ == "__main__":
    main()
