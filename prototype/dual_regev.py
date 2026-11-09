"""Real dual-Regev public-key encryption (CPA), for calibrating working point A.

What this IS:
  * Gentry-Peikert-Vaikuntanathan "dual" LWE encryption:
        pk = (A in Z_q^{n x m}, u = A e mod q),  sk = short e
        c1 = A^T s + x  (m coords),  c2 = u^T s + x' + bit*q/2
        dec: c2 - e^T c1
  * real noise, real modular arithmetic, real ciphertext size.

What this is NOT:
  * no lattice trapdoor (MP12) and therefore no randomness recovery td;
    the "anamorphic" extraction is demonstrated white-box (the extractor is
    handed s), which is exactly what a td would provide;
  * CPA only, no CCA/FO, no security proof, no parameter optimisation.

Purpose: replace the 1088-byte structural stand-in in the A-mode row with a
measured dual-Regev ciphertext size, and check that the cover decryption is
independent of the encryption randomness s (the payload carrier).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

import numpy as np

Q = 8380417  # 2^23 - 2^13 + 1


@dataclass
class DRParams:
    n: int = 256          # LWE dimension
    m: int = 1024         # number of columns of A
    q: int = Q
    eta: int = 1          # secret e in [-eta, eta]
    noise: int = 1        # encryption noise in [-noise, noise]
    payload_bits: int = 256

    @property
    def ct_bytes(self) -> int:
        # c1: m coefficients mod q (24 bits each for byte alignment), c2: one
        return self.m * 3 + 3


def keygen(p: DRParams, rng: np.random.Generator):
    A = rng.integers(0, p.q, size=(p.n, p.m), dtype=np.int64)
    e = rng.integers(-p.eta, p.eta + 1, size=p.m, dtype=np.int64)
    u = A @ e % p.q
    return A, u, e


def encrypt(p: DRParams, A, u, bit: int, rng: np.random.Generator, s=None):
    s = rng.integers(0, p.q, size=p.n, dtype=np.int64) if s is None else s
    x = rng.integers(-p.noise, p.noise + 1, size=p.m, dtype=np.int64)
    xp = int(rng.integers(-p.noise, p.noise + 1))
    c1 = (A.T @ s + x) % p.q
    c2 = (int(u @ s) + xp + bit * (p.q // 2)) % p.q
    return (c1, c2), s


def decrypt(p: DRParams, e, ct) -> int:
    c1, c2 = ct
    d = (int(c2) - int(e @ c1)) % p.q
    # distance to 0 and to q/2
    dist0 = min(d, p.q - d)
    dist1 = abs(d - p.q // 2)
    return 1 if dist1 < dist0 else 0


def noise_term(p: DRParams, e, ct, bit: int) -> int:
    c1, c2 = ct
    d = (int(c2) - int(e @ c1) - bit * (p.q // 2)) % p.q
    return d - p.q if d > p.q // 2 else d


def pack_s(p: DRParams, s: np.ndarray, payload: int) -> np.ndarray:
    """Encode payload bits into the low bits of the first payload_bits
    coordinates of s.  In a real anamorphic scheme s would be sampled from a
    PRF(td, nonce) so that its distribution stays uniform; the point here is
    only that the payload rides in s."""
    out = s.copy()
    for i in range(p.payload_bits):
        out[i] = (out[i] & ~1) | ((payload >> i) & 1)
    return out


def unpack_s(p: DRParams, s: np.ndarray) -> int:
    payload = 0
    for i in range(p.payload_bits):
        payload |= (int(s[i]) & 1) << i
    return payload


def main():
    p = DRParams()
    rng = np.random.default_rng(20261024)
    A, u, e = keygen(p, rng)

    report = {"params": {"n": p.n, "m": p.m, "q": p.q, "eta": p.eta,
                         "noise": p.noise, "payload_bits": p.payload_bits,
                         "ct_bytes": p.ct_bytes}}

    # 1. correctness over random cover bits and random s
    ok = 0
    worst = 0
    trials = 200
    for _ in range(trials):
        bit = int(rng.integers(0, 2))
        ct, _ = encrypt(p, A, u, bit, rng)
        if decrypt(p, e, ct) == bit:
            ok += 1
        worst = max(worst, abs(noise_term(p, e, ct, bit)))
    report["correctness"] = {"ok": ok / trials,
                             "worst_noise": int(worst),
                             "q_over_4": p.q // 4,
                             "noise_margin_ratio": float(worst / (p.q // 4))}

    # 2. cover decryption is independent of s: same bit, 100 different s
    indep = 0
    for _ in range(100):
        bit = 1
        s = rng.integers(0, p.q, size=p.n, dtype=np.int64)
        ct, _ = encrypt(p, A, u, bit, rng, s=s)
        indep += int(decrypt(p, e, ct) == bit)
    report["cover_independent_of_s"] = indep / 100

    # 3. payload rides in s (white-box extraction = what a td would give)
    pay_ok = 0
    for _ in range(50):
        payload = int.from_bytes(hashlib.sha256(rng.bytes(8)).digest()[: p.payload_bits // 8], "little")
        s = pack_s(p, rng.integers(0, p.q, size=p.n, dtype=np.int64), payload)
        ct, _ = encrypt(p, A, u, 0, rng, s=s)
        # cover still decrypts ...
        assert decrypt(p, e, ct) == 0
        # ... and the payload comes back from s (white-box)
        pay_ok += int(unpack_s(p, s) == payload)
    report["payload_in_s"] = {"ok": pay_ok / 50,
                              "capacity_bits_theory": p.n * 23,
                              "uses_bits": p.payload_bits}

    # 4. sizes
    ct, _ = encrypt(p, A, u, 1, rng)
    actual = int(ct[0].nbytes + 8)  # int64 storage; on the wire 24 bits/coeff
    report["sizes"] = {
        "ct_bytes_wire": p.ct_bytes,
        "c1_coeffs": p.m, "c1_bits_per_coeff": 24,
        "c2_coeffs": 1,
        "note": "q < 2^24, so 3 bytes per c1 coefficient on the wire",
    }

    # 5. timing
    t0 = time.perf_counter()
    for _ in range(50):
        ct, _ = encrypt(p, A, u, 1, rng)
    enc_ms = (time.perf_counter() - t0) / 50 * 1e3
    t0 = time.perf_counter()
    for _ in range(50):
        decrypt(p, e, ct)
    dec_ms = (time.perf_counter() - t0) / 50 * 1e3
    t0 = time.perf_counter()
    for _ in range(3):
        keygen(p, rng)
    kg_ms = (time.perf_counter() - t0) / 3 * 1e3
    report["timing_ms"] = {"keygen": kg_ms, "encrypt": enc_ms, "decrypt": dec_ms,
                           "note": "pure numpy; encryption is one n x m mat-vec"}

    # 6. comparison with the structural stand-in used in the prototype
    report["comparison"] = {
        "structural_stand_in_bytes": 1136,
        "real_dual_regev_bytes": p.ct_bytes,
        "delta": p.ct_bytes - 1136,
        "ring_base_bytes": 9760,
        "A_total_structural": 9760 + 1136,
        "A_total_real": 9760 + p.ct_bytes,
    }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    with open("results/dual_regev.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\nwrote results/dual_regev.json")


if __name__ == "__main__":
    main()
