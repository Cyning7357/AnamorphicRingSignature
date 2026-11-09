"""VEIL prototype: decoy-response anamorphic ring signature (Scheme B).

SCOPE / WHAT THIS IS
--------------------
This is a *mechanics + embedding* prototype, not a security-parameter
implementation.  It implements the real algebraic shape of a decoy/AOS
lattice ring signature over R_q = Z_q[x]/(x^d+1):

    w_j = A*z_j - c_j*t_j,   c_{j+1} = H(oid, epoch, m, j, w_j, ct)

with uniform-box responses (DualRing-LB style) -- NOT Gaussians.  It uses
small parameters and plain negacyclic convolution (no NTT), so it must not
be used to claim lattice security levels.  What it *does* validate:

  1. zero byte overhead:    |sigma_normal| == |sigma_anamorphic|
  2. exact-ish distribution: decoy responses stay uniform under embedding
  3. attribution:           holder of dk recovers (payload, signer index)
  4. robustness:            a normal signature extracts to bottom
  5. negative control:      naive LSB embedding is statistically detectable

The embedding maps a payload into the response box B = [-H, H)^{l*d} with a
keyed Feistel permutation (FPE) over [0, |B|).  Because |B| = 2^(t*l*d) is a
power of two, the permutation is exact and constant-round: no cycle walking
(which would leak through its data-dependent iteration count).

Parameter note: the signer's z_pi is uniform over a box shrunk by M = d*eta
on each side (the |c*s| bound).  We pick H >> M so the boundary shell has
total variation ~ l*d*M/H ~ 1e-4, i.e. unobservable; a real implementation
should either accept the same tiny statistical distance (as the base
schemes do) or sample decoys from the same shrunk box.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

# --------------------------------------------------------------------------
# parameters (small on purpose; see SCOPE above)
# --------------------------------------------------------------------------
Q = 8380417          # 2^23 - 2^13 + 1, the Dilithium prime
D = 256              # ring degree
K = 2                # rows of A
L = 2                # cols of A  (= number of secret polynomials)
ETA = 1              # secret coefficient bound: s_i in {-1,0,1}
T = 29               # bits per response coefficient  -> box [-2^28, 2^28)
H = 1 << (T - 1)
ND = L * D           # coefficients per response
L_BITS = T * ND      # log2 |B|  = 14848
L1 = L_BITS // 2
L2 = L_BITS - L1
MASK2 = (1 << L2) - 1
BYTES_PER_RESP = L_BITS // 8
M = D * ETA          # |c*s| bound
FEISTEL_ROUNDS = 16

PAYLOAD_BYTES = 32
MAC_BYTES = 16
MU_BITS = (PAYLOAD_BYTES + MAC_BYTES) * 8
assert MU_BITS < L_BITS


# --------------------------------------------------------------------------
# ring arithmetic  R_q = Z_q[x]/(x^d+1)
# --------------------------------------------------------------------------
def poly_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    a = np.asarray(a)
    b = np.asarray(b)
    assert a.shape == (D,) and b.shape == (D,), f"poly_mul expects (D,): got {a.shape}, {b.shape}"
    c = np.convolve(a.astype(np.int64), b.astype(np.int64))
    res = c[:D].copy()
    res[: len(c) - D] -= c[D:]
    return res % Q


def mat_vec(A: list[list[np.ndarray]], v: list[np.ndarray]) -> list[np.ndarray]:
    out = []
    for i in range(K):
        acc = np.zeros(D, dtype=np.int64)
        for j in range(L):
            acc += poly_mul(A[i][j], v[j])
        out.append(acc % Q)
    return out


def scale_poly(c: np.ndarray, t: np.ndarray) -> list[np.ndarray]:
    """c is a challenge; returns [c*t] for a single polynomial, list-wrapped."""
    return [poly_mul(c, t)]


def vec_sub(a: list[np.ndarray], b: list[np.ndarray]) -> list[np.ndarray]:
    return [(x - y) % Q for x, y in zip(a, b)]


# --------------------------------------------------------------------------
# hashing / challenge
# --------------------------------------------------------------------------
def challenge(digest: bytes) -> np.ndarray:
    bits = np.unpackbits(np.frombuffer(digest, dtype=np.uint8))[:D]
    return bits.astype(np.int64)


def h_chain(m: bytes, j: int, w: list[np.ndarray], ct: bytes, domain: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(domain)
    h.update(len(m).to_bytes(4, "big"))
    h.update(m)
    h.update(j.to_bytes(4, "big"))
    for poly in w:
        h.update(np.ascontiguousarray(poly, dtype="<i8").tobytes())
    h.update(ct)
    return h.digest()


# --------------------------------------------------------------------------
# box <-> integer <-> Feistel permutation
# --------------------------------------------------------------------------
def sample_box(rng: np.random.Generator) -> np.ndarray:
    return rng.integers(-H, H, size=ND, dtype=np.int64)


def in_box(z: np.ndarray) -> bool:
    return bool(np.all(z >= -H) and np.all(z < H))


def box_to_int(z: np.ndarray) -> int:
    x = 0
    mask = (1 << T) - 1
    for c in z[::-1]:
        x = (x << T) | (int(c) + H)
    return x


def int_to_box(x: int) -> np.ndarray:
    out = np.empty(ND, dtype=np.int64)
    mask = (1 << T) - 1
    for i in range(ND):          # coefficient 0 is the LOW digit
        out[i] = (x & mask) - H
        x >>= T
    return out


def _round_fn(dk: bytes, rnd: int, half: int) -> int:
    h = hashlib.shake_256(dk + rnd.to_bytes(2, "big") + half.to_bytes(L2 // 8, "big"))
    return int.from_bytes(h.digest(L1 // 8), "big")


def feistel_perm(dk: bytes, x: int) -> int:
    l = x >> L2
    r = x & MASK2
    for i in range(FEISTEL_ROUNDS):
        l, r = r, l ^ _round_fn(dk, i, r)
    return (l << L2) | r


def feistel_inv(dk: bytes, y: int) -> int:
    l = y >> L2
    r = y & MASK2
    for i in reversed(range(FEISTEL_ROUNDS)):
        l, r = r ^ _round_fn(dk, i, l), l
    return (l << L2) | r


# --------------------------------------------------------------------------
# keys, payload encoding
# --------------------------------------------------------------------------
@dataclass
class Keys:
    A: list[list[np.ndarray]] = field(default_factory=list)
    sks: list[list[np.ndarray]] = field(default_factory=list)
    pks: list[list[np.ndarray]] = field(default_factory=list)


def keygen(rng: np.random.Generator, n: int = 4) -> Keys:
    A = [[rng.integers(0, Q, size=D, dtype=np.int64) for _ in range(L)] for _ in range(K)]
    sks, pks = [], []
    for _ in range(n):
        s = [rng.integers(-ETA, ETA + 1, size=D, dtype=np.int64) for _ in range(L)]
        sks.append(s)
        pks.append(mat_vec(A, s))
    return Keys(A=A, sks=sks, pks=pks)


def encode_payload(dk_mac: bytes, payload: bytes) -> int:
    mac = hmac.new(dk_mac, payload, hashlib.sha256).digest()[:MAC_BYTES]
    return (int.from_bytes(payload, "big") << (MAC_BYTES * 8)) | int.from_bytes(mac, "big")


def decode_payload(dk_mac: bytes, mu: int) -> Optional[bytes]:
    payload = (mu >> (MAC_BYTES * 8)).to_bytes(PAYLOAD_BYTES, "big")
    mac = (mu & ((1 << (MAC_BYTES * 8)) - 1)).to_bytes(MAC_BYTES, "big")
    good = hmac.new(dk_mac, payload, hashlib.sha256).digest()[:MAC_BYTES]
    return payload if hmac.compare_digest(good, mac) else None


def fpe_encode(dk: bytes, rng: np.random.Generator, mu: int) -> np.ndarray:
    nbits = L_BITS - MU_BITS
    nbytes = (nbits + 7) // 8
    r = int.from_bytes(rng.bytes(nbytes), "big") & ((1 << nbits) - 1)
    return int_to_box(feistel_perm(dk, (r << MU_BITS) | mu))


def lsb_encode(z: np.ndarray, mu: int) -> np.ndarray:
    """Deliberately naive control: overwrite the low bit of the first MU_BITS coeffs."""
    out = z.copy()
    for i in range(MU_BITS):
        out[i] = (out[i] & ~1) | ((mu >> i) & 1)
    return out


# --------------------------------------------------------------------------
# signature
# --------------------------------------------------------------------------
@dataclass
class Sig:
    c1: bytes
    zs: list[np.ndarray]

    def size(self) -> int:
        return len(self.c1) + sum(BYTES_PER_RESP for _ in self.zs)


def sign(
    keys: Keys,
    pi: int,
    m: bytes,
    *,
    embed: Optional[str] = None,   # None | "fpe" | "lsb"
    mu: int = 0,
    dk: bytes = b"",
    rng: Optional[np.random.Generator] = None,
    domain: bytes = b"VEIL/v1",
) -> Optional[Sig]:
    rng = rng or np.random.default_rng()
    n = len(keys.pks)
    A, pks, s_pi = keys.A, keys.pks, keys.sks[pi]

    # 1. signer commits first: w_pi = A*y
    Hm = H - M
    y = [rng.integers(-Hm, Hm, size=D, dtype=np.int64) for _ in range(L)]
    w_pi = mat_vec(A, y)
    c_next = h_chain(m, pi, w_pi, b"", domain)
    c_init = c_next

    # 2. walk the ring, filling every other branch with a random response
    zs: list[Optional[np.ndarray]] = [None] * n
    c1: Optional[bytes] = None
    for step in range(1, n):
        j = (pi + step) % n
        z = sample_box(rng)
        if embed == "fpe":
            z = fpe_encode(dk, rng, mu)
        elif embed == "lsb":
            z = lsb_encode(z, mu)
        zs[j] = z
        cv = challenge(c_next)
        polys = [z[i * D:(i + 1) * D] for i in range(L)]
        Az = mat_vec(A, polys)
        w = [(Az[i] - poly_mul(cv, pks[j][i])) % Q for i in range(K)]
        c_after = h_chain(m, j, w, b"", domain)
        if j == n - 1:
            c1 = c_after
        c_next = c_after

    # 3. close the ring on the signer's own branch
    #    z_pi = y + c*s is an INTEGER vector (not reduced mod Q); only A*z is
    #    computed mod Q.  |c*s| <= M, and poly_mul returns residues, so we
    #    centre them back to the true signed value.
    c_pi = challenge(c_next)  # c_next is now c_pi
    parts = []
    for i in range(L):
        cs = poly_mul(c_pi, s_pi[i]).astype(np.int64)
        cs = np.where(cs > Q // 2, cs - Q, cs)
        parts.append(y[i] + cs)
    z_pi = np.concatenate(parts)
    if not in_box(z_pi):
        return None  # reject and let the caller retry
    zs[pi] = z_pi
    if c1 is None:  # pi == n
        c1 = c_init
    return Sig(c1=c1, zs=zs)  # type: ignore[arg-type]


def verify(keys: Keys, m: bytes, sig: Sig, domain: bytes = b"VEIL/v1") -> bool:
    A, pks = keys.A, keys.pks
    n = len(pks)
    for z in sig.zs:
        if not in_box(z):
            return False
    c_digest = sig.c1
    for j in range(n):
        cv = challenge(c_digest)
        z = sig.zs[j]
        polys = [z[i * D:(i + 1) * D] for i in range(L)]
        Az = mat_vec(A, polys)
        w = [(Az[i] - poly_mul(cv, pks[j][i])) % Q for i in range(K)]
        c_digest = h_chain(m, j, w, b"", domain)
    return c_digest == sig.c1


def extract_attr(sig: Sig, dk: bytes, dk_mac: bytes) -> tuple[Optional[bytes], Optional[int]]:
    """Return (payload, signer index) for an attributable-mode signature."""
    hits: dict[bytes, list[int]] = {}
    for j, z in enumerate(sig.zs):
        x = feistel_inv(dk, box_to_int(z))
        payload = decode_payload(dk_mac, x & ((1 << MU_BITS) - 1))
        if payload is not None:
            hits.setdefault(payload, []).append(j)
    if not hits:
        return None, None
    payload = max(hits, key=lambda p: len(hits[p]))
    decoded = set(hits[payload])
    missing = [j for j in range(len(sig.zs)) if j not in decoded]
    return payload, (missing[0] if len(missing) == 1 else None)


def extract_lsb(sig: Sig, dk_mac: bytes) -> tuple[Optional[bytes], Optional[int]]:
    hits: dict[bytes, list[int]] = {}
    for j, z in enumerate(sig.zs):
        mu = 0
        for i in range(MU_BITS):
            mu |= (int(z[i]) & 1) << i
        payload = decode_payload(dk_mac, mu)
        if payload is not None:
            hits.setdefault(payload, []).append(j)
    if not hits:
        return None, None
    payload = max(hits, key=lambda p: len(hits[p]))
    decoded = set(hits[payload])
    missing = [j for j in range(len(sig.zs)) if j not in decoded]
    return payload, (missing[0] if len(missing) == 1 else None)


# --------------------------------------------------------------------------
# serialization (fixed layout, identical for both modes)
# --------------------------------------------------------------------------
def serialize(sig: Sig) -> bytes:
    out = bytearray(sig.c1)
    for z in sig.zs:
        out += box_to_int(z).to_bytes(BYTES_PER_RESP, "big")
    return bytes(out)


def deserialize(blob: bytes, n: int) -> Sig:
    c1 = blob[:32]
    zs = []
    off = 32
    for _ in range(n):
        zs.append(int_to_box(int.from_bytes(blob[off:off + BYTES_PER_RESP], "big")))
        off += BYTES_PER_RESP
    return Sig(c1=c1, zs=zs)
