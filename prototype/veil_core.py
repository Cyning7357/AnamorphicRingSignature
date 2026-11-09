"""VEIL core (v2): parameterised decoy/AOS lattice ring signature.

Compared with veil_proto.py (v1, kept only for reference):
  * negacyclic NTT over Z_q[x]/(x^d+1), vectorised with numpy
  * sparse binary challenges (tau ones), as in DualRing-LB / Raptor
  * parameterised d, k, l, tau, box width t
  * modes: normal | fpe (B) | lsb (negative control) | salt (B')

SCOPE: still a mechanics prototype.  No Gaussian sampling, no security
parameters, no claim of lattice hardness.  The NTT is exercised for
correctness and speed; it is what a real implementation would use.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

Q = 8380417  # 2^23 - 2^13 + 1  (q - 1 = 2^13 * 1023)


# --------------------------------------------------------------------------
# parameters + precomputation
# --------------------------------------------------------------------------
@dataclass
class Params:
    d: int = 256
    k: int = 4
    l: int = 4
    eta: int = 1
    tau: int = 39
    t: int = 19
    n: int = 4
    q: int = Q
    q_rounds: int = 16
    payload_bytes: int = 32
    mac_bytes: int = 16

    # derived
    H: int = field(init=False)
    ND: int = field(init=False)
    L_BITS: int = field(init=False)
    L1: int = field(init=False)
    L2: int = field(init=False)
    RESP_BYTES: int = field(init=False)
    MU_BITS: int = field(init=False)
    M: int = field(init=False)
    inv_d: int = field(init=False)
    PSI: np.ndarray = field(init=False)
    PSI_INV: np.ndarray = field(init=False)
    BITREV: np.ndarray = field(init=False)
    roots: dict = field(init=False)
    inv_roots: dict = field(init=False)

    def __post_init__(self):
        self.H = 1 << (self.t - 1)
        self.ND = self.l * self.d
        self.L_BITS = self.t * self.ND
        self.L1 = self.L_BITS // 2
        self.L2 = self.L_BITS - self.L1
        self.RESP_BYTES = self.L_BITS // 8
        self.MU_BITS = (self.payload_bytes + self.mac_bytes) * 8
        self.M = self.tau * self.eta
        self.inv_d = pow(self.d, self.q - 2, self.q)

        # primitive 2d-th root of unity
        two_d = 2 * self.d
        assert (self.q - 1) % two_d == 0
        psi = None
        for g in range(2, 1000):
            cand = pow(g, (self.q - 1) // two_d, self.q)
            if pow(cand, self.d, self.q) == self.q - 1:
                psi = cand
                break
        assert psi is not None, "no 2d-th root found"
        self.PSI = np.array([pow(psi, i, self.q) for i in range(self.d)], dtype=np.int64)
        psi_inv = pow(psi, self.q - 2, self.q)
        self.PSI_INV = np.array([pow(psi_inv, i, self.q) for i in range(self.d)], dtype=np.int64)

        # bit reversal for length d
        bits = self.d.bit_length() - 1
        idx = np.arange(self.d, dtype=np.int64)
        rev = np.zeros(self.d, dtype=np.int64)
        for i in range(bits):
            rev = (rev << 1) | ((idx >> i) & 1)
        self.BITREV = rev

        # stage roots: for block length L, w = omega^(d/L), omega = psi^2
        omega = psi * psi % self.q
        omega_inv = pow(omega, self.q - 2, self.q)
        self.roots, self.inv_roots = {}, {}
        length = 2
        while length <= self.d:
            half = length // 2
            w = pow(omega, self.d // length, self.q)
            wi = pow(omega_inv, self.d // length, self.q)
            self.roots[length] = np.array([pow(w, j, self.q) for j in range(half)], dtype=np.int64)
            self.inv_roots[length] = np.array([pow(wi, j, self.q) for j in range(half)], dtype=np.int64)
            length *= 2


# --------------------------------------------------------------------------
# NTT over Z_q[x]/(x^d+1)
# --------------------------------------------------------------------------
def _transform(p: Params, a: np.ndarray, roots: dict) -> np.ndarray:
    b = a[p.BITREV].astype(np.int64).copy()
    length = 2
    while length <= p.d:
        half = length // 2
        blk = b.reshape(-1, length)
        u = blk[:, :half].copy()
        t = blk[:, half:] * roots[length] % p.q
        hi = u + t
        hi -= p.q * (hi >= p.q)
        lo = u - t
        lo += p.q * (lo < 0)
        blk[:, :half] = hi
        blk[:, half:] = lo
        b = blk.reshape(-1)
        length *= 2
    return b


def ntt(p: Params, a: np.ndarray) -> np.ndarray:
    return _transform(p, a * p.PSI % p.q, p.roots)


def intt(p: Params, a: np.ndarray) -> np.ndarray:
    """Inverse of ntt: forward runs stages 2,4,...,d, so the inverse runs
    d,...,2 with inverse roots, then the bit reversal and the 1/d scale."""
    b = a.astype(np.int64).copy()
    length = p.d
    while length >= 2:
        half = length // 2
        blk = b.reshape(-1, length)
        u = blk[:, :half].copy()
        v = blk[:, half:].copy()
        hi = u + v
        hi -= p.q * (hi >= p.q)
        blk[:, :half] = hi
        blk[:, half:] = ((u - v) * p.inv_roots[length]) % p.q
        b = blk.reshape(-1)
        length //= 2
    return b[p.BITREV] * p.inv_d % p.q * p.PSI_INV % p.q


def poly_mul(p: Params, a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return intt(p, ntt(p, a) * ntt(p, b) % p.q)


def schoolbook_mul(p: Params, a: np.ndarray, b: np.ndarray) -> np.ndarray:
    c = np.convolve(a.astype(np.int64), b.astype(np.int64))
    res = c[: p.d].copy()
    res[: p.d - 1] -= c[p.d:]
    return res % p.q


def sparse_mul(p: Params, idx: np.ndarray, a: np.ndarray) -> np.ndarray:
    """Multiply by the sparse polynomial sum_{i in idx} x^i, modulo x^d+1."""
    out = np.zeros(p.d, dtype=np.int64)
    for i in idx:
        i = int(i)
        if i == 0:
            out += a
        else:
            out[i:] += a[: p.d - i]
            out[:i] -= a[p.d - i:]
    return out % p.q


def _ntt_batch(p: Params, A: np.ndarray) -> np.ndarray:
    """NTT applied to a (batch, d) array in one go."""
    b = (A * p.PSI % p.q)[:, p.BITREV].astype(np.int64).copy()
    length = 2
    while length <= p.d:
        half = length // 2
        blk = b.reshape(b.shape[0], -1, length)
        u = blk[:, :, :half].copy()
        t = blk[:, :, half:] * p.roots[length] % p.q
        hi = u + t
        hi -= p.q * (hi >= p.q)
        lo = u - t
        lo += p.q * (lo < 0)
        blk[:, :, :half] = hi
        blk[:, :, half:] = lo
        b = blk.reshape(b.shape[0], -1)
        length *= 2
    return b


def _intt_batch(p: Params, A: np.ndarray) -> np.ndarray:
    b = A.astype(np.int64).copy()
    length = p.d
    while length >= 2:
        half = length // 2
        blk = b.reshape(b.shape[0], -1, length)
        u = blk[:, :, :half].copy()
        v = blk[:, :, half:].copy()
        hi = u + v
        hi -= p.q * (hi >= p.q)
        blk[:, :, :half] = hi
        blk[:, :, half:] = ((u - v) * p.inv_roots[length]) % p.q
        b = blk.reshape(b.shape[0], -1)
        length //= 2
    return b[:, p.BITREV] * p.inv_d % p.q * p.PSI_INV % p.q


def mat_vec(p: Params, A_hat: list[list[np.ndarray]], z: list[np.ndarray]) -> list[np.ndarray]:
    zh = _ntt_batch(p, np.stack(z, axis=0))
    rows = []
    for i in range(p.k):
        acc = np.zeros(p.d, dtype=np.int64)
        for j in range(p.l):
            acc = (acc + A_hat[i][j] * zh[j]) % p.q
        rows.append(acc)
    return list(_intt_batch(p, np.stack(rows, axis=0)))


# --------------------------------------------------------------------------
# hashing, challenge, keys
# --------------------------------------------------------------------------
def h_chain(m: bytes, j: int, w: list[np.ndarray], extra: bytes, domain: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(domain)
    h.update(len(m).to_bytes(4, "big"))
    h.update(m)
    h.update(j.to_bytes(4, "big"))
    for poly in w:
        h.update(np.ascontiguousarray(poly, dtype="<i8").tobytes())
    h.update(extra)
    return h.digest()


def sparse_challenge(p: Params, digest: bytes) -> np.ndarray:
    seen: set[int] = set()
    ctr = 0
    while len(seen) < p.tau:
        block = hashlib.shake_256(digest + ctr.to_bytes(2, "big")).digest(64)
        for i in range(0, 64, 2):
            v = int.from_bytes(block[i:i + 2], "big") % p.d
            seen.add(v)
            if len(seen) == p.tau:
                break
        ctr += 1
    return np.array(sorted(seen), dtype=np.int64)


@dataclass
class Keys:
    p: Params
    A_hat: list[list[np.ndarray]]
    sks: list[list[np.ndarray]]
    pks: list[list[np.ndarray]]      # t_j in NTT domain


def keygen(p: Params, rng: np.random.Generator) -> Keys:
    A_hat = [[rng.integers(0, p.q, size=p.d, dtype=np.int64) for _ in range(p.l)]
             for _ in range(p.k)]
    sks, pks = [], []
    for _ in range(p.n):
        s = [rng.integers(-p.eta, p.eta + 1, size=p.d, dtype=np.int64) for _ in range(p.l)]
        sks.append(s)
        # t_hat[i] = sum_j A_hat[i][j] * NTT(s_j); keep t in the NORMAL domain
        # because c*t is computed with a sparse multiplication.
        s_hat = [ntt(p, poly) for poly in s]
        t_hat = []
        for i in range(p.k):
            acc = np.zeros(p.d, dtype=np.int64)
            for j in range(p.l):
                acc = (acc + A_hat[i][j] * s_hat[j]) % p.q
            t_hat.append(acc)
        pks.append([intt(p, acc) for acc in t_hat])
    return Keys(p=p, A_hat=A_hat, sks=sks, pks=pks)


# --------------------------------------------------------------------------
# box <-> integer <-> Feistel
# --------------------------------------------------------------------------
def sample_box(p: Params, rng: np.random.Generator) -> np.ndarray:
    return rng.integers(-p.H, p.H, size=p.ND, dtype=np.int64)


def in_box(p: Params, z: np.ndarray) -> bool:
    return bool(np.all(z >= -p.H) and np.all(z < p.H))


def box_to_int(p: Params, z: np.ndarray) -> int:
    x = 0
    for c in z[::-1]:
        x = (x << p.t) | (int(c) + p.H)
    return x


def int_to_box(p: Params, x: int) -> np.ndarray:
    """Vectorised: unpack the integer once and slice it into t-bit digits."""
    nbits = p.ND * p.t
    raw = x.to_bytes((nbits + 7) // 8, "little")
    bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8), bitorder="little")[:nbits]
    powers = (1 << np.arange(p.t, dtype=np.int64))
    digits = bits.reshape(p.ND, p.t).astype(np.int64) @ powers
    return digits - p.H


def _f(p: Params, dk: bytes, rnd: int, half: int) -> int:
    h = hashlib.shake_256(dk + rnd.to_bytes(2, "big") + half.to_bytes(p.L2 // 8, "big"))
    return int.from_bytes(h.digest(p.L1 // 8), "big")


def feistel_perm(p: Params, dk: bytes, x: int) -> int:
    mask = (1 << p.L2) - 1
    l, r = x >> p.L2, x & mask
    for i in range(p.q_rounds):
        l, r = r, l ^ _f(p, dk, i, r)
    return (l << p.L2) | r


def feistel_inv(p: Params, dk: bytes, y: int) -> int:
    mask = (1 << p.L2) - 1
    l, r = y >> p.L2, y & mask
    for i in reversed(range(p.q_rounds)):
        l, r = r ^ _f(p, dk, i, l), l
    return (l << p.L2) | r


# --------------------------------------------------------------------------
# payload encoding
# --------------------------------------------------------------------------
def encode_mu(p: Params, dk_mac: bytes, payload: bytes) -> int:
    mac = hmac.new(dk_mac, payload, hashlib.sha256).digest()[: p.mac_bytes]
    return (int.from_bytes(payload, "big") << (p.mac_bytes * 8)) | int.from_bytes(mac, "big")


def decode_mu(p: Params, dk_mac: bytes, mu: int) -> Optional[bytes]:
    payload = (mu >> (p.mac_bytes * 8)).to_bytes(p.payload_bytes, "big")
    mac = (mu & ((1 << (p.mac_bytes * 8)) - 1)).to_bytes(p.mac_bytes, "big")
    good = hmac.new(dk_mac, payload, hashlib.sha256).digest()[: p.mac_bytes]
    return payload if hmac.compare_digest(good, mac) else None


# --------------------------------------------------------------------------
# signature
# --------------------------------------------------------------------------
@dataclass
class Sig:
    c1: bytes
    zs: list[np.ndarray]
    epoch: int = 0
    tag: Optional[bytes] = None
    ae_ct: Optional[bytes] = None
    salt: Optional[bytes] = None
    nonce: Optional[bytes] = None

    def size(self, p: Params) -> int:
        base = len(self.c1) + sum(p.RESP_BYTES for _ in self.zs)
        if self.tag is not None:
            base += len(self.tag)
        if self.ae_ct is not None:
            base += len(self.ae_ct)
        if self.salt is not None:
            base += len(self.salt) + len(self.nonce or b"")
        return base


def link_tag(p: Params, sk: list[np.ndarray], epoch: int) -> bytes:
    """Public linking tag: same agent + same epoch -> same tag."""
    h = hashlib.sha256(b"VEIL/link")
    for poly in sk:
        h.update(np.ascontiguousarray(poly, dtype="<i8").tobytes())
    h.update(epoch.to_bytes(8, "big"))
    return h.digest()


def merkle_root(pks: list[list[np.ndarray]]) -> bytes:
    """Commitment to the epoch's member set."""
    leaves = []
    for pk in pks:
        h = hashlib.sha256(b"VEIL/leaf")
        for poly in pk:
            h.update(np.ascontiguousarray(poly, dtype="<i8").tobytes())
        leaves.append(h.digest())
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [hashlib.sha256(b"VEIL/node" + leaves[i] + leaves[i + 1]).digest()
                  for i in range(0, len(leaves), 2)]
    return leaves[0]


AE_CT_BYTES = 1088  # ML-KEM-768 ciphertext size; SIMULATED, see module docstring


def ae_encrypt(p: Params, td: bytes, mu: int, rng: np.random.Generator) -> bytes:
    """STRUCTURAL A-mode carrier.

    The 1088-byte blob stands in for a KEM ciphertext.  The payload is masked
    with a PRF keyed by the extraction trapdoor `td`, so:
      * anyone holding td recovers mu;
      * anyone holding only the receiver's ordinary key sees random bytes.
    This gives the right size, interface and hash-binding behaviour.  It is
    NOT an instantiation of public-key anamorphic AE: no LWE encryption, and
    no anamorphic security claim.  See the README.
    """
    kem = rng.bytes(AE_CT_BYTES)
    pad = hashlib.shake_256(td + b"/ae" + kem).digest(p.payload_bytes + p.mac_bytes)
    mu_b = mu.to_bytes(p.payload_bytes + p.mac_bytes, "big")
    return kem + bytes(a ^ b for a, b in zip(pad, mu_b))


def ae_decrypt(p: Params, td: bytes, dk_mac: bytes, ct: bytes) -> Optional[bytes]:
    kem, v = ct[:AE_CT_BYTES], ct[AE_CT_BYTES:]
    pad = hashlib.shake_256(td + b"/ae" + kem).digest(p.payload_bytes + p.mac_bytes)
    mu = int.from_bytes(bytes(a ^ b for a, b in zip(v, pad)), "big")
    return decode_mu(p, dk_mac, mu)


def _header(epoch: int, root: bytes, tag: Optional[bytes], ae_ct: Optional[bytes],
            salt: Optional[bytes], nonce: Optional[bytes]) -> bytes:
    out = bytearray(epoch.to_bytes(8, "big"))
    out += root
    if tag is not None:
        out += tag
    if ae_ct is not None:
        out += ae_ct
    if salt is not None:
        out += salt + (nonce or b"")
    return bytes(out)


def sign(keys: Keys, pi: int, m: bytes, *,
         embed: Optional[str] = None,     # None | "fpe" | "lsb" | "salt" | "ae"
         mu: int = 0, dk: bytes = b"", dk_mac: bytes = b"",
         epoch: int = 0, root: bytes = b"", link: bool = False,
         rng: Optional[np.random.Generator] = None,
         domain: bytes = b"VEIL/v3") -> Optional[Sig]:
    p = keys.p
    rng = rng or np.random.default_rng()
    n = p.n
    s_pi = keys.sks[pi]

    salt = nonce = None
    ae_ct = None
    if embed == "salt":
        nonce = rng.bytes(16)
        pad = hashlib.shake_256(dk + nonce).digest(p.payload_bytes + p.mac_bytes)
        mu_bytes = mu.to_bytes(p.payload_bytes + p.mac_bytes, "big")
        salt = bytes(a ^ b for a, b in zip(pad, mu_bytes))
    elif embed == "ae":
        ae_ct = ae_encrypt(p, dk, mu, rng)
    tag = link_tag(p, s_pi, epoch) if link else None
    extra = _header(epoch, root, tag, ae_ct, salt, nonce)

    # 1. signer commits: w_pi = A*y
    Hm = p.H - p.M
    y = [rng.integers(-Hm, Hm, size=p.d, dtype=np.int64) for _ in range(p.l)]
    w_pi = mat_vec(p, keys.A_hat, y)
    c_next = h_chain(m, pi, w_pi, extra, domain)
    c_init = c_next

    zs: list[Optional[np.ndarray]] = [None] * n
    c1: Optional[bytes] = None
    for step in range(1, n):
        j = (pi + step) % n
        if embed == "fpe":
            nbits = p.L_BITS - p.MU_BITS
            r = int.from_bytes(rng.bytes((nbits + 7) // 8), "big") & ((1 << nbits) - 1)
            z = int_to_box(p, feistel_perm(p, dk, (r << p.MU_BITS) | mu))
        else:
            z = sample_box(p, rng)
            if embed == "lsb":
                z = z.copy()
                for i in range(p.MU_BITS):
                    z[i] = (z[i] & ~1) | ((mu >> i) & 1)
        zs[j] = z
        cvec = sparse_challenge(p, c_next)
        Az = mat_vec(p, keys.A_hat, [z[i * p.d:(i + 1) * p.d] for i in range(p.l)])
        ct = [sparse_mul(p, cvec, keys.pks[j][i]) for i in range(p.k)]
        w = [(Az[i] - ct[i]) % p.q for i in range(p.k)]
        c_after = h_chain(m, j, w, extra, domain)
        if j == n - 1:
            c1 = c_after
        c_next = c_after

    # 2. close on the signer's branch: z_pi = y + c_pi*s (integers)
    c_pi = sparse_challenge(p, c_next)
    parts = []
    for i in range(p.l):
        cs = sparse_mul(p, c_pi, s_pi[i])
        cs = np.where(cs > p.q // 2, cs - p.q, cs)
        parts.append(y[i] + cs)
    z_pi = np.concatenate(parts)
    if not in_box(p, z_pi):
        return None
    zs[pi] = z_pi
    if c1 is None:
        c1 = c_init
    return Sig(c1=c1, zs=zs, epoch=epoch, tag=tag, ae_ct=ae_ct,
               salt=salt, nonce=nonce)  # type: ignore[arg-type]


def verify(keys: Keys, m: bytes, sig: Sig, root: bytes = b"",
           epoch: Optional[int] = None, domain: bytes = b"VEIL/v3") -> bool:
    p = keys.p
    extra = _header(sig.epoch if epoch is None else epoch, root,
                    sig.tag, sig.ae_ct, sig.salt, sig.nonce)
    for z in sig.zs:
        if not in_box(p, z):
            return False
    c_digest = sig.c1
    for j in range(p.n):
        cvec = sparse_challenge(p, c_digest)
        z = sig.zs[j]
        Az = mat_vec(p, keys.A_hat, [z[i * p.d:(i + 1) * p.d] for i in range(p.l)])
        ct = [sparse_mul(p, cvec, keys.pks[j][i]) for i in range(p.k)]
        w = [(Az[i] - ct[i]) % p.q for i in range(p.k)]
        c_digest = h_chain(m, j, w, extra, domain)
    return c_digest == sig.c1


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------
def extract_fpe(keys: Keys, sig: Sig, dk: bytes, dk_mac: bytes):
    p = keys.p
    hits: dict[bytes, list[int]] = {}
    for j, z in enumerate(sig.zs):
        x = feistel_inv(p, dk, box_to_int(p, z))
        payload = decode_mu(p, dk_mac, x & ((1 << p.MU_BITS) - 1))
        if payload is not None:
            hits.setdefault(payload, []).append(j)
    if not hits:
        return None, None
    payload = max(hits, key=lambda k: len(hits[k]))
    decoded = set(hits[payload])
    missing = [j for j in range(len(sig.zs)) if j not in decoded]
    return payload, (missing[0] if len(missing) == 1 else None)


def extract_salt(keys: Keys, sig: Sig, dk: bytes, dk_mac: bytes):
    p = keys.p
    if sig.salt is None or sig.nonce is None:
        return None
    pad = hashlib.shake_256(dk + sig.nonce).digest(p.payload_bytes + p.mac_bytes)
    mu_bytes = bytes(a ^ b for a, b in zip(sig.salt, pad))
    mu = int.from_bytes(mu_bytes, "big")
    return decode_mu(p, dk_mac, mu)


def extract_lsb(keys: Keys, sig: Sig, dk_mac: bytes):
    p = keys.p
    hits: dict[bytes, list[int]] = {}
    for j, z in enumerate(sig.zs):
        mu = 0
        for i in range(p.MU_BITS):
            mu |= (int(z[i]) & 1) << i
        payload = decode_mu(p, dk_mac, mu)
        if payload is not None:
            hits.setdefault(payload, []).append(j)
    if not hits:
        return None, None
    payload = max(hits, key=lambda k: len(hits[k]))
    decoded = set(hits[payload])
    missing = [j for j in range(len(sig.zs)) if j not in decoded]
    return payload, (missing[0] if len(missing) == 1 else None)


# --------------------------------------------------------------------------
# serialization
# --------------------------------------------------------------------------
def serialize(keys: Keys, sig: Sig) -> bytes:
    p = keys.p
    out = bytearray(sig.c1)
    for z in sig.zs:
        out += box_to_int(p, z).to_bytes(p.RESP_BYTES, "big")
    if sig.tag is not None:
        out += sig.tag
    if sig.ae_ct is not None:
        out += sig.ae_ct
    if sig.salt is not None:
        out += sig.salt + (sig.nonce or b"")
    return bytes(out)


def link(sig_a: Sig, sig_b: Sig) -> bool:
    return sig_a.tag is not None and sig_a.tag == sig_b.tag


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import time
    rng = np.random.default_rng(0)
    p = Params()
    a = rng.integers(0, p.q, size=p.d, dtype=np.int64)
    b = rng.integers(0, p.q, size=p.d, dtype=np.int64)
    assert np.array_equal(poly_mul(p, a, b), schoolbook_mul(p, a, b)), "NTT mul mismatch"
    assert np.array_equal(intt(p, ntt(p, a)), a), "NTT roundtrip mismatch"
    idx = np.array(sorted(rng.choice(p.d, p.tau, replace=False)))
    assert np.array_equal(sparse_mul(p, idx, b), schoolbook_mul(p, np.bincount(idx, minlength=p.d) % p.q, b))

    t0 = time.perf_counter()
    for _ in range(2000):
        poly_mul(p, a, b)
    t_ntt = (time.perf_counter() - t0) / 2000 * 1e6
    t0 = time.perf_counter()
    for _ in range(2000):
        schoolbook_mul(p, a, b)
    t_sch = (time.perf_counter() - t0) / 2000 * 1e6
    print(f"NTT self-test OK; mul: NTT {t_ntt:.1f} us vs schoolbook {t_sch:.1f} us (d={p.d})")

    keys = keygen(p, rng)
    dk = hashlib.sha256(b"dk").digest()
    dk_mac = hashlib.sha256(b"mac").digest()
    mu = encode_mu(p, dk_mac, b"hello".ljust(p.payload_bytes, b"\x00"))
    root = merkle_root(keys.pks)
    for mode in (None, "fpe", "salt", "ae"):
        s = sign(keys, 1, b"m", embed=mode, mu=mu, dk=dk, rng=rng, epoch=1, root=root)
        assert s is not None and verify(keys, b"m", s, root=root), f"verify failed for {mode}"
        print(f"mode={mode}: ok, size={s.size(p)}")
    s = sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=1, root=root)
    print("fpe extract:", extract_fpe(keys, s, dk, dk_mac))
    s = sign(keys, 1, b"m", embed="salt", mu=mu, dk=dk, rng=rng, epoch=1, root=root)
    print("salt extract:", extract_salt(keys, s, dk, dk_mac))
    s = sign(keys, 1, b"m", embed="ae", mu=mu, dk=dk, rng=rng, epoch=1, root=root)
    print("ae extract:", ae_decrypt(p, dk, dk_mac, s.ae_ct))

    # epoch binding: a signature for the old root must not verify against a new one
    assert verify(keys, b"m", s, root=root)
    assert not verify(keys, b"m", s, root=b"\x00" * 32)
    # linkability: same agent + epoch links; different agent or epoch does not
    a1 = sign(keys, 0, b"a", rng=rng, epoch=7, root=root, link=True)
    a2 = sign(keys, 0, b"b", rng=rng, epoch=7, root=root, link=True)
    b1 = sign(keys, 1, b"c", rng=rng, epoch=7, root=root, link=True)
    a3 = sign(keys, 0, b"d", rng=rng, epoch=8, root=root, link=True)
    assert link(a1, a2) and not link(a1, b1) and not link(a1, a3)
    print("link/epoch: ok")
