"""Enrollment / provisioning prototype (paper Section V-D).

Backends, chosen at import time:
  * ``pqcrypto`` (preferred): ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204),
    i.e. the primitives named in the paper.  Install with ``pip install pqcrypto``.
  * fallback (no pqcrypto): X25519 (RFC 7748, checked against the RFC vector)
    as the KEM and a toy 512-bit RSA as the organization signature.  These are
    NOT post-quantum and are only meant to keep the flow runnable.

Protocol:
  enroll : c_i, ss <- KEM.Encaps(pk_X),  dk_i = HKDF(ss, oid || ep || i || pk_i)
  derive : ss <- KEM.Decaps(sk_X, c_i),  same HKDF
  publish: rt = Merkle(leaf_i),          sigma = Sign(sk_org, oid || ep || rt)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any

import numpy as np

import veil_core as vc

# --------------------------------------------------------------------------
# backend selection
# --------------------------------------------------------------------------
try:
    from pqcrypto.kem.ml_kem_768 import keygen as _pq_kem_keygen
    from pqcrypto.kem.ml_kem_768 import encaps as _pq_encaps
    from pqcrypto.kem.ml_kem_768 import decaps as _pq_decaps
    from pqcrypto.sign.ml_dsa_65 import keygen as _pq_sig_keygen
    from pqcrypto.sign.ml_dsa_65 import sign as _pq_sign
    from pqcrypto.sign.ml_dsa_65 import verify as _pq_verify
    from pqcrypto import InvalidSignatureError as _InvalidSig

    BACKEND = "pqcrypto: ML-KEM-768 + ML-DSA-65"
    USE_PQ = True
except ImportError:  # pragma: no cover - fallback path
    BACKEND = "stand-in: X25519 + toy 512-bit RSA"
    USE_PQ = False


# --------------------------------------------------------------------------
# HKDF (RFC 5869)
# --------------------------------------------------------------------------
def hkdf(ikm: bytes, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


# --------------------------------------------------------------------------
# X25519 (RFC 7748) - fallback KEM only
# --------------------------------------------------------------------------
_P = 2**255 - 19
_A24 = 121665
_BASE = (9).to_bytes(32, "little")


def _clamp(k: bytes) -> int:
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(bytes(b), "little")


def x25519(scalar: bytes, u: bytes) -> bytes:
    k = _clamp(scalar)
    u_int = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1 = u_int % _P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) % _P
        x3 = x3 * x3 % _P
        z3 = (da - cb) % _P
        z3 = x1 * z3 * z3 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


# --------------------------------------------------------------------------
# toy RSA - fallback organization signature only
# --------------------------------------------------------------------------
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + int.from_bytes(os.urandom(16), "big") % (n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int = 256) -> int:
    while True:
        cand = int.from_bytes(os.urandom(bits // 8), "big") | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


# --------------------------------------------------------------------------
# uniform interface
# --------------------------------------------------------------------------
@dataclass
class ExtractorKeys:
    pk: Any
    sk: Any


@dataclass
class OrgKeys:
    pk: Any
    sk: Any


def extractor_keygen(rng: np.random.Generator | None = None) -> ExtractorKeys:
    if USE_PQ:
        pk, sk = _pq_kem_keygen()
        return ExtractorKeys(pk=pk, sk=sk)
    sk_b = (rng or np.random.default_rng()).bytes(32)
    return ExtractorKeys(pk=x25519(sk_b, _BASE), sk=sk_b)


def org_keygen(bits: int = 512) -> OrgKeys:
    if USE_PQ:
        pk, sk = _pq_sig_keygen()
        return OrgKeys(pk=pk, sk=sk)
    p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
    while p == q:
        q = _gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    return OrgKeys(pk=(n, e), sk=(n, pow(e, -1, phi)))


def org_sign(keys: OrgKeys, msg: bytes) -> bytes:
    if USE_PQ:
        return _pq_sign(keys.sk, msg)
    n, d = keys.sk
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    return pow(h, d, n).to_bytes(64, "big")


def org_verify(keys: OrgKeys, msg: bytes, sig: bytes) -> bool:
    if USE_PQ:
        try:
            _pq_verify(keys.pk, msg, sig)
            return True
        except _InvalidSig:
            return False
    n, e = keys.pk
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    return pow(int.from_bytes(sig, "big"), e, n) == h


# --------------------------------------------------------------------------
# Merkle tree over the epoch's member entries
# --------------------------------------------------------------------------
def leaf_hash(oid: bytes, ep: int, i: int, pk_i: bytes, c_i: bytes) -> bytes:
    h = hashlib.sha256(b"veil/leaf")
    h.update(len(oid).to_bytes(2, "big"))
    h.update(oid)
    h.update(ep.to_bytes(8, "big"))
    h.update(i.to_bytes(4, "big"))
    h.update(len(pk_i).to_bytes(4, "big"))
    h.update(pk_i)
    h.update(c_i)
    return h.digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(b"veil/node" + level[j] + level[j + 1]).digest()
                 for j in range(0, len(level), 2)]
    return level[0]


def _dk_info(oid: bytes, ep: int, i: int, pk_i: bytes) -> bytes:
    return (b"veil/dk" + len(oid).to_bytes(2, "big") + oid + ep.to_bytes(8, "big")
            + i.to_bytes(4, "big") + pk_i)


# --------------------------------------------------------------------------
# protocol
# --------------------------------------------------------------------------
def enroll(oid: bytes, ep: int, i: int, pk_i: bytes, pk_X: bytes,
           rng: np.random.Generator | None = None) -> tuple[bytes, bytes, bytes]:
    if USE_PQ:
        c_i, ss = _pq_encaps(pk_X)
    else:
        rng = rng or np.random.default_rng()
        esk = rng.bytes(32)
        c_i = x25519(esk, _BASE)
        ss = x25519(esk, pk_X)
    dk_i = hkdf(ss, info=_dk_info(oid, ep, i, pk_i))
    return c_i, dk_i, hkdf(dk_i, info=b"veil/mac")


def derive(sk_X: Any, oid: bytes, ep: int, i: int, pk_i: bytes,
           c_i: bytes) -> tuple[bytes, bytes]:
    ss = _pq_decaps(sk_X, c_i) if USE_PQ else x25519(sk_X, c_i)
    dk_i = hkdf(ss, info=_dk_info(oid, ep, i, pk_i))
    return dk_i, hkdf(dk_i, info=b"veil/mac")


def publish(oid: bytes, ep: int, entries: list[tuple[int, bytes, bytes]],
            org: OrgKeys) -> tuple[bytes, bytes]:
    leaves = [leaf_hash(oid, ep, i, pk_i, c_i) for i, pk_i, c_i in entries]
    rt = merkle_root(leaves)
    return rt, org_sign(org, b"veil/root" + oid + ep.to_bytes(8, "big") + rt)


def verify_header(org: OrgKeys, oid: bytes, ep: int, rt: bytes, sigma: bytes) -> bool:
    return org_verify(org, b"veil/root" + oid + ep.to_bytes(8, "big") + rt, sigma)


def pk_bytes(pk: list[np.ndarray]) -> bytes:
    return b"".join(np.ascontiguousarray(poly, dtype="<i8").tobytes() for poly in pk)


# --------------------------------------------------------------------------
def main():
    rng = np.random.default_rng(20261025)
    report = {"backend": BACKEND}

    # 1. X25519 RFC 7748 vector (exercises the fallback KEM)
    scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    report["x25519_rfc7748"] = x25519(scalar, u).hex() == expected
    assert report["x25519_rfc7748"], "x25519 test vector failed"

    # 2. enrollment / derivation agreement
    oid, ep = b"org-42", 7
    X = extractor_keygen(rng)
    org = org_keygen(512)
    p = vc.Params(n=4, t=19)
    keys = vc.keygen(p, rng)
    members = list(range(4))
    pk_b = [pk_bytes(keys.pks[i]) for i in members]

    c, dk, dk_mac = {}, {}, {}
    for i in members:
        c[i], dk[i], dk_mac[i] = enroll(oid, ep, i, pk_b[i], X.pk, rng)
    derived = {i: derive(X.sk, oid, ep, i, pk_b[i], c[i]) for i in members}
    report["kem_agreement"] = all(derived[i][0] == dk[i] and derived[i][1] == dk_mac[i]
                                  for i in members)

    # 3. context binding
    report["binding"] = {
        "transplant_ciphertext": derive(X.sk, oid, ep, 1, pk_b[1], c[0])[0] != dk[1],
        "wrong_epoch": derive(X.sk, oid, ep + 1, 0, pk_b[0], c[0])[0] != dk[0],
    }

    # 4. epoch publication + header verification
    entries = [(i, pk_b[i], c[i]) for i in members]
    rt, sigma = publish(oid, ep, entries, org)
    report["header"] = {
        "valid": verify_header(org, oid, ep, rt, sigma),
        "tampered_root": not verify_header(org, oid, ep, bytes(32), sigma),
        "tampered_sigma": not verify_header(org, oid, ep, rt,
                                            bytes([sigma[0] ^ 1]) + sigma[1:]),
    }

    # 5. end-to-end: enrolled dk signs, derived dk extracts
    pi, m = 2, b"task-42"
    payload = b"ALERT:peer-07-compromised-2026".ljust(p.payload_bytes, b"\x00")
    mu = vc.encode_mu(p, dk_mac[pi], payload)
    sig = vc.sign(keys, pi, m, embed="fpe", mu=mu, dk=dk[pi], rng=rng, epoch=ep, root=rt)
    got_payload, who = vc.extract_fpe(keys, sig, derived[pi][0], derived[pi][1])
    wrong_payload, _ = vc.extract_fpe(keys, sig, derived[1][0], derived[1][1])
    report["end_to_end"] = {
        "signature_verifies": vc.verify(keys, m, sig, root=rt),
        "payload_recovered": got_payload == payload,
        "signer_recovered": who == pi,
        "wrong_member_key_fails": wrong_payload is None,
    }

    # 6. sizes and timing
    def timed(fn, reps=20):
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        return (time.perf_counter() - t0) / reps * 1e3

    t_org = timed(lambda: org_keygen(512), reps=1)
    t_enroll = timed(lambda: enroll(oid, ep, 0, pk_b[0], X.pk, rng), reps=50)
    t_derive = timed(lambda: derive(X.sk, oid, ep, 0, pk_b[0], c[0]), reps=50)
    t_publish = timed(lambda: publish(oid, ep, entries, org), reps=20)
    t_verify = timed(lambda: verify_header(org, oid, ep, rt, sigma), reps=20)
    report["cost"] = {
        "c_i_bytes": len(c[0]),
        "mlkem768_ct_bytes": 1088,
        "root_bytes": len(rt),
        "org_sig_bytes": len(sigma),
        "enroll_ms": t_enroll,
        "derive_ms": t_derive,
        "publish_ms": t_publish,
        "verify_header_ms": t_verify,
        "org_keygen_ms": t_org,
    }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    os.makedirs("results", exist_ok=True)
    with open("results/enroll.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\nwrote results/enroll.json")


if __name__ == "__main__":
    main()
