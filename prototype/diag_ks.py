"""Diagnostic: is the B-vs-normal KS deviation real, or test noise?

Compares (a) normal vs normal (null), (b) B vs B (null), (c) B vs normal,
and reports a byte-level chi-square of each class against uniform.
"""
import hashlib
import numpy as np

import veil_core as vc
from run_experiments import ks_2samp, PAYLOAD


def decoy_bytes_of(p, sig, pi):
    return b"".join(vc.box_to_int(p, z).to_bytes(p.RESP_BYTES, "big")
                    for j, z in enumerate(sig.zs) if j != pi)


def main():
    p = vc.Params(n=4, t=19)
    rng = np.random.default_rng(7)
    keys = vc.keygen(p, rng)
    dk = hashlib.sha256(b"veil-dk").digest()
    dk_mac = hashlib.sha256(b"veil-mac").digest()
    mu = vc.encode_mu(p, dk_mac, PAYLOAD)

    def batch(kind, count, seed):
        r = np.random.default_rng(seed)
        out = []
        for _ in range(count):
            pi = int(r.integers(0, p.n))
            e = None if kind == "normal" else kind
            s = vc.sign(keys, pi, b"d", embed=e, mu=mu, dk=dk, rng=r)
            out.append(decoy_bytes_of(p, s, pi))
        return np.frombuffer(b"".join(out), np.uint8)

    n1 = batch("normal", 60, 1)
    n2 = batch("normal", 60, 2)
    b1 = batch("fpe", 60, 3)
    b2 = batch("fpe", 60, 4)

    def chi2_uniform(x):
        c = np.bincount(x.astype(np.int64), minlength=256)
        e = c.sum() / 256.0
        return float(((c - e) ** 2 / e).sum())

    print("n=60 sigs each, bytes per class:", len(n1))
    for name, a, b in [("normal vs normal (null)", n1, n2),
                       ("B vs B (null)", b1, b2),
                       ("normal vs B", n1, b1)]:
        d, pv = ks_2samp(a, b)
        print(f"{name:26s} D={d:.5f} p={pv:.4f}")
    for name, x in [("normal", n1), ("B", b1)]:
        c2 = chi2_uniform(x)
        print(f"chi2 vs uniform {name:8s} = {c2:8.1f} (df=255, mean 255, sd 22.6)")


if __name__ == "__main__":
    main()
