"""Large-sample evaluation: zero-byte, detectability, extraction, robustness, linking.

E1  1000 normal vs 1000 attributable signatures: serialized length equality.
E2  2000 per class (normal / attributable / LSB control): chi-square, KS,
    low-bit test, and an 8-feature logistic-regression detector (1500/500 split).
E3  300 signatures: extraction correctness and a public signer probe.
E4  200 each: framing, transplant, epoch mismatch.
E5  200 each: linking (same/different agent, same/different epoch).

Run: python eval_full.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import time

import numpy as np

import veil_core as vc
from run_experiments import (auc, chi2_uniform, decoy_bytes, features, ks_2samp,
                             lowbit_slice, probe, train_logreg)


def main():
    rng = np.random.default_rng(20261028)
    p = vc.Params(n=4, t=19)
    keys = vc.keygen(p, rng)
    root = bytes(range(32))
    epoch = 7
    payload = b"ALERT:peer-07-compromised-2026".ljust(p.payload_bytes, b"\x00")
    dk = rng.bytes(32)
    dk_mac = hashlib.sha256(dk).digest()
    mu = vc.encode_mu(p, dk_mac, payload)
    report = {"params": {"n": p.n, "t": p.t, "q": p.q}}

    # ---------------- E1: zero-byte ----------------
    t0 = time.perf_counter()
    sizes_n, sizes_b = [], []
    ok_n = ok_b = 0
    for _ in range(1000):
        pi = int(rng.integers(0, p.n))
        sn = vc.sign(keys, pi, b"m", embed=None, rng=rng, epoch=epoch, root=root)
        sb = vc.sign(keys, pi, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch, root=root)
        sizes_n.append(len(vc.serialize(keys, sn)))
        sizes_b.append(len(vc.serialize(keys, sb)))
        ok_n += int(vc.verify(keys, b"m", sn, root=root))
        ok_b += int(vc.verify(keys, b"m", sb, root=root))
    report["e1_zero_byte"] = {
        "pairs": 1000,
        "size_normal": sizes_n[0],
        "size_attributable": sizes_b[0],
        "all_lengths_equal": all(a == b for a, b in zip(sizes_n, sizes_b)),
        "normal_verifies": ok_n / 1000,
        "attributable_verifies": ok_b / 1000,
        "seconds": time.perf_counter() - t0,
    }

    # ---------------- E2: detectability ----------------
    counts = {c: np.zeros(256, dtype=np.int64) for c in ("normal", "fpe", "lsb")}
    lowbit = {c: 0 for c in counts}
    nbytes = {c: 0 for c in counts}
    reservoir = {c: [] for c in counts}
    feats = {c: [] for c in counts}
    t0 = time.perf_counter()
    for cls, embed in (("normal", None), ("fpe", "fpe"), ("lsb", "lsb")):
        for k in range(2000):
            pi = int(rng.integers(0, p.n))
            kw = dict(embed=embed, rng=rng, epoch=epoch, root=root)
            if embed == "fpe":
                kw.update(mu=mu, dk=dk)
            elif embed == "lsb":
                kw.update(mu=mu)
            sig = vc.sign(keys, pi, b"m", **kw)
            b = decoy_bytes(p, sig, pi)
            arr = np.frombuffer(b, dtype=np.uint8)
            counts[cls] += np.bincount(arr.astype(np.int64), minlength=256)
            lowbit[cls] += int((arr & 1).sum())
            nbytes[cls] += len(arr)
            if k % 10 == 0:
                reservoir[cls].append(b)
            feats[cls].append(features(p, sig, pi))
    e2 = {"seconds": time.perf_counter() - t0}

    def split(cls):
        X = np.array(feats[cls])
        return X[:1500], X[1500:]

    Xn_tr, Xn_te = split("normal")
    for cls in ("fpe", "lsb"):
        Xc_tr, Xc_te = split(cls)
        model = train_logreg(np.vstack([Xn_tr, Xc_tr]),
                             np.r_[np.zeros(len(Xn_tr)), np.ones(len(Xc_tr))])
        s = np.r_[model(Xn_te), model(Xc_te)]
        y = np.r_[np.zeros(len(Xn_te)), np.ones(len(Xc_te))]
        res = reservoir["normal"] + reservoir[cls]
        a = np.frombuffer(b"".join(reservoir["normal"]), dtype=np.uint8)
        b = np.frombuffer(b"".join(reservoir[cls]), dtype=np.uint8)
        d, pval = ks_2samp(a, b)
        c = counts[cls]
        e = c.sum() / 256.0
        e2[cls] = {
            "detector_auc": auc(s, y),
            "chi2_vs_uniform": float(((c - e) ** 2 / e).sum()),
            "chi2_normal": float(((counts["normal"] - e) ** 2 / e).sum()),
            "ks_d": d, "ks_p": pval,
            "lowbit_frac": lowbit[cls] / nbytes[cls],
            "lowbit_normal": lowbit["normal"] / nbytes["normal"],
            "mean_bytes": nbytes[cls] / 2000,
        }
    report["e2_detectability"] = e2

    # ---------------- E3: extraction and probe ----------------
    ok = 0
    probe_sigs = []
    for _ in range(300):
        pi = int(rng.integers(0, p.n))
        sig = vc.sign(keys, pi, b"m", embed="fpe", mu=mu, dk=dk, rng=rng,
                      epoch=epoch, root=root)
        got, who = vc.extract_fpe(keys, sig, dk, dk_mac)
        ok += int(got == payload and who == pi)
        probe_sigs.append((sig, pi))
    report["e3_extraction"] = {"trials": 300, "correct": ok / 300, "probe": probe(p, probe_sigs)}

    # ---------------- E4: robustness ----------------
    framing = 0
    for _ in range(200):
        pi = int(rng.integers(0, p.n))
        sig = vc.sign(keys, pi, b"m", embed=None, rng=rng, epoch=epoch, root=root)
        got, _ = vc.extract_fpe(keys, sig, dk, dk_mac)
        framing += int(got is None)
    transplant = 0
    for _ in range(200):
        pi = int(rng.integers(0, p.n))
        other = (pi + 1) % p.n
        a = vc.sign(keys, pi, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch, root=root)
        b = vc.sign(keys, other, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch, root=root)
        mod = copy.deepcopy(a)
        mod.zs[other % p.n] = b.zs[other % p.n]
        transplant += int(not vc.verify(keys, b"m", mod, root=root))
    epoch_bad = 0
    for _ in range(200):
        pi = int(rng.integers(0, p.n))
        sig = vc.sign(keys, pi, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch, root=root)
        epoch_bad += int(not vc.verify(keys, b"m", sig, root=bytes(32)))
    report["e4_robustness"] = {
        "framing_returns_bot": framing / 200,
        "transplant_rejected": transplant / 200,
        "wrong_root_rejected": epoch_bad / 200,
    }

    # ---------------- E5: linking ----------------
    def linked(a, b):
        return vc.link(a, b)

    same_same = sum(
        linked(vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch,
                       root=root, link=True),
               vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch,
                       root=root, link=True))
        for _ in range(200))
    diff_agent = sum(
        linked(vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch,
                       root=root, link=True),
               vc.sign(keys, 2, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch,
                       root=root, link=True))
        for _ in range(200))
    diff_epoch = sum(
        linked(vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch,
                       root=root, link=True),
               vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=epoch + 1,
                       root=root, link=True))
        for _ in range(200))
    report["e5_link"] = {
        "same_agent_same_epoch": same_same / 200,
        "different_agent": diff_agent / 200,
        "different_epoch": diff_epoch / 200,
    }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    os.makedirs("results", exist_ok=True)
    with open("results/full.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\nwrote results/full.json")


if __name__ == "__main__":
    main()
