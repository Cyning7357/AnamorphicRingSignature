"""VEIL v3 experiments: three working points + linkability + epoch binding.

Run:  python run_experiments.py [--trials 40] [--ring 4] [--t 19]

Checks:
  1. correctness of normal / B(fpe) / B'(salt) / A(ae) + tamper + epoch binding
  2. sizes of the three working points (A is measured, but its carrier is a
     STRUCTURAL stand-in -- see veil_core.ae_encrypt)
  3. extraction: B gives (payload, signer); B' and A give payload; normal -> bottom
  4. linkability: same agent+epoch links, different agent/epoch does not
  5. distribution: B vs normal (chi2, KS vs null, low-bit, detector) + LSB control
  6. anonymity vs box width t; ring-size sweep; timing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import time

import numpy as np

import veil_core as vc

PAYLOAD = b"ALERT:peer-07-compromised-2026".ljust(vc.Params().payload_bytes, b"\x00")
EPOCH = 1


# --------------------------------------------------------------------------
def ks_2samp(a: np.ndarray, b: np.ndarray) -> tuple[float, float]:
    a, b = np.sort(a), np.sort(b)
    grid = np.concatenate([a, b])
    ca = np.searchsorted(a, grid, side="right") / len(a)
    cb = np.searchsorted(b, grid, side="right") / len(b)
    d = float(np.max(np.abs(ca - cb)))
    n_eff = len(a) * len(b) / (len(a) + len(b))
    lam = (math.sqrt(n_eff) + 0.12 + 0.11 / math.sqrt(n_eff)) * d
    p = sum(2.0 * ((-1) ** (k - 1)) * math.exp(-2.0 * k * k * lam * lam) for k in range(1, 101))
    return d, max(0.0, min(1.0, p))


def chi2_uniform(x: np.ndarray) -> float:
    c = np.bincount(x.astype(np.int64), minlength=256)
    e = c.sum() / 256.0
    return float(((c - e) ** 2 / e).sum())


def two_prop_p(k1: int, n1: int, k2: int, n2: int) -> float:
    p = (k1 + k2) / (n1 + n2)
    se = math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2))
    return 1.0 if se == 0 else math.erfc(abs(k1 / n1 - k2 / n2) / se / math.sqrt(2.0))


def auc(scores: np.ndarray, labels: np.ndarray) -> float:
    order = np.argsort(scores)
    ranks = np.empty(len(scores))
    ranks[order] = np.arange(1, len(scores) + 1)
    pos = labels == 1
    n_pos, n_neg = pos.sum(), (~pos).sum()
    return float((ranks[pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def train_logreg(X, y, iters=2000, lr=0.3):
    mu, sd = X.mean(0), X.std(0) + 1e-9
    Xs = (X - mu) / sd
    w, b = np.zeros(X.shape[1]), 0.0
    for _ in range(iters):
        p = 1.0 / (1.0 + np.exp(-(Xs @ w + b)))
        w -= lr * (Xs.T @ (p - y) / len(y))
        b -= lr * float(np.mean(p - y))
    return lambda Z: ((Z - mu) / sd) @ w + b


def decoy_bytes(p, sig, pi):
    return b"".join(vc.box_to_int(p, z).to_bytes(p.RESP_BYTES, "big")
                    for j, z in enumerate(sig.zs) if j != pi)


def lowbit_slice(p, sig, pi):
    return np.concatenate([z[: p.MU_BITS] & 1 for j, z in enumerate(sig.zs) if j != pi])


def features(p, sig, pi):
    arr = np.frombuffer(decoy_bytes(p, sig, pi), dtype=np.uint8).astype(np.float64)
    counts = np.bincount(arr.astype(np.int64), minlength=256)
    prob = counts / counts.sum()
    ent = -np.sum(prob[prob > 0] * np.log2(prob[prob > 0]))
    chi2 = float(np.sum((counts - counts.sum() / 256.0) ** 2 / (counts.sum() / 256.0))) / 256.0
    lb = float(lowbit_slice(p, sig, pi).mean())
    ac = float(np.corrcoef(arr[:-1], arr[1:])[0, 1])
    return np.array([arr.mean() / 255, arr.std() / 255, lb, chi2, ent / 8,
                     float(np.mean(arr == 0)), ac, float(np.max(np.abs(prob - 1 / 256)))])


def probe(p, sigs):
    amax = sum(int(np.argmax([int(np.max(np.abs(z))) for z in s.zs])) == pi for s, pi in sigs)
    amin = sum(int(np.argmin([int(np.max(np.abs(z))) for z in s.zs])) == pi for s, pi in sigs)
    return {"argmax_acc": amax / len(sigs), "argmin_acc": amin / len(sigs),
            "chance": 1.0 / p.n}


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=40)
    ap.add_argument("--ring", type=int, default=4)
    ap.add_argument("--t", type=int, default=19)
    ap.add_argument("--seed", type=int, default=20261024)
    args = ap.parse_args()

    p = vc.Params(n=args.ring, t=args.t)
    rng = np.random.default_rng(args.seed)
    keys = vc.keygen(p, rng)
    root = vc.merkle_root(keys.pks)
    dk = hashlib.sha256(b"veil-dk").digest()
    dk_mac = hashlib.sha256(b"veil-mac").digest()
    mu = vc.encode_mu(p, dk_mac, PAYLOAD)

    report = {"params": {
        "d": p.d, "k": p.k, "l": p.l, "eta": p.eta, "tau": p.tau, "t": p.t,
        "n": p.n, "q": p.q, "M": p.M, "H": p.H, "log2_box": p.L_BITS,
        "resp_bytes": p.RESP_BYTES, "payload_bytes": p.payload_bytes,
        "epoch": EPOCH, "merkle_root_hex": root.hex()[:16] + "...",
    }}

    # 1. correctness + tamper + epoch binding
    trials = 15
    ok = {k: 0 for k in ("normal", "fpe", "salt", "ae")}
    tamper = 0
    epoch_break = 0
    for _ in range(trials):
        pi = int(rng.integers(0, p.n))
        m = b"task-%d" % int(rng.integers(0, 10**6))
        for mode in ok:
            s = vc.sign(keys, pi, m, embed=None if mode == "normal" else mode,
                        mu=mu, dk=dk, rng=rng, epoch=EPOCH, root=root)
            assert s is not None and vc.verify(keys, m, s, root=root), f"verify failed: {mode}"
            ok[mode] += 1
            if mode == "fpe":
                s2 = vc.Sig(c1=s.c1, zs=[z.copy() for z in s.zs], epoch=s.epoch,
                            tag=s.tag, ae_ct=s.ae_ct, salt=s.salt, nonce=s.nonce)
                s2.zs[0][0] ^= 1
                tamper += int(not vc.verify(keys, m, s2, root=root))
                epoch_break += int(not vc.verify(keys, m, s, root=b"\x00" * 32))
    report["correctness"] = {k: v / trials for k, v in ok.items()}
    report["correctness"].update({"tamper_rejected": tamper / trials,
                                  "wrong_epoch_root_rejected": epoch_break / trials})

    # 2. sizes
    m = b"size"
    sigs = {
        "normal": vc.sign(keys, 0, m, rng=rng, epoch=EPOCH, root=root),
        "B_fpe": vc.sign(keys, 0, m, embed="fpe", mu=mu, dk=dk, rng=rng, epoch=EPOCH, root=root),
        "B_prime_salt": vc.sign(keys, 0, m, embed="salt", mu=mu, dk=dk, rng=rng, epoch=EPOCH, root=root),
        "A_ae": vc.sign(keys, 0, m, embed="ae", mu=mu, dk=dk, rng=rng, epoch=EPOCH, root=root),
        "B_link": vc.sign(keys, 0, m, embed="fpe", mu=mu, dk=dk, rng=rng, epoch=EPOCH,
                          root=root, link=True),
    }
    base = len(vc.serialize(keys, sigs["normal"]))
    report["sizes"] = {k: len(vc.serialize(keys, s)) for k, s in sigs.items()}
    report["sizes"].update({
        "base": base,
        "overhead_B": len(vc.serialize(keys, sigs["B_fpe"])) - base,
        "overhead_B_prime": len(vc.serialize(keys, sigs["B_prime_salt"])) - base,
        "overhead_A": len(vc.serialize(keys, sigs["A_ae"])) - base,
        "overhead_link": len(vc.serialize(keys, sigs["B_link"])) - base,
        "breakdown": f"32 + {p.n} x {p.RESP_BYTES}",
        "note_A": "A carrier is a 1088 B structural stand-in + 48 B payload; "
                  "no anamorphic security is instantiated (see README)",
    })

    # 3. extraction
    T = 30
    attr = 0
    for _ in range(T):
        pi = int(rng.integers(0, p.n))
        s = vc.sign(keys, pi, b"x", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=EPOCH, root=root)
        payload, who = vc.extract_fpe(keys, s, dk, dk_mac)
        attr += int(payload == PAYLOAD and who == pi)
    salt_ok = 0
    for _ in range(T):
        s = vc.sign(keys, int(rng.integers(0, p.n)), b"x", embed="salt", mu=mu, dk=dk,
                    rng=rng, epoch=EPOCH, root=root)
        salt_ok += int(vc.extract_salt(keys, s, dk, dk_mac) == PAYLOAD)
    ae_ok = 0
    for _ in range(T):
        s = vc.sign(keys, int(rng.integers(0, p.n)), b"x", embed="ae", mu=mu, dk=dk,
                    rng=rng, epoch=EPOCH, root=root)
        ae_ok += int(vc.ae_decrypt(p, dk, dk_mac, s.ae_ct) == PAYLOAD)
    rob = 0
    for _ in range(T):
        s = vc.sign(keys, int(rng.integers(0, p.n)), b"x", rng=rng, epoch=EPOCH, root=root)
        payload, who = vc.extract_fpe(keys, s, dk, dk_mac)
        rob += int(payload is None and who is None)
    report["extraction"] = {"B_payload_and_signer": attr / T, "B_prime_payload": salt_ok / T,
                            "A_payload": ae_ok / T, "normal_returns_bottom": rob / T}

    # 4. linkability
    a1 = vc.sign(keys, 0, b"a", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=7, root=root, link=True)
    a2 = vc.sign(keys, 0, b"b", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=7, root=root, link=True)
    b1 = vc.sign(keys, 1, b"c", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=7, root=root, link=True)
    a3 = vc.sign(keys, 0, b"d", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=8, root=root, link=True)
    report["linkability"] = {
        "same_agent_same_epoch": vc.link(a1, a2),
        "different_agent": vc.link(a1, b1),
        "different_epoch": vc.link(a1, a3),
        "tag_bytes": len(a1.tag),
    }

    # 5. distribution (2 seeds)
    def collect(seed, count, kind):
        r = np.random.default_rng(seed)
        k = vc.keygen(p, r)
        mu_ = vc.encode_mu(p, dk_mac, PAYLOAD)
        out = []
        for _ in range(count):
            pi = int(r.integers(0, p.n))
            e = None if kind == "normal" else kind
            out.append((vc.sign(k, pi, b"d", embed=e, mu=mu_, dk=dk, rng=r, epoch=EPOCH,
                                root=vc.merkle_root(k.pks)), pi))
        return out

    pool = {k: [] for k in ("normal", "fpe", "lsb")}
    for i in range(2):
        for kind in pool:
            pool[kind] += collect(args.seed + i, args.trials, kind)
    nb = np.frombuffer(b"".join(decoy_bytes(p, s, pi) for s, pi in pool["normal"]), np.uint8)
    fb = np.frombuffer(b"".join(decoy_bytes(p, s, pi) for s, pi in pool["fpe"]), np.uint8)
    lb = np.frombuffer(b"".join(decoy_bytes(p, s, pi) for s, pi in pool["lsb"]), np.uint8)
    bf = np.concatenate([lowbit_slice(p, s, pi) for s, pi in pool["fpe"]])
    bn = np.concatenate([lowbit_slice(p, s, pi) for s, pi in pool["normal"]])
    X = np.array([features(p, s, pi) for s, pi in pool["normal"] + pool["fpe"]])
    y = np.array([0] * len(pool["normal"]) + [1] * len(pool["fpe"]))
    idx = np.random.default_rng(0).permutation(len(y))
    cut = 2 * len(y) // 3
    clf = train_logreg(X[idx[:cut]], y[idx[:cut]])
    report["distribution"] = {
        "chi2_df255": {"normal": chi2_uniform(nb), "B": chi2_uniform(fb),
                       "lsb": chi2_uniform(lb)},
        "ks_normal_vs_B": dict(zip(("D", "p"), ks_2samp(nb, fb))),
        "ks_normal_vs_lsb": dict(zip(("D", "p"), ks_2samp(nb, lb))),
        "lowbit_frac": {"normal": float(bn.mean()), "B": float(bf.mean())},
        "lowbit_p_B_vs_normal": two_prop_p(int(bf.sum()), len(bf), int(bn.sum()), len(bn)),
        "detector_auc_B": auc(clf(X[idx[cut:]]), y[idx[cut:]]),
        "samples": {"normal": len(nb), "B": len(fb), "lsb": len(lb)},
    }

    # 6. anonymity vs box width
    gap = []
    for t in (18, 19, 20):
        pp = vc.Params(n=args.ring, t=t)
        rr = np.random.default_rng(args.seed + t)
        kk = vc.keygen(pp, rr)
        mroot = vc.merkle_root(kk.pks)
        sigs = []
        for _ in range(25):
            pi = int(rr.integers(0, pp.n))
            sigs.append((vc.sign(kk, pi, b"a", embed="fpe", mu=mu, dk=dk, rng=rr,
                                 epoch=EPOCH, root=mroot), pi))
        pr = probe(pp, sigs)
        pr.update({"t": t, "M_over_H": pp.M / pp.H,
                   "shell_prob": 1 - (1 - pp.M / pp.H) ** (pp.l * pp.d)})
        gap.append(pr)
    report["anonymity_vs_box_width"] = gap

    # 7. ring sweep + timing
    sweep = []
    for nn in (2, 4, 8):
        pp = vc.Params(n=nn, t=args.t)
        rr = np.random.default_rng(args.seed + nn)
        kk = vc.keygen(pp, rr)
        mroot = vc.merkle_root(kk.pks)
        mu_ = vc.encode_mu(pp, dk_mac, PAYLOAD)
        s = vc.sign(kk, 0, b"s", embed="fpe", mu=mu_, dk=dk, rng=rr, epoch=EPOCH, root=mroot)
        t0 = time.perf_counter()
        for _ in range(8):
            vc.sign(kk, 0, b"s", embed="fpe", mu=mu_, dk=dk, rng=rr, epoch=EPOCH, root=mroot)
        sweep.append({"n": nn, "size": len(vc.serialize(kk, s)),
                      "sign_ms": (time.perf_counter() - t0) / 8 * 1e3})
    report["ring_sweep"] = sweep

    def timed(fn, reps=15):
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        return (time.perf_counter() - t0) / reps * 1e3

    sig = vc.sign(keys, 0, b"tm", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=EPOCH, root=root)
    a = rng.integers(0, p.q, size=p.d, dtype=np.int64)
    b = rng.integers(0, p.q, size=p.d, dtype=np.int64)
    t0 = time.perf_counter()
    for _ in range(300):
        vc.poly_mul(p, a, b)
    t_ntt = (time.perf_counter() - t0) / 300 * 1e6
    report["timing_ms"] = {
        "sign": timed(lambda: vc.sign(keys, 0, b"tm", embed="fpe", mu=mu, dk=dk,
                                      rng=np.random.default_rng(1), epoch=EPOCH, root=root)),
        "verify": timed(lambda: vc.verify(keys, b"tm", sig, root=root)),
        "extract": timed(lambda: vc.extract_fpe(keys, sig, dk, dk_mac)),
        "mul_ntt_us": t_ntt,
        "note": "pure Python/numpy; timings are indicative only",
    }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    os.makedirs("results", exist_ok=True)
    with open("results/phase3.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\nwrote results/phase3.json")


if __name__ == "__main__":
    main()
