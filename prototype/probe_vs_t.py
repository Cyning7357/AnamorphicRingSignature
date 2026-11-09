"""Signer-probe accuracy vs the box width t (base decoy signature leak)."""

import json

import numpy as np

import veil_core as vc
from run_experiments import probe


def main():
    rng = np.random.default_rng(7)
    out = {}
    for t in (18, 19, 20, 21):
        p = vc.Params(n=4, t=t)
        keys = vc.keygen(p, rng)
        sigs = []
        for _ in range(300):
            pi = int(rng.integers(0, p.n))
            sig = vc.sign(keys, pi, b"m", embed=None, rng=rng, epoch=1, root=bytes(32))
            sigs.append((sig, pi))
        res = probe(p, sigs)
        res["signature_bytes"] = len(vc.serialize(keys, sigs[0][0]))
        out[t] = res
        print(t, res)
    with open("results/probe_vs_t.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    main()
