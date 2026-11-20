"""Python reference timings for the paper's Table V (k = 3, l = 4, t = 19)."""
import json
import statistics
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import veil_core as vc  # noqa: E402

REPS = 60
rng = np.random.default_rng(2026)
out = {"params": {"k": 3, "l": 4, "t": 19, "reps": REPS}, "results": {}}


def bench(n, embed):
    p = vc.Params(n=n)
    keys = vc.keygen(p, rng)
    dk = rng.bytes(32)
    mu = vc.encode_mu(p, dk, b"x" * p.payload_bytes)
    sign, verify, extract = [], [], []
    for _ in range(REPS):
        t0 = time.perf_counter()
        sig = vc.sign(keys, 1, b"m", embed=embed, mu=mu, dk=dk, rng=rng, epoch=1, root=bytes(32))
        sign.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        assert vc.verify(keys, b"m", sig, root=bytes(32))
        verify.append(time.perf_counter() - t0)
        if embed == "fpe":
            t0 = time.perf_counter()
            pay, idx = vc.extract_fpe(keys, sig, dk, dk)
            extract.append(time.perf_counter() - t0)
            assert pay == b"x" * p.payload_bytes and idx == 1
    return {
        "size": len(vc.serialize(keys, sig)),
        "sign_ms": statistics.median(sign) * 1e3,
        "verify_ms": statistics.median(verify) * 1e3,
        "extract_ms": statistics.median(extract) * 1e3 if extract else None,
    }


for n in (4, 8, 16):
    out["results"][f"n={n}"] = {"regular": bench(n, None), "fpe": bench(n, "fpe")}

path = Path(__file__).resolve().parent / "results" / "py_bench.json"
path.write_text(json.dumps(out, indent=2), encoding="utf-8")
for key, val in out["results"].items():
    print(key, {mode: {k: (round(v, 2) if isinstance(v, float) else v) for k, v in m.items()} for mode, m in val.items()})
print("wrote", path)
