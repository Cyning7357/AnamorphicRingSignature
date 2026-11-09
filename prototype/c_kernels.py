"""ctypes binding to the C NTT / sparse-multiplication kernel, plus benchmarks.

Build first:  gcc -O3 -shared -o ../c/veil_kernels.dll ../c/veil_kernels.c
Run:          python c_kernels.py
"""

from __future__ import annotations

import ctypes
import json
import os
import tempfile
import time
from pathlib import Path

import numpy as np

import veil_core as vc

ROOT = Path(__file__).resolve().parents[1]


def _load():
    """The workspace may be blocked by an application-control policy; TEMP is not."""
    candidates = [ROOT / "c" / "veil_kernels.dll",
                  Path(tempfile.gettempdir()) / "veil_kernels.dll"]
    last = None
    for path in candidates:
        if not path.exists():
            continue
        try:
            return ctypes.CDLL(str(path))
        except OSError as exc:  # blocked path
            last = exc
    raise OSError(f"could not load veil_kernels.dll: {last}")


LIB = _load()

_i64p = ctypes.POINTER(ctypes.c_int64)
_i32p = ctypes.POINTER(ctypes.c_int32)

LIB.ntt_fwd.argtypes = [_i64p, _i64p]
LIB.ntt_inv.argtypes = [_i64p, _i64p]
LIB.sparse_mul.argtypes = [_i64p, _i64p, _i32p, ctypes.c_int]


def ntt(a: np.ndarray) -> np.ndarray:
    out = np.empty(256, dtype=np.int64)
    LIB.ntt_fwd(out.ctypes.data_as(_i64p), np.ascontiguousarray(a, dtype=np.int64).ctypes.data_as(_i64p))
    return out


def intt(a: np.ndarray) -> np.ndarray:
    out = np.empty(256, dtype=np.int64)
    LIB.ntt_inv(out.ctypes.data_as(_i64p), np.ascontiguousarray(a, dtype=np.int64).ctypes.data_as(_i64p))
    return out


def sparse_mul(idx: np.ndarray, a: np.ndarray) -> np.ndarray:
    out = np.empty(256, dtype=np.int64)
    LIB.sparse_mul(out.ctypes.data_as(_i64p),
                   np.ascontiguousarray(a, dtype=np.int64).ctypes.data_as(_i64p),
                   np.ascontiguousarray(idx, dtype=np.int32).ctypes.data_as(_i32p),
                   len(idx))
    return out


def main():
    p = vc.Params(n=4, t=19)
    rng = np.random.default_rng(11)
    a = rng.integers(0, p.q, size=256, dtype=np.int64)
    b = rng.integers(0, p.q, size=256, dtype=np.int64)
    idx = rng.choice(256, size=39, replace=False)

    checks = {
        "ntt": np.array_equal(ntt(a), vc.ntt(p, a)),
        "intt": np.array_equal(intt(a), vc.intt(p, a)),
        "ntt_intt_roundtrip": np.array_equal(intt(ntt(a)), a),
        "sparse_mul": np.array_equal(sparse_mul(idx, a), vc.sparse_mul(p, idx, a)),
    }

    def bench(fn, reps):
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        return (time.perf_counter() - t0) / reps * 1e6

    reps = 2000
    py = {
        "ntt": bench(lambda: vc.ntt(p, a), reps),
        "intt": bench(lambda: vc.intt(p, a), reps),
        "sparse": bench(lambda: vc.sparse_mul(p, idx, a), reps),
    }
    c = {
        "ntt": bench(lambda: ntt(a), reps),
        "intt": bench(lambda: intt(a), reps),
        "sparse": bench(lambda: sparse_mul(idx, a), reps),
    }
    shake = bench(lambda: vc._f(p, b"dk" * 16, 0, 12345), 1000)

    # one signature: 16 forward, 16 inverse, 16 sparse, 48 SHAKE
    py_sig = 16 * py["ntt"] + 16 * py["intt"] + 16 * py["sparse"] + 48 * shake
    c_sig = 16 * c["ntt"] + 16 * c["intt"] + 16 * c["sparse"] + 48 * shake

    report = {
        "correctness": checks,
        "python_us": py,
        "c_us": c,
        "speedup": {k: py[k] / c[k] for k in py},
        "shake_us": shake,
        "projected_sign_ms": {"python": py_sig / 1e3, "c": c_sig / 1e3,
                              "speedup": py_sig / c_sig},
    }
    print(json.dumps(report, indent=2))
    os.makedirs("results", exist_ok=True)
    with open("results/c_kernels.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("wrote results/c_kernels.json")


if __name__ == "__main__":
    main()
