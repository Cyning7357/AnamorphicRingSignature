"""Atomised cost model: measure per-operation cost and predict sign/verify."""

import time

import numpy as np

import veil_core as vc

p = vc.Params(n=4, t=19)
rng = np.random.default_rng(3)
a = rng.integers(0, p.q, size=p.d, dtype=np.int64)
b = rng.integers(0, p.q, size=p.d, dtype=np.int64)
idx = rng.choice(p.d, size=39, replace=False)
keys = vc.keygen(p, rng)
dk = rng.bytes(32)
mu = vc.encode_mu(p, dk, b"x" * p.payload_bytes)
half = rng.bytes(p.L2 // 8)


def bench(fn, reps=200):
    t0 = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t0) / reps * 1e6  # microseconds


c_ntt = bench(lambda: vc._ntt_batch(p, a[None]))
c_intt = bench(lambda: vc._intt_batch(p, a[None]))
c_sparse = bench(lambda: vc.sparse_mul(p, idx, a))
c_shake = bench(lambda: vc._f(p, dk, 0, 12345))
c_sign = bench(lambda: vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk,
                               rng=rng, epoch=1, root=bytes(32)), reps=50)
sig = vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=1, root=bytes(32))
c_verify = bench(lambda: vc.verify(keys, b"m", sig, root=bytes(32)), reps=50)

pred_sign = 16 * c_ntt + 16 * c_intt + 16 * c_sparse + 48 * c_shake
pred_verify = 16 * c_ntt + 16 * c_intt + 16 * c_sparse

rows = [
    ("NTT(256)", c_ntt),
    ("INTT(256)", c_intt),
    ("sparse_mul (39 terms)", c_sparse),
    ("SHAKE (1.2 KB)", c_shake),
    ("predicted sign", pred_sign),
    ("measured sign", c_sign),
    ("predicted verify", pred_verify),
    ("measured verify", c_verify),
]
print(f"{'operation':28s} {'us':>10s}")
for name, us in rows:
    print(f"{name:28s} {us:10.1f}")
print(f"\noperation counts per sign: 16 NTT, 16 INTT, 16 sparse, 48 SHAKE")
print(f"model/measured: sign {pred_sign / c_sign:.2f}x, verify {pred_verify / c_verify:.2f}x")
