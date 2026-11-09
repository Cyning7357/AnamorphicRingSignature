import numpy as np
import veil_core as vc

p = vc.Params(n=4, t=19)
rng = np.random.default_rng(0)

def old_sparse(p, idx, a):
    out = np.zeros(p.d, dtype=np.int64)
    for i in idx:
        i = int(i)
        if i == 0:
            out += a
        else:
            out[i:] += a[: p.d - i]
            out[:i] -= a[p.d - i:]
    return out % p.q

a = rng.integers(0, p.q, size=p.d, dtype=np.int64)
z = rng.integers(0, p.q, size=p.d, dtype=np.int64)
print("ntt batch ok:", np.array_equal(vc.ntt(p, a), vc._ntt_batch(p, a[None])[0]))
print("intt batch ok:", np.array_equal(vc.intt(p, a), vc._intt_batch(p, a[None])[0]))

idx = rng.choice(p.d, size=8, replace=False)
print("sparse ok:", np.array_equal(old_sparse(p, idx, a), vc.sparse_mul(p, idx, a)))

A_hat = [[rng.integers(0, p.q, size=p.d, dtype=np.int64) for _ in range(p.l)] for _ in range(p.k)]
zlist = [rng.integers(0, p.q, size=p.d, dtype=np.int64) for _ in range(p.l)]
zh = [vc.ntt(p, poly) for poly in zlist]
manual = [vc.intt(p, sum((A_hat[i][j] * zh[j]) % p.q for j in range(p.l)) % p.q) for i in range(p.k)]
fast = vc.mat_vec(p, A_hat, zlist)
print("matvec ok:", all(np.array_equal(x, y) for x, y in zip(manual, fast)))
