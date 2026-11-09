"""Count the dominant operations of one sign and one verify (language-independent)."""

import numpy as np

import veil_core as vc

counts = {"ntt": 0, "intt": 0, "sparse": 0, "f": 0, "poly_mul": 0,
          "ntt_batch": 0, "ntt_polys": 0, "intt_batch": 0, "intt_polys": 0}
orig = {k: getattr(vc, k) for k in ("ntt", "intt", "sparse_mul", "_f", "poly_mul",
                                    "_ntt_batch", "_intt_batch")}


def wrap(name, key):
    fn = orig[name]

    def inner(*a, **kw):
        counts[key] += 1
        return fn(*a, **kw)

    setattr(vc, name, inner)


for n, k in (("ntt", "ntt"), ("intt", "intt"), ("sparse_mul", "sparse"),
             ("_f", "f"), ("poly_mul", "poly_mul")):
    wrap(n, k)


def wrap_batch(name, calls_key, polys_key):
    fn = orig[name]

    def inner(p, A, *a, **kw):
        counts[calls_key] += 1
        counts[polys_key] += A.shape[0]
        return fn(p, A, *a, **kw)

    setattr(vc, name, inner)


wrap_batch("_ntt_batch", "ntt_batch", "ntt_polys")
wrap_batch("_intt_batch", "intt_batch", "intt_polys")

p = vc.Params(n=4, t=19)
rng = np.random.default_rng(1)
keys = vc.keygen(p, rng)
dk = rng.bytes(32)
mu = vc.encode_mu(p, dk, b"x" * p.payload_bytes)

for name, fn in (("sign", lambda: vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk,
                                          rng=rng, epoch=1, root=bytes(32))),):
    for k in counts:
        counts[k] = 0
    sig = fn()
    print(name, dict(counts), "bytes:", len(vc.serialize(keys, sig)))

for k in counts:
    counts[k] = 0
ok = vc.verify(keys, b"m", sig, root=bytes(32))
print("verify", dict(counts), "ok:", ok)
