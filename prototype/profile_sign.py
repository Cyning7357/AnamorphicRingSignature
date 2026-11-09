import cProfile
import pstats
import numpy as np

import veil_core as vc

rng = np.random.default_rng(1)
p = vc.Params(n=4, t=19)
keys = vc.keygen(p, rng)
dk = rng.bytes(32)
mu = vc.encode_mu(p, dk, b"x" * p.payload_bytes)

def work():
    for _ in range(100):
        vc.sign(keys, 1, b"m", embed="fpe", mu=mu, dk=dk, rng=rng, epoch=1, root=bytes(32))

cProfile.run("work()", "prof.out")
st = pstats.Stats("prof.out")
st.sort_stats("cumulative").print_stats(12)
