"""SIS estimates for the ring layer: A is k x l over R_q, d = 256.

The verification equation is exact, so t = A s and a forgery yields a short
v = z' - z with A v = 0.  With k < l the kernel is non-trivial and recovering
the short solution is an SIS instance with
    n = k*d rows, m = l*d columns, q = 2^23 - 2^13 + 1,
    bound = 2*H (infinity norm), H = 2^(t-1), t = 19.
"""
from estimator import SIS

Q = 2**23 - 2**13 + 1
D = 256
L = 4
H = 2**18
BOUND = 2 * H

for k in (1, 2, 3):
    for norm, bound in (("oo", BOUND), ("2", BOUND)):
        nrm = float("inf") if norm == "oo" else 2
        params = SIS.Parameters(n=k * D, m=L * D, q=Q, length_bound=bound, norm=nrm)
        try:
            res = SIS.estimate(params)
            best = min(v["rop"] for v in res.values() if v["rop"] != float("inf"))
            import math

            print(f"k={k} norm={norm} bound={bound} bits={math.log2(float(best)):.1f}")
        except Exception as exc:  # noqa: BLE001
            print(f"k={k} norm={norm} bound={bound} ERROR {type(exc).__name__}: {exc}")
