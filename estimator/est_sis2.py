"""Second pass: Euclidean bound from the actual response distribution."""
import math

from estimator import SIS

Q = 2**23 - 2**13 + 1
D = 256
L = 4
H = 2**18
# z uniform in [-H, H)^(L*D); difference of two responses:
EUCLID = 2 * H * math.sqrt((L * D) / 3.0)

cases = [
    (2, 2, EUCLID),
    (3, 2, EUCLID),
    (3, float("inf"), 2 * H),
    (4, float("inf"), 2 * H),
]
for k, norm, bound in cases:
    params = SIS.Parameters(n=k * D, m=L * D, q=Q, length_bound=bound, norm=norm)
    try:
        res = SIS.estimate(params)
        rops = [v["rop"] for v in res.values() if v["rop"] != float("inf")]
        if not rops:
            print(f"k={k} norm={norm} bound={bound:.3g} NO-ATTACK (empty result)")
            continue
        print(f"k={k} norm={norm} bound={bound:.3g} bits={math.log2(float(min(rops))):.1f}")
    except Exception as exc:  # noqa: BLE001
        print(f"k={k} norm={norm} bound={bound:.3g} ERROR {type(exc).__name__}: {exc}")
