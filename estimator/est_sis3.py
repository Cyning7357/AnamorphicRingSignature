"""SIS strength for k = 3, l = 4 as a function of the response-box width t."""
import math

from estimator import SIS

Q = 2**23 - 2**13 + 1
D, L = 256, 4

for t in (18, 19, 20, 21):
    bound = 2 * (2 ** (t - 1))  # infinity-norm bound on z' - z
    params = SIS.Parameters(n=3 * D, m=L * D, q=Q, length_bound=bound, norm=float("inf"))
    res = SIS.estimate(params)
    rops = [v["rop"] for v in res.values() if v["rop"] != float("inf")]
    bits = math.log2(float(min(rops))) if rops else float("nan")
    print(f"t={t} bound={bound} bits={bits:.1f}")
