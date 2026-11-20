"""Calibrate the estimator against known Dilithium MSIS parameter sets."""
import math

from estimator import SIS, schemes

for name in ("Dilithium2_MSIS_WkUnf", "Dilithium3_MSIS_WkUnf", "Dilithium5_MSIS_WkUnf"):
    params = getattr(schemes, name)
    print(name, params)
    res = SIS.estimate(params)
    rops = [v["rop"] for v in res.values() if v["rop"] != float("inf")]
    print("  bits =", round(math.log2(float(min(rops))), 1) if rops else "n/a")
