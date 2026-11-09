"""Emit c/constants.h from veil_core's parameters (roots, bit reversal)."""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype"))
import veil_core as vc  # noqa: E402

p = vc.Params()
out = pathlib.Path(__file__).with_name("constants.h")

roots, inv_roots = [], []
stage_offsets = []
length = 2
while length <= p.d:
    stage_offsets.append(len(roots))
    roots.extend(int(x) for x in p.roots[length].tolist())
    inv_roots.extend(int(x) for x in p.inv_roots[length].tolist())
    length *= 2

lines = [
    "#pragma once",
    "#include <stdint.h>",
    f"#define Q {p.q}",
    f"#define D {p.d}",
    "static const int64_t PSI[D] = {" + ",".join(map(str, p.PSI.tolist())) + "};",
    "static const int32_t BITREV[D] = {" + ",".join(map(str, p.BITREV.tolist())) + "};",
    "static const int64_t ROOTS[] = {" + ",".join(map(str, roots)) + "};",
    "static const int64_t INV_ROOTS[] = {" + ",".join(map(str, inv_roots)) + "};",
    f"static const int64_t INV_D = {p.inv_d};",
    "static const int64_t PSI_INV[D] = {" + ",".join(map(str, p.PSI_INV.tolist())) + "};",
]
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("wrote", out, "roots entries:", len(roots))
