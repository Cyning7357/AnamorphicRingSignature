"""Experiment figures from the JSON results (matplotlib).

Run: python plot_results.py
Out: figures/plots/*.pdf and *.png

Figures:
  1. chi-square of the decoy bytes (regular / attributable / naive LSB)
  2. signer-probe accuracy versus the response-box width t
  3. signature size versus ring size for the three working points
  4. carrier size with and without the MP12 trapdoor
"""

from __future__ import annotations

import json
import pathlib
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype"))
import veil_core as vc  # noqa: E402

RES = ROOT / "prototype" / "results"
OUT = pathlib.Path(__file__).parent / "plots"
OUT.mkdir(exist_ok=True)

plt.rcParams.update({
    "font.size": 9,
    "font.family": "serif",
    "axes.linewidth": 0.8,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linewidth": 0.5,
    "legend.frameon": False,
    "figure.dpi": 200,
})


def save(fig, name):
    fig.tight_layout()
    fig.savefig(OUT / f"{name}.pdf")
    fig.savefig(OUT / f"{name}.png", dpi=300)
    plt.close(fig)


# 1. chi-square ------------------------------------------------------------
d = json.loads((RES / "full.json").read_text(encoding="utf-8"))
e = d["e2_detectability"]
vals = [e["fpe"]["chi2_normal"], e["fpe"]["chi2_vs_uniform"], e["lsb"]["chi2_vs_uniform"]]
labels = ["regular", "attributable", "naive LSB"]
fig, ax = plt.subplots(figsize=(3.4, 2.4))
bars = ax.bar(labels, vals, color=["#b0b0b0", "#4c72b0", "#c44e52"], width=0.6)
ax.set_yscale("log")
ax.set_ylabel(r"$\chi^2$ of decoy bytes (df = 255)")
mean, sd = 255.0, np.sqrt(2 * 255.0)
ax.axhspan(mean - 2 * sd, mean + 2 * sd, color="#4c72b0", alpha=0.12, lw=0)
ax.axhline(mean, color="#4c72b0", ls="--", lw=0.8)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v * 1.15, f"{v:.0f}", ha="center", va="bottom", fontsize=8)
ax.set_ylim(1e2, 2e4)
save(fig, "fig-chi2")

# 2. probe versus t --------------------------------------------------------
p = json.loads((RES / "probe_vs_t.json").read_text(encoding="utf-8"))
ts = sorted(int(k) for k in p)
acc = [p[str(t)]["argmin_acc"] for t in ts]
chance = [p[str(t)]["chance"] for t in ts]
fig, ax = plt.subplots(figsize=(3.4, 2.4))
ax.plot(ts, acc, "o-", color="#4c72b0", label="signer probe (argmin)")
ax.plot(ts, chance, "s--", color="#888888", ms=3, label="chance (1/n)")
for t, a in zip(ts, acc):
    ax.annotate(f"{a:.2f}", (t, a), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=8)
ax.set_xlabel("response-box width $t$")
ax.set_ylabel("probe accuracy")
ax.set_ylim(0.22, 0.35)
ax.set_xticks(ts)
ax.legend(loc="upper right")
save(fig, "fig-probe")

# 3. size versus n ---------------------------------------------------------
def sig_bytes(n: int, embed: str | None) -> int:
    p = vc.Params(n=n, t=19)
    rng = np.random.default_rng(1000 + n + (0 if embed is None else hash(embed) % 97))
    keys = vc.keygen(p, rng)
    dk = rng.bytes(32)
    mu = vc.encode_mu(p, dk, b"x" * p.payload_bytes)
    kw = dict(embed=embed, rng=rng, epoch=1, root=bytes(32))
    if embed == "fpe":
        kw.update(mu=mu, dk=dk)
    elif embed == "salt":
        kw.update(mu=mu, dk=dk)
    sig = vc.sign(keys, 0, b"m", **kw)
    return len(vc.serialize(keys, sig))


ns = [2, 4, 8, 16, 32, 64]
ring = np.array([sig_bytes(n, None) for n in ns])
b = np.array([sig_bytes(n, "fpe") for n in ns])
assert np.array_equal(ring, b), "attributable mode must match the regular size"

fig, ax = plt.subplots(figsize=(3.4, 2.6))
ax.plot(ns, ring / 1024, "s--", color="#999999", ms=4, label="regular = attributable (+0 B)")
ax.plot(ns, (ring + 64) / 1024, "^-", color="#55a868", label="salted (+64 B)")
ax.plot(ns, (ring + 3075) / 1024, "D-", color="#c44e52", label="anonymous, square (+3075 B)")
ax.plot(ns, (ring + 8426) / 1024, "v-", color="#8172b2", label="anonymous, with $td$ (+8426 B)")
ax.set_xscale("log", base=2)
ax.set_xticks(ns)
ax.set_xticklabels([str(n) for n in ns])
ax.set_xlabel("ring size $n$")
ax.set_ylabel("signature size (KB)")
ax.legend(loc="upper left", fontsize=7.5)
save(fig, "fig-size")

# 4. trapdoor cost ---------------------------------------------------------
t = json.loads((RES / "td.json").read_text(encoding="utf-8"))
square = t["sizes"]["square_dual_regev_bytes_at_same_n"]
gadget = t["sizes"]["ct_bytes_bitpacked"]
fig, ax = plt.subplots(figsize=(2.9, 2.5))
bars = ax.bar(["square", "with $R$"], [square, gadget], color=["#4c72b0", "#dd8452"], width=0.55)
ax.set_ylabel("carrier size (bytes)")
for b_, v in zip(bars, [square, gadget]):
    ax.text(b_.get_x() + b_.get_width() / 2, v * 1.02, f"{v}", ha="center", va="bottom", fontsize=8)
ax.set_ylim(0, gadget * 1.55)
coeff_factor = t["sizes"]["c1_coeffs"] / t["params"]["n"]
ax.text(0.5, gadget * 1.28, f"$\\times${gadget / square:.1f} in bytes\n"
        f"({coeff_factor:.1f}$\\times$ in coefficients)",
        ha="center", va="bottom", fontsize=8, color="#333333")
save(fig, "fig-td")

print("wrote", ", ".join(sorted(p.name for p in OUT.glob("*.pdf"))))
