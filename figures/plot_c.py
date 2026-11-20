# -*- coding: utf-8 -*-
"""Figures for the C port and the detector sweep, from the JSON results."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import NullFormatter, ScalarFormatter

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "prototype" / "results"
OUT = Path(__file__).resolve().parent / "plots"
OUT.mkdir(exist_ok=True)

plt.rcParams.update({"font.size": 8, "axes.labelsize": 8, "xtick.labelsize": 7,
                     "ytick.labelsize": 7, "legend.fontsize": 6.8})


def save(fig, name):
    fig.savefig(OUT / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(OUT / f"{name}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


c = json.loads((RES / "c_sign.json").read_text(encoding="utf-8"))
ns = [4, 8, 16]
py_sign = [2.20, 4.54, 14.99]
py_verify = [1.59, 3.24, 11.20]
py_extract = [1.93, 3.44, 9.61]
c_sign = [c["benchmark"]["results"]["fpe"][f"n={n}"]["sign"]["mean_ms"] for n in ns]
c_verify = [c["benchmark"]["results"]["fpe"][f"n={n}"]["verify"]["mean_ms"] for n in ns]
c_extract = [c["benchmark"]["results"]["fpe"][f"n={n}"]["extract"]["mean_ms"] for n in ns]

BLUE, RED = "#4c72b0", "#c44e52"
fig, (a1, a2) = plt.subplots(2, 1, figsize=(3.4, 4.4))

a1.plot(ns, py_sign, "-", color=BLUE, marker="o", label="Python sign")
a1.plot(ns, c_sign, "-", color=RED, marker="o", label="C sign")
a1.plot(ns, py_verify, "--", color=BLUE, marker="s", mfc="none", label="Python verify")
a1.plot(ns, c_verify, "--", color=RED, marker="s", mfc="none", label="C verify")
a1.set_yscale("log")
a1.set_xlim(3.3, 16.8)
a1.set_ylim(0.1, 30)
a1.set_xticks(ns)
a1.set_yticks([0.1, 0.3, 1, 3, 10])
a1.yaxis.set_major_formatter(ScalarFormatter())
a1.yaxis.set_minor_formatter(NullFormatter())
a1.set_xlabel("ring size $n$")
a1.set_ylabel("time (ms)")
a1.text(0.03, 0.93, "(a) signing and verification", transform=a1.transAxes,
        fontsize=7, va="top")

a2.plot(ns, py_extract, "-", color=BLUE, marker="^", label="Python extract")
a2.plot(ns, c_extract, "-", color=RED, marker="^", mfc="none", label="C extract")
a2.set_yscale("log")
a2.set_xlim(3.3, 16.8)
a2.set_ylim(0.25, 10)
a2.set_xticks(ns)
a2.set_yticks([0.3, 0.6, 1, 2, 3, 6])
a2.yaxis.set_major_formatter(ScalarFormatter())
a2.yaxis.set_minor_formatter(NullFormatter())
a2.set_xlabel("ring size $n$")
a2.set_ylabel("time (ms)")
a2.text(0.03, 0.93, "(b) extraction", transform=a2.transAxes, fontsize=7, va="top")

handles = [Line2D([], [], color=BLUE, marker="o", ls="-", label="Python"),
           Line2D([], [], color=RED, marker="o", ls="-", label="C"),
           Line2D([], [], color="0.35", marker="o", ls="-", label="sign"),
           Line2D([], [], color="0.35", marker="s", ls="--", mfc="none", label="verify"),
           Line2D([], [], color="0.35", marker="^", ls="-", label="extract")]
fig.legend(handles=handles, loc="upper center", ncol=5, frameon=False,
           bbox_to_anchor=(0.5, 1.0), handlelength=1.6, columnspacing=1.2)
fig.tight_layout(rect=(0, 0, 1, 0.96))
save(fig, "fig-c")

e = json.loads((RES / "extra.json").read_text(encoding="utf-8"))
labels = [f"$n={n}$" for n in e["ring_sweep"]] + \
         [f"{r} rounds" for r in e["rounds"]] + \
         [f"{p} B payload" for p in e["payload"]] + \
         ["whole signature"]
vals = [v["auc"] for v in e["ring_sweep"].values()] + \
       [v["auc"] for v in e["rounds"].values()] + \
       [v["auc"] for v in e["payload"].values()] + \
       [e["full_signature"]["auc"]]
fig, ax = plt.subplots(figsize=(3.4, 2.9))
y = list(range(len(labels)))
ax.barh(y, vals, color="#55a868", height=0.62)
ax.axvline(0.5, color="#333333", ls="--", lw=0.9)
ax.set_yticks(y)
ax.set_yticklabels(labels, fontsize=6.8)
ax.invert_yaxis()
ax.set_xlim(0.4, 0.6)
ax.set_xlabel("detector AUC")
ax.text(0.505, -0.9, "chance", fontsize=6.5, color="#333333")
save(fig, "fig-auc")
print("wrote fig-c and fig-auc")


