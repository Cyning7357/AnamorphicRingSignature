"""Fig. anonymity: rejection rate and the sampler ablation."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["DejaVu Serif"],
    "font.size": 8,
    "axes.linewidth": 0.6,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
})

data = json.loads(Path("prototype/results/probe_fix.json").read_text())
rej = data["reject"]
rows = data["rows"]
ts = [r["t"] for r in rej]

fig, (a1, a2) = plt.subplots(2, 1, figsize=(3.4, 3.5))

a1.bar(ts, [100 * r["p"] for r in rej], width=0.55, color="#c0504d", edgecolor="#7f2f2d", linewidth=0.5)
for t, r in zip(ts, rej):
    a1.text(t, 100 * r["p"] + 0.8, f"{100 * r['p']:.0f}%", ha="center", fontsize=7)
a1.set_xlabel("response-box width $t$")
a1.set_ylabel("rejection rate (%)")
a1.set_xticks(ts)
a1.set_ylim(0, 32)
a1.set_title("(a) mask rejection", fontsize=8, loc="left")

for sampler, colour, marker, label in (
    ("tapered", "#c0504d", "s", "shrunk mask box"),
    ("uniform", "#4f81bd", "o", "enlarged mask box"),
):
    pts = [r for r in rows if r["sampler"] == sampler]
    a2.plot([r["t"] for r in pts], [r["probe"] for r in pts],
            marker=marker, color=colour, linewidth=1.0, markersize=4, label=label)
a2.axhline(0.25, color="#808080", linestyle="--", linewidth=0.8)
a2.text(18.05, 0.2525, "chance", fontsize=6.5, color="#606060", ha="left", va="bottom")
a2.set_xlabel("response-box width $t$")
a2.set_ylabel("probe accuracy")
a2.set_xticks(ts)
a2.set_ylim(0.22, 0.37)
a2.set_title("(b) signer probe", fontsize=8, loc="left")
a2.legend(fontsize=6.5, frameon=False, loc="upper right")

fig.tight_layout(pad=0.4)
out = Path("figures/plots")
out.mkdir(parents=True, exist_ok=True)
fig.savefig(out / "fig-anon.pdf")
fig.savefig(out / "fig-anon.png", dpi=300)
print("wrote fig-anon")

