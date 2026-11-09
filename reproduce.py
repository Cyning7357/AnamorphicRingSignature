"""Run every experiment and the paper build in order.

Usage:
    python reproduce.py                 # everything that is installed
    python reproduce.py --skip-tex      # experiments only
    python reproduce.py --skip-proverif # no ProVerif

Missing optional tools (ProVerif, latexmk) are reported and skipped, not fatal.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def run(cmd: list[str], cwd: Path) -> bool:
    print(f"\n$ {' '.join(cmd)}  (in {cwd.name}/)")
    try:
        subprocess.run(cmd, cwd=cwd, check=True)
        return True
    except subprocess.CalledProcessError as exc:
        print(f"  failed with exit code {exc.returncode}")
        return False
    except (FileNotFoundError, OSError) as exc:
        print(f"  could not launch {cmd[0]}: {exc}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-tex", action="store_true")
    ap.add_argument("--skip-proverif", action="store_true")
    args = ap.parse_args()

    proto = ROOT / "prototype"
    scripts = [
        "veil_core.py",
        "eval_full.py",
        "probe_vs_t.py",
        "cost_model.py",
        "dual_regev.py",
        "td_demo.py",
        "cca_demo.py",
        "enroll.py",
        "mcp_demo.py",
    ]
    ok = True
    for name in scripts:
        ok &= run([PY, name], proto)

    if not args.skip_proverif:
        if shutil.which("proverif"):
            for model in ("enroll.pv", "enroll_compromised.pv"):
                run(["proverif", model], ROOT / "proverif")
        else:
            print("\nproverif not on PATH; skipping the symbolic models")

    run([PY, "plot_results.py"], ROOT / "figures")
    run([PY, "make_figures.py"], ROOT / "figures")

    if not args.skip_tex:
        if shutil.which("latexmk"):
            run(["latexmk", "-pdf", "-interaction=nonstopmode", "veil.tex"], ROOT)
        else:
            print("\nlatexmk not on PATH; skipping the paper build")

    print("\nall done" if ok else "\nsome steps failed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
