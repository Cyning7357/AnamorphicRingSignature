# VEIL prototype

Python prototype for the paper *Hiding Messages in Decoy Responses:
Size-Preserving Post-Quantum Anamorphic Ring Signatures*.
It implements the three working points, extraction and linking, the
enrollment flow, the anonymous carrier, and the experiments that produce
every number in the paper.

## Files

- `veil_core.py` — ring core: NTT over `Z_q[x]/(x^d+1)`, sparse challenges,
  the Feistel/FPE carrier, extraction, link tags, epoch/Merkle roots.
  Modes: `normal`, `B(fpe)`, `B'(salt)`, `lsb` (control).
- `enroll.py` — enrollment and key distribution: KEM encapsulation to derive
  `dk_i`, context binding, organization signature over the epoch root.
- `dual_regev.py` — real dual-Regev encryption (CPA) used to measure the
  anonymous carrier.
- `td_demo.py` — MP12 gadget trapdoor and decoding; randomness recovery.
- `run_experiments.py` — size, distribution, extraction, linkability, epoch.
- `bench_py.py` — Python timings (median of 60 runs) → `results/py_bench.json`.
- `c_sign.py` — ctypes driver for the C port (`c/veil_sign.c`), including
  kernel self-test, Merkle root check, extraction and linking.
- `probe_fix.json` / `plot_anon.py` (in `../figures`) — signer-probe
  before/after the mask-box fix.

## Parameters

Ring core: `d=256, k=3, l=4, q=2^23-2^13+1, eta=1, tau=39, t=19`.
`k<l` is required: with `k>=l` the public key `t=A s` determines `s` by
elimination, while `k<l` leaves a coset of the 256-dimensional kernel and
recovering a short element is an MSIS instance (n=768, m=1024, bound 2^19).

Dual Regev: `n=256, m=1024, q=2^23-2^13+1`, errors and noise in {-1,0,1}.

**This is not a production parameter set.** The ring-layer MSIS instance is
estimated at about 145 bits; the embedding and the anonymous carrier are
not tied to a target level, and no side-channel hardening is attempted.

## Results (n=4, attributable mode)

| Quantity | Value |
|---|---|
| Signature size | 9760 B (identical to a regular signature) |
| Extract | payload + signer index, 300/300 |
| Python sign / verify / extract | 2.2 / 1.6 / 1.9 ms |
| C sign / verify / extract | 0.32 / 0.10 / 0.24 ms |
| Salted variant | 9824 B (+64) |
| Anonymous, square carrier | 12835 B (+3075) |
| Anonymous, with trapdoor | 18186 B (+8426) |

Probe accuracy with the corrected mask box: 0.241 / 0.250 / 0.248 / 0.255
for `t = 18, 19, 20, 21` (chance 0.25, s.e. 0.014). Mask rejection:
26% / 14% / 7% / 4%.

## Running

```
python bench_py.py
python c_sign.py --reps 60        # needs the shared library, see ../REPRODUCE.md
```

The C port is built from `../c/veil_sign.c`; `c_sign.py` looks for the
library via `VEIL_LIB`, then a local build, then compiles it with the gcc on
`PATH` (or `VEIL_MINGW` on Windows).
