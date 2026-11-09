# VEIL

Reference implementation, experiment scripts, and symbolic models for the paper

> **Hiding Messages in Decoy Responses: Size-Preserving Post-Quantum Anamorphic Ring Signatures**

The repository reproduces every number in the paper: signature sizes, the
distributional tests, extraction and robustness experiments, the MP12 trapdoor
measurement, the Fujisaki--Okamoto negative result, the ML-KEM/ML-DSA enrollment
flow, the agent-workflow simulation, and the ProVerif models.

## Layout

| Path | Contents |
|---|---|
| `prototype/veil_core.py` | ring core: NTT, sparse challenges, FPE, the three modes, linking, epoch root |
| `prototype/eval_full.py` | E1--E5: size equality, detector, extraction, robustness, linking |
| `prototype/dual_regev.py` | real CPA dual Regev, used to calibrate the anonymous carrier |
| `prototype/td_demo.py` | MP12 trapdoor + gadget decoding (randomness recovery) |
| `prototype/cca_demo.py` | multi-bit KEM + FO; shows that FO rejects the anamorphic ciphertext |
| `prototype/enroll.py` | enrollment with ML-KEM-768 and ML-DSA-65 (falls back to X25519/RSA) |
| `prototype/mcp_demo.py` | agent workflow under three connection topologies |
| `prototype/c_kernels.py` | ctypes binding and benchmark for the C kernel |
| `c/` | C NTT and sparse multiplication, plus the constant generator |
| `proverif/` | symbolic models of the enrollment protocol (honest and compromised) |
| `figures/` | scripts for Figures 1--5 |
| `REPRODUCE.md` | environment, commands, expected values, caveats |

## Requirements

```
pip install numpy matplotlib pillow pqcrypto "fonttools==4.51.0"
```

`fonttools` is pinned because newer builds fail to load in some Windows runtimes,
which breaks the PDF backend of matplotlib. ProVerif and TeX Live are optional.

## Quick start

```
python reproduce.py            # everything that is installed
python reproduce.py --skip-tex # experiments only
```

See `REPRODUCE.md` for the full command list and the mapping from paper numbers
to scripts.

## Headline results

| Quantity | Value |
|---|---|
| regular / attributable signature, n=4 | 9760 B (identical) |
| salted variant | 9824 B (+64) |
| anonymous mode (ring + measured ciphertext) | 12835 B (+3075) |
| anonymous mode with MP12 trapdoor | 8426 B carrier (7.3x bytes, 13.5x coefficients) |
| chi-square, attributable / regular / naive LSB | 239.1 / 257.3 / 5891 |
| detector AUC, attributable / naive LSB | 0.519 / 0.972 |
| extraction | 300/300 |
| signer probe, t=19 vs chance | 0.30 vs 0.25 |
| enrollment | 1088 B ciphertext, 3309 B ML-DSA signature |
| agent workflow | 34 KB log, cryptography 16--24 ms |

## Caveats

- The parameters are chosen for mechanics, not for a security level; see the
  parameter-guidance paragraph of the paper.
- The ring prototype appends a 1088-byte structural stand-in for the anonymous
  carrier; the 12835-byte figure combines the ring with the separately measured
  3075-byte ciphertext.
- The trapdoor and CCA experiments use their own parameters and demonstrate
  mechanisms, not security levels.
- The agent workflow simulates the transport and tool latency; no language model
  is invoked.

## License

MIT; see `LICENSE`.
