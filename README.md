# VEIL

Reference implementation, experiment scripts, lattice estimates, and symbolic models for the paper

> **Hiding Messages in Decoy Responses: Size-Preserving Post-Quantum Anamorphic Ring Signatures**

The repository reproduces every number in the paper: signature sizes, the
distributional tests, extraction and robustness experiments, the signer probe,
the MP12 trapdoor measurement, the Fujisaki--Okamoto negative result, the
ML-KEM/ML-DSA enrollment flow, the agent-workflow simulation, the C signer, the
MSIS estimate, and the ProVerif models.

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
| `prototype/bench_py.py` | Python timings for Table V (`results/py_bench.json`) |
| `prototype/c_sign.py` | ctypes binding for the C signer: self-test, extraction, linking, timings |
| `c/veil_sign.c` | full C signer/verifier: NTT, SHAKE-256, Feistel FPE, extract, link, Merkle root |
| `c/veil_kernels.c` | standalone NTT and sparse multiplication kernel |
| `estimator/` | lattice-estimator (SageMath) scripts for the MSIS instance of the ring layer |
| `proverif/` | symbolic models of the enrollment protocol (honest and compromised) |
| `figures/` | plotting scripts: sizes, chi-square, probe, C-vs-Python cost, detector AUC |
| `REPRODUCE.md` | environment, commands, expected values, caveats |

## Requirements

```
pip install numpy matplotlib pillow pqcrypto "fonttools==4.51.0"
```

`fonttools` is pinned because newer builds fail to load in some Windows runtimes,
which breaks the PDF backend of matplotlib.

The C signer needs `libcrypto` (OpenSSL 3). On Linux:

```
gcc -O3 -shared -fPIC -o /tmp/veil_sign.so c/veil_sign.c -I c -lcrypto
python3 prototype/c_sign.py --reps 60
```

The MSIS estimates need SageMath; `estimator/README.md` gives the Miniforge
recipe. ProVerif and TeX Live are optional.

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
| anonymous mode with MP12 trapdoor | 18186 B (8426 B carrier) |
| chi-square, attributable / regular / naive LSB | 239.1 / 257.3 / 5891 |
| detector AUC, attributable / naive LSB | 0.519 / 0.972 |
| extraction | 300/300 |
| signer probe, t=19 vs chance (enlarged mask) | 0.250 vs 0.25 |
| signer probe, t=19 (shrunk-mask ablation) | 0.277 |
| MSIS estimate, k=3, t=19 | 144.9 bit (Dilithium2: 152.2 bit) |
| Python sign / verify / extract, n=4 | 2.2 / 1.6 / 1.9 ms |
| C sign / verify / extract, n=4 | 0.36 / 0.10 / 0.24 ms |
| C sign / verify / extract, n=16 | 1.61 / 0.41 / 1.02 ms |
| enrollment | 1088 B ciphertext, 3309 B ML-DSA signature |
| agent workflow | 34 KB log, cryptography 16--24 ms |

## Parameters

`d=256`, `k=3`, `l=4`, `q=2^23-2^13+1`, `eta=1`, `tau=39`, `t=19`.
The matrix `A` is `k x l` with `k < l`, so `t = A s` leaves a 256-dimensional
kernel and recovering the short `s` is MSIS; see the parameter-guidance
paragraph of the paper. With `k >= l` the public key would determine the secret
by linear algebra, so the asymmetry is required, not cosmetic.

## C signer

```
cd c
gcc -O3 -shared -fPIC -o /tmp/veil_sign.so veil_sign.c -I . -lcrypto
cd ../prototype
python c_sign.py --reps 60
```

On managed Windows environments an application-control policy blocks freshly
built DLLs; run the same commands under WSL. `c_sign.py` compiles `.dll` on
Windows and `.so` on Linux and loads whichever it finds.

## Caveats

- The ring layer is estimated at about 145 bits for its MSIS instance, but the
  embedding and the anonymous carrier are not tied to a target level.
- The ring prototype appends a 1088-byte structural stand-in for the anonymous
  carrier; the 12835-byte figure combines the ring with the separately measured
  3075-byte ciphertext.
- The trapdoor and CCA experiments use their own parameters and demonstrate
  mechanisms, not security levels.
- The agent workflow simulates the transport and tool latency; no language model
  is invoked.
- `extract` and `link` are implemented in both Python and C; the salt and
  anonymous carriers remain Python-only.

## License

MIT; see `LICENSE`.
