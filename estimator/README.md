# MSIS estimate for the ring layer

The ring core publishes `A` of size `k x l` over `R_q` and `t_i = A s_i`. The
verification equation is exact, so the public key alone must not determine
`s_i`. This is why `k < l`: the solution set of `A s = t` is then a coset of the
kernel of `A`, and finding the short element is an MSIS instance.

The scripts use `lattice-estimator` (malb) on top of SageMath. Install once,
without root:

```
curl -L -o miniforge.sh https://mirrors.tuna.tsinghua.edu.cn/github-release/conda-forge/miniforge/LatestRelease/Miniforge3-Linux-x86_64.sh
bash miniforge.sh -b -p "$HOME/miniforge3"
"$HOME/miniforge3/bin/conda" config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge
"$HOME/miniforge3/bin/mamba" install -y sage

curl -L -o le.tar.gz https://codeload.github.com/malb/lattice-estimator/tar.gz/refs/heads/main
tar xzf le.tar.gz && mv lattice-estimator-main "$HOME/lattice-estimator"
```

Then:

```
cd estimator
~/miniforge3/bin/sage est_sis3.py     # k = 1..4 at t = 19, and t = 18..21 at k = 3
~/miniforge3/bin/sage calib.py        # Dilithium2_MSIS_WkUnf as a calibration point
```

`est_sis3.py` imports the estimator from `$HOME/lattice-estimator` and reports,
for `q = 2^23 - 2^13 + 1`, `d = 256`, `l = 4` and the infinity-norm bound
`2^t` implied by the acceptance test `z in B`:

| k | estimated bits |
|---|---|
| 1 | 42.5 |
| 2 | 72.4 |
| 3 | 144.9 |
| 4 | no solution (trivial kernel) |

At `k = 3`, `t = 18/19/20/21` gives 175.7 / 144.9 / 122.9 / 106.7 bits.
`calib.py` returns 152.2 bits for Dilithium2's MSIS instance under the same
model, so the 145-bit figure is comparable to a deployed parameter set rather
than an absolute claim.
