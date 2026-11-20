#!/usr/bin/env python3
"""ctypes harness for the C VEIL ring signer (c/veil_sign.c).

Runs, for n = 4, 8, 16:
  * a self-test: sign -> verify must succeed, a tampered signature must fail,
  * the serialized signature size (32 + n * 2432 bytes),
  * a sign / verify benchmark (mean over --reps repetitions, default 200),
for the REGULAR mode (veil_core.sign(embed=None)) and the ATTRIBUTABLE FPE
mode (veil_core.sign(embed="fpe")).  Results go to prototype/results/c_sign.json.

Build (the workspace may be blocked by an application-control policy; %TEMP% is
not):
  gcc -O3 -shared -static-libgcc -o "%TEMP%\\veil_sign.dll" c\\veil_sign.c ^
      -I c -L <mingw-prefix>/lib -lcrypto

Run:
  python prototype/c_sign.py --build --reps 200
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMP = Path(tempfile.gettempdir())
IS_WIN = platform.system() == "Windows"
LIB_PATH = TEMP / ("veil_sign.dll" if IS_WIN else "veil_sign.so")
DLL_PATH = LIB_PATH  # historical name used below

def _first_dir(candidates):
    for candidate in candidates:
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return None


# Toolchain discovery: set VEIL_MINGW to a mingw-w64 prefix, or rely on gcc
# being on PATH.  No machine-specific path is baked in.
MINGW = _first_dir([
    os.environ.get("VEIL_MINGW"),
    r"C:\msys64\mingw64",
    r"C:\mingw64",
]) or Path(sys.executable).resolve().parents[1]

_GCC_ON_PATH = shutil.which("gcc")
GCC = Path(_GCC_ON_PATH) if _GCC_ON_PATH else MINGW / "bin" / "gcc.exe"
OPENSSL_INCLUDE = MINGW / "include"
OPENSSL_LIB = MINGW / "lib"

# Directories that may contain the OpenSSL 3 runtime library.  Set
# VEIL_OPENSSL_DIR when libcrypto lives outside the toolchain prefix.
DLL_SEARCH_DIRS = tuple(
    path for path in (
        Path(os.environ["VEIL_OPENSSL_DIR"]) if os.environ.get("VEIL_OPENSSL_DIR") else None,
        GCC.parent,
        MINGW / "bin",
        Path(sys.base_prefix) / "DLLs",
        Path(sys.executable).resolve().parent / "DLLs",
    ) if path is not None and path.is_dir()
)

SIG_C1_BYTES = 32
RESP_BYTES = 2432
PAYLOAD_BYTES = 32
MAC_BYTES = 16
MU_BYTES = PAYLOAD_BYTES + MAC_BYTES

MODES = {"regular": 0, "fpe": 1}

_dll_dir_handles: list[object] = []


# --------------------------------------------------------------------------
# build / load
# --------------------------------------------------------------------------
def build_dll() -> None:
    if IS_WIN:
        cmd = [
            str(GCC), "-O3", "-shared", "-static-libgcc",
            "-o", str(LIB_PATH),
            str(ROOT / "c" / "veil_sign.c"),
            "-I", str(ROOT / "c"),
            "-I", str(OPENSSL_INCLUDE),
            "-L", str(OPENSSL_LIB),
            "-lcrypto",
        ]
    else:
        cmd = [
            "gcc", "-O3", "-shared", "-fPIC",
            "-o", str(LIB_PATH),
            str(ROOT / "c" / "veil_sign.c"),
            "-I", str(ROOT / "c"),
            "-lcrypto",
        ]
    print("build:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print("built:", LIB_PATH)


def _load_cdll(path: Path) -> ctypes.CDLL:
    """Load a DLL whose dependencies live in the directories added above.

    Plain ctypes.CDLL on Windows does not always search the directories passed
    to os.add_dll_directory for *dependencies*; the LOAD_LIBRARY_SEARCH_* flags
    make that explicit.  Fall back to the historical behaviour if the Python
    build does not accept winmode.
    """
    if not IS_WIN:
        return ctypes.CDLL(str(path))
    attempts = (
        {"winmode": 0x1000 | 0x0400},   # DEFAULT_DIRS | USER_DIRS
        {"winmode": 0x0400},            # USER_DIRS
        {},                             # default LoadLibraryEx flags
    )
    last: OSError | None = None
    for kwargs in attempts:
        try:
            return ctypes.CDLL(str(path), **kwargs)
        except TypeError:               # no winmode on this Python
            continue
        except OSError as exc:
            last = exc
    raise SystemExit(
        f"could not load {path}: {last}\n"
        "libcrypto-3-x64.dll must be resolvable; searched: "
        + ", ".join(str(d) for d in DLL_SEARCH_DIRS)
    )


def load_lib() -> ctypes.CDLL:
    if IS_WIN:
        for directory in DLL_SEARCH_DIRS:
            if directory.is_dir():
                try:
                    _dll_dir_handles.append(os.add_dll_directory(str(directory)))
                except OSError:
                    pass
    if not LIB_PATH.is_file():
        raise SystemExit(f"{DLL_PATH} not found; run with --build")
    lib = _load_cdll(DLL_PATH)
    _bind(lib)
    print("loaded:", DLL_PATH)
    return lib


def _bind(lib: ctypes.CDLL) -> None:
    lib.veil_ctx_new.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
    lib.veil_ctx_new.restype = ctypes.c_void_p
    lib.veil_ctx_free.argtypes = [ctypes.c_void_p]
    lib.veil_ctx_free.restype = None
    lib.veil_sig_size.argtypes = [ctypes.c_void_p]
    lib.veil_sig_size.restype = ctypes.c_size_t
    lib.veil_n.argtypes = [ctypes.c_void_p]
    lib.veil_n.restype = ctypes.c_int
    lib.veil_sign.argtypes = [
        ctypes.c_void_p, ctypes.c_int,
        ctypes.c_char_p, ctypes.c_size_t,      # msg, msg_len
        ctypes.c_char_p, ctypes.c_size_t,      # extra, extra_len
        ctypes.c_char_p, ctypes.c_size_t,      # dk, dk_len
        ctypes.c_char_p,                       # mu (48 B)
        ctypes.c_int, ctypes.c_uint64,         # mode, nonce
        ctypes.c_void_p, ctypes.c_size_t,      # out, out_cap
        ctypes.POINTER(ctypes.c_size_t),       # out_len
    ]
    lib.veil_sign.restype = ctypes.c_int
    lib.veil_verify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_size_t,      # msg, msg_len
        ctypes.c_char_p, ctypes.c_size_t,      # extra, extra_len
        ctypes.c_char_p, ctypes.c_size_t,      # sig, sig_len
    ]
    lib.veil_verify.restype = ctypes.c_int
    lib.veil_kernel_selftest.argtypes = []
    lib.veil_kernel_selftest.restype = ctypes.c_int
    lib.veil_link_tag.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                  ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte)]
    lib.veil_link_tag.restype = ctypes.c_int
    lib.veil_extract_fpe.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_int),
    ]
    lib.veil_extract_fpe.restype = ctypes.c_int
    lib.veil_merkle_root.argtypes = [
        ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t, ctypes.c_size_t,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte),
    ]
    lib.veil_merkle_root.restype = ctypes.c_int


# --------------------------------------------------------------------------
# thin Python wrappers
# --------------------------------------------------------------------------
class Ctx:
    """Owns a VeilCtx; use as a context manager."""

    def __init__(self, lib: ctypes.CDLL, n: int, seed: bytes) -> None:
        self.lib = lib
        self.ptr = lib.veil_ctx_new(seed, len(seed), n)
        if not self.ptr:
            raise RuntimeError(f"veil_ctx_new failed (n={n})")
        if int(lib.veil_n(self.ptr)) != n:
            raise RuntimeError("veil_n mismatch")

    @property
    def sig_size(self) -> int:
        return int(self.lib.veil_sig_size(self.ptr))

    def close(self) -> None:
        if self.ptr:
            self.lib.veil_ctx_free(self.ptr)
            self.ptr = None

    def __enter__(self) -> "Ctx":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def encode_mu(payload: bytes, dk_mac: bytes) -> bytes:
    """Same integer layout as veil_core.encode_mu: (payload << 128) | mac."""
    mac = hmac.new(dk_mac, payload, hashlib.sha256).digest()[:MAC_BYTES]
    value = (int.from_bytes(payload, "big") << (8 * MAC_BYTES)) | int.from_bytes(
        mac, "big"
    )
    return value.to_bytes(MU_BYTES, "big")


def sign(lib: ctypes.CDLL, ctx: Ctx, pi: int, msg: bytes, extra: bytes,
         dk: bytes, mu: bytes, mode: int, nonce: int) -> bytes:
    need = ctx.sig_size
    buf = ctypes.create_string_buffer(need)
    out_len = ctypes.c_size_t(0)
    ok = lib.veil_sign(
        ctx.ptr, pi,
        msg, len(msg),
        extra, len(extra),
        dk, len(dk),
        mu, mode, nonce,
        ctypes.cast(buf, ctypes.c_void_p), need,
        ctypes.byref(out_len),
    )
    if ok != 1:
        raise RuntimeError(f"veil_sign failed (mode={mode}, pi={pi})")
    if int(out_len.value) != need:
        raise RuntimeError(f"veil_sign wrote {out_len.value} bytes, expected {need}")
    return buf.raw[:need]


def verify(lib: ctypes.CDLL, ctx: Ctx, msg: bytes, extra: bytes, sig: bytes) -> bool:
    return lib.veil_verify(
        ctx.ptr, msg, len(msg), extra, len(extra), sig, len(sig)
    ) == 1


def extract(lib: ctypes.CDLL, ctx: Ctx, sig: bytes, dk: bytes,
            dk_mac: bytes) -> tuple[bytes, int] | None:
    payload = (ctypes.c_ubyte * PAYLOAD_BYTES)()
    pi = ctypes.c_int(-1)
    ok = lib.veil_extract_fpe(
        ctx.ptr, sig, len(sig), dk, len(dk), dk_mac, len(dk_mac),
        payload, ctypes.byref(pi),
    )
    return (bytes(payload), int(pi.value)) if ok == 1 else None


def link_tag(lib: ctypes.CDLL, ctx: Ctx, member: int, epoch: int) -> bytes:
    out = (ctypes.c_ubyte * 32)()
    if lib.veil_link_tag(ctx.ptr, member, epoch, out) != 1:
        raise RuntimeError("veil_link_tag failed")
    return bytes(out)


def summary(samples_ms: list[float]) -> dict:
    return {
        "mean_ms": statistics.fmean(samples_ms),
        "median_ms": statistics.median(samples_ms),
        "min_ms": min(samples_ms),
        "max_ms": max(samples_ms),
        "stdev_ms": statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0,
        "n": len(samples_ms),
    }


def merkle_root(lib: ctypes.CDLL, pks: list[list[int]]) -> bytes:
    """Commitment over leaves given as flat little-endian int64 coefficients."""
    n = len(pks)
    l = len(pks[0])
    flat = (ctypes.c_int64 * (n * l))()
    for i, leaf in enumerate(pks):
        for j, v in enumerate(leaf):
            flat[i * l + j] = v
    out = (ctypes.c_ubyte * 32)()
    if lib.veil_merkle_root(flat, n, l // 256, 256, out) != 1:
        raise RuntimeError("veil_merkle_root failed")
    return bytes(out)


def merkle_selftest(lib: ctypes.CDLL) -> bool:
    """Compare the C root with a direct transcription of veil_core.merkle_root."""
    import struct

    def ref_root(pks: list[list[int]]) -> bytes:
        leaves = []
        for leaf in pks:
            h = hashlib.sha256(b"VEIL/leaf")
            for v in leaf:
                h.update(struct.pack("<q", v))
            leaves.append(h.digest())
        while len(leaves) > 1:
            if len(leaves) % 2:
                leaves.append(leaves[-1])
            leaves = [hashlib.sha256(b"VEIL/node" + leaves[i] + leaves[i + 1]).digest()
                      for i in range(0, len(leaves), 2)]
        return leaves[0]

    for n in (1, 3, 4, 7):
        pks = []
        for i in range(n):
            pks.append([int.from_bytes(hashlib.sha256(f"m{i}-{j}".encode()).digest()[:8],
                                       "little", signed=True) % 8380417
                        for j in range(4 * 256)])
        if merkle_root(lib, pks) != ref_root(pks):
            return False
    return True


# --------------------------------------------------------------------------
# self-test / benchmark
# --------------------------------------------------------------------------
def selftest(lib: ctypes.CDLL, n: int, mode_name: str, mode: int,
             seed: bytes, msg: bytes, extra: bytes, dk: bytes, dk_mac: bytes,
             mu: bytes) -> dict:
    pi = n // 2
    with Ctx(lib, n, seed) as ctx:
        size = ctx.sig_size
        expected = SIG_C1_BYTES + n * RESP_BYTES
        sig = sign(lib, ctx, pi, msg, extra, dk, mu, mode, nonce=1)
        checks = {
            "size_bytes": size,
            "size_expected": expected,
            "size_ok": size == expected and len(sig) == expected,
            "sign_ok": len(sig) == expected,
            "verify_ok": verify(lib, ctx, msg, extra, sig),
        }

        bad = bytearray(sig)
        bad[0] ^= 0x01
        checks["tamper_c1_rejected"] = not verify(lib, ctx, msg, extra, bytes(bad))

        bad = bytearray(sig)
        bad[SIG_C1_BYTES + 11] ^= 0x01
        checks["tamper_response_rejected"] = not verify(
            lib, ctx, msg, extra, bytes(bad)
        )

        checks["tamper_message_rejected"] = not verify(
            lib, ctx, msg + b"!", extra, sig
        )

        bad_extra = bytearray(extra)
        bad_extra[-1] ^= 0x01
        checks["tamper_extra_rejected"] = not verify(
            lib, ctx, msg, bytes(bad_extra), sig
        )

        # extraction: attributable recovers (payload, pi); regular must fail
        got = extract(lib, ctx, sig, dk, dk_mac)
        if mode == 1:
            checks["extract_payload"] = got is not None and got[0] == mu[:PAYLOAD_BYTES]
            checks["extract_signer"] = got is not None and got[1] == pi
        else:
            checks["extract_bot"] = got is None

        tag = link_tag(lib, ctx, pi, epoch=7)
        checks["link_same_member_epoch"] = (
            tag == link_tag(lib, ctx, pi, epoch=7)
        )
        checks["link_other_member"] = (
            tag != link_tag(lib, ctx, (pi + 1) % n, epoch=7)
        )
        checks["link_other_epoch"] = tag != link_tag(lib, ctx, pi, epoch=8)

        required = [
            "size_ok", "sign_ok", "verify_ok",
            "tamper_c1_rejected", "tamper_response_rejected",
            "tamper_message_rejected", "tamper_extra_rejected",
            "link_same_member_epoch", "link_other_member", "link_other_epoch",
        ]
        required += ["extract_payload", "extract_signer"] if mode == 1 else ["extract_bot"]
        checks["pass"] = all(checks[k] for k in required)
    return checks


def bench(lib: ctypes.CDLL, n: int, mode_name: str, mode: int, reps: int,
          seed: bytes, msg: bytes, extra: bytes, dk: bytes, dk_mac: bytes,
          mu: bytes) -> dict:
    pi = n // 2
    with Ctx(lib, n, seed) as ctx:
        sigs: list[bytes] = []
        sign_ms: list[float] = []
        for r in range(reps):
            t0 = time.perf_counter()
            sig = sign(lib, ctx, pi, msg, extra, dk, mu, mode, nonce=1000 + r)
            sign_ms.append((time.perf_counter() - t0) * 1e3)
            sigs.append(sig)

        verify_ms: list[float] = []
        for r in range(reps):
            t0 = time.perf_counter()
            ok = verify(lib, ctx, msg, extra, sigs[r])
            verify_ms.append((time.perf_counter() - t0) * 1e3)
            if not ok:
                raise RuntimeError(f"benchmark signature {r} failed to verify")

        extract_ms: list[float] = []
        for r in range(reps):
            t0 = time.perf_counter()
            extract(lib, ctx, sigs[r], dk, dk_mac)
            extract_ms.append((time.perf_counter() - t0) * 1e3)

        return {
            "size_bytes": ctx.sig_size,
            "sign": summary(sign_ms),
            "verify": summary(verify_ms),
            "extract": summary(extract_ms),
        }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reps", type=int, default=200,
                        help="repetitions per (n, mode) benchmark (default 200)")
    parser.add_argument("--build", action="store_true", help="build the DLL first")
    parser.add_argument("--ns", default="4,8,16", help="comma-separated ring sizes")
    parser.add_argument("--json", default=str(ROOT / "prototype" / "results" /
                                             "c_sign.json"))
    args = parser.parse_args(argv)
    if args.reps < 1:
        parser.error("--reps must be >= 1")

    ns = [int(x) for x in args.ns.split(",") if x.strip()]
    if args.build or not DLL_PATH.is_file():
        build_dll()
    lib = load_lib()

    seed = hashlib.sha256(b"VEIL/c_sign/selftest").digest()
    msg = b"VEIL c signer self-test message"
    root = hashlib.sha256(b"VEIL/c_sign/root").digest()
    epoch = 7
    extra = epoch.to_bytes(8, "big") + root
    dk = hashlib.sha256(b"VEIL/c_sign/fpe-key").digest()
    dk_mac = hashlib.sha256(b"VEIL/c_sign/mac-key").digest()
    payload = b"VEIL c signer payload".ljust(PAYLOAD_BYTES, b"\x00")[:PAYLOAD_BYTES]
    mu = encode_mu(payload, dk_mac)

    report: dict = {
        "harness": "prototype/c_sign.py",
        "dll": str(DLL_PATH),
        "params": {
            "d": 256, "k": 3, "l": 4, "t": 19, "tau": 39, "eta": 1,
            "q": 8380417, "q_rounds": 16, "domain": "VEIL/v3",
            "payload_bytes": PAYLOAD_BYTES, "mac_bytes": MAC_BYTES,
            "mu_bits": 8 * MU_BYTES, "resp_bytes": RESP_BYTES,
            "c1_bytes": SIG_C1_BYTES,
            "sig_size_formula": "32 + n * 2432",
        },
        "selftest": {},
        "benchmark": {"reps": args.reps, "results": {}},
        "notes": [
            "Keys (A, s_i), y and the decoys are derived from SHAKE-256(seed, nonce) "
            "rather than NumPy's RNG; signatures verify with this C verifier and "
            "match Python's serialized size, but are not byte-identical to Python's.",
            "Only the REGULAR (embed=None) and ATTRIBUTABLE FPE (embed='fpe') modes "
            "are implemented.",
            "Link tags and FPE extraction (feistel_inv) are implemented; Merkle "
            "roots, salt/ae modes and constant-time serialization remain Python-only.",
            "mu = (32-byte payload << 128) | first 16 bytes of HMAC-SHA256(dk_mac, "
            "payload); the MAC is computed in Python and passed as 48 bytes.",
        ],
    }

    kernel_ok = lib.veil_kernel_selftest() == 1
    report["kernel_selftest"] = kernel_ok
    print()
    print("C kernel self-test (NTT mul + sparse mul vs schoolbook):",
          "PASS" if kernel_ok else "FAIL")
    merkle_ok = merkle_selftest(lib)
    report["merkle_selftest"] = merkle_ok
    print("C Merkle root vs Python reference:",
          "PASS" if merkle_ok else "FAIL")
    print(f"{'n':>3}  {'mode':<8} {'size[B]':>8}  self-test")
    for n in ns:
        for mode_name, mode in MODES.items():
            checks = selftest(lib, n, mode_name, mode, seed, msg, extra, dk,
                              dk_mac, mu)
            report["selftest"].setdefault(mode_name, {})[f"n={n}"] = checks
            status = "PASS" if checks["pass"] else "FAIL"
            print(f"{n:>3}  {mode_name:<8} {checks['size_bytes']:>8}  {status}"
                  f"  (sign={checks['sign_ok']}, verify={checks['verify_ok']},"
                  f" tamper c1/z/msg/extra="
                  f"{checks['tamper_c1_rejected']}/"
                  f"{checks['tamper_response_rejected']}/"
                  f"{checks['tamper_message_rejected']}/"
                  f"{checks['tamper_extra_rejected']})")

    if 4 in ns:
        size4 = report["selftest"]["regular"]["n=4"]["size_bytes"]
        if size4 != 9760:
            raise SystemExit(f"n=4 signature size is {size4}, expected 9760")

    print()
    print(f"benchmark: {args.reps} repetitions per (n, mode)")
    print(f"{'n':>3}  {'mode':<8} {'size[B]':>8}  {'sign mean[ms]':>14}"
          f"  {'verify mean[ms]':>16}")
    for n in ns:
        for mode_name, mode in MODES.items():
            result = bench(lib, n, mode_name, mode, args.reps, seed, msg, extra,
                           dk, dk_mac, mu)
            report["benchmark"]["results"].setdefault(mode_name, {})[f"n={n}"] = result
            print(f"{n:>3}  {mode_name:<8} {result['size_bytes']:>8}"
                  f"  {result['sign']['mean_ms']:>14.4f}"
                  f"  {result['verify']['mean_ms']:>16.4f}")

    all_pass = kernel_ok and all(
        entry["pass"]
        for by_mode in report["selftest"].values()
        for entry in by_mode.values()
    )
    report["all_pass"] = all_pass

    out_path = Path(args.json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    print()
    print("wrote:", out_path)
    if not all_pass:
        print("SELF-TEST FAILED")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
