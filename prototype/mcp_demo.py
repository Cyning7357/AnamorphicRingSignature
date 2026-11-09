"""End-to-end agent workflow under two connection topologies.

Topology "gateway" (assumed in the paper):
    agents -> org gateway -> platform.  The gateway forwards only the org id,
    so the platform's log is org-level.

Topology "direct":
    agents -> platform, each agent with its own connection.  The platform
    knows the agent at the transport layer; the signature still hides the
    signer from third parties, and the hidden channel is unaffected.

The cryptographic layer is identical in both: the same keys, signatures and
extraction.  Only what the platform records differs, which is the point.

Run: python mcp_demo.py
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass

import numpy as np

import enroll as en
import veil_core as vc

EPOCH = 1
SIM_STEP_MS = 120
PAYLOAD = b"FLAG:clause-7-unusual".ljust(vc.Params().payload_bytes, b"\x00")

rng = np.random.default_rng(20261030)


@dataclass
class Org:
    name: str
    oid: bytes
    p: vc.Params
    keys: vc.Keys
    org_keys: en.OrgKeys
    entries: list
    c: dict
    dk: dict
    dk_mac: dict
    rt: bytes
    sigma: bytes

    def pk_bytes(self, i: int) -> bytes:
        return en.pk_bytes(self.keys.pks[i])

    def sign(self, pi: int, m: bytes, mu: int | None = None):
        kw = dict(embed=None, epoch=EPOCH, root=self.rt)
        if mu is not None:
            kw.update(embed="fpe", mu=mu, dk=self.dk[pi])
        t0 = time.perf_counter()
        sig = vc.sign(self.keys, pi, m, rng=rng, **kw)
        return sig, (time.perf_counter() - t0) * 1e3


@dataclass
class LogEntry:
    org: str
    m: bytes
    sig: object
    size: int
    sign_ms: float
    agent: int | None = None          # None when the gateway strips it
    connection: str | None = None     # transport connection id
    credential: str | None = None     # scope of the presented credential
    verify_ms: float = 0.0


class Platform:
    def __init__(self, topology: str):
        self.topology = topology
        self.log: list[LogEntry] = []
        self.verify_ok = 0
        self.verify_fail = 0

    def submit(self, org: Org, entry: LogEntry):
        if self.topology == "gateway":
            entry.connection = f"endpoint-{org.name}"
            entry.credential = "organization"
        elif self.topology == "credential":
            entry.connection = f"conn-{len(self.log)}"
            entry.credential = "organization"
        else:
            entry.connection = f"conn-{org.name}-{entry.agent}"
            entry.credential = f"organization+agent:{entry.agent}"

        t0 = time.perf_counter()
        ok = en.verify_header(org.org_keys, org.oid, EPOCH, org.rt, org.sigma) and \
            vc.verify(org.keys, entry.m, entry.sig, root=org.rt)
        entry.verify_ms = (time.perf_counter() - t0) * 1e3
        self.log.append(entry)
        self.verify_ok += int(ok)
        self.verify_fail += int(not ok)
        return ok

    def try_extract(self, orgs: dict) -> int:
        """Key seizure: the platform holds every signing key and still tries."""
        hits = 0
        for entry in self.log:
            org = orgs[entry.org]
            for sk in org.keys.sks:
                payload, _ = vc.extract_fpe(
                    org.keys, entry.sig,
                    hashlib.sha256(sk[0].tobytes()).digest(),
                    hashlib.sha256(b"mac").digest())
                if payload is not None:
                    hits += 1
        return hits


class Auditor:
    def __init__(self, X: en.ExtractorKeys):
        self.X = X

    def scan(self, org: Org, log: list[LogEntry]):
        for entry in log:
            if entry.org != org.name:
                continue
            for i in range(org.p.n):
                dk_i, dk_mac_i = en.derive(self.X.sk, org.oid, EPOCH, i,
                                           org.pk_bytes(i), org.c[i])
                payload, who = vc.extract_fpe(org.keys, entry.sig, dk_i, dk_mac_i)
                if payload is not None:
                    return entry, i, payload, who
        return None


def build_org(name: str, oid: bytes, n: int, X, r) -> Org:
    p = vc.Params(n=n, t=19)
    keys = vc.keygen(p, r)
    org_keys = en.org_keygen(512)
    c, dk, dk_mac, entries = {}, {}, {}, []
    for i in range(n):
        c[i], dk[i], dk_mac[i] = en.enroll(oid, EPOCH, i, en.pk_bytes(keys.pks[i]), X.pk)
        entries.append((i, en.pk_bytes(keys.pks[i]), c[i]))
    rt, sigma = en.publish(oid, EPOCH, entries, org_keys)
    return Org(name, oid, p, keys, org_keys, entries, c, dk, dk_mac, rt, sigma)


def run(topology: str) -> dict:
    global rng
    rng = np.random.default_rng(20261030)
    X = en.extractor_keygen(rng)
    A = build_org("OrgA", b"org-a", 3, X, rng)
    B = build_org("OrgB", b"org-b", 2, X, rng)
    orgs = {"OrgA": A, "OrgB": B}
    platform = Platform(topology)
    auditor = Auditor(X)

    planner, executor = 0, 1
    retriever = 1

    def send(org: Org, pi: int, m: bytes, mu: int | None = None):
        sig, t = org.sign(pi, m, mu)
        platform.submit(org, LogEntry(org.name, m, sig,
                                      len(vc.serialize(org.keys, sig)), t,
                                      agent=pi if topology == "direct" else None))

    t_task = time.perf_counter()
    send(A, planner, b'{"tool":"fetch","doc":"contract-X"}')
    time.sleep(SIM_STEP_MS / 1e3)
    send(B, retriever, b'{"doc":"contract-X","pages":12}')
    time.sleep(SIM_STEP_MS / 1e3)
    send(A, planner, b'{"action":"summarize","doc":"contract-X"}')
    time.sleep(SIM_STEP_MS / 1e3)
    send(A, executor, b'{"summary":"9 clauses","clauses":9}')
    time.sleep(SIM_STEP_MS / 1e3)
    mu = vc.encode_mu(A.p, A.dk_mac[executor], PAYLOAD)
    send(A, executor, b'{"status":"ok"}', mu=mu)
    wall = (time.perf_counter() - t_task) * 1e3

    crypto = sum(e.sign_ms + e.verify_ms for e in platform.log)
    hits = platform.try_extract(orgs)
    found = auditor.scan(A, platform.log)
    payload, who = (found[2], found[1]) if found else (None, None)

    return {
        "topology": topology,
        "messages": len(platform.log),
        "log_bytes": sum(e.size for e in platform.log),
        "mean_signature_bytes": float(np.mean([e.size for e in platform.log])),
        "platform": {
            "sees": {"gateway": "organization only (gateway strips the agent id)",
                     "credential": "organization credential on distinct connections",
                     "direct": "organization and agent id (transport metadata)"}[topology],
            "connections": len({e.connection for e in platform.log}),
            "credential_scope": "organization" if topology != "direct" else "organization+agent",
            "verified": platform.verify_ok,
            "failed": platform.verify_fail,
            "extraction_successes_with_all_sk": hits,
        },
        "auditor": {
            "extracted_payload": payload.rstrip(b"\x00").decode("latin1") if payload else None,
            "signer_index": who,
            "signer_org": "OrgA",
            "signer_matches_index": bool(found and who == found[1]),
        },
        "latency_ms": {
            "crypto": crypto,
            "simulated_steps": 4 * SIM_STEP_MS,
            "wall": wall,
            "crypto_share": crypto / wall,
        },
    }


def main():
    reports = {t: run(t) for t in ("gateway", "credential", "direct")}
    for t, r in reports.items():
        print(f"[{t}] messages={r['messages']} log={r['log_bytes']} B "
              f"connections={r['platform']['connections']} "
              f"cred={r['platform']['credential_scope']}")
        print(f"          verified={r['platform']['verified']} "
              f"extracted_with_all_sk={r['platform']['extraction_successes_with_all_sk']} "
              f"auditor={r['auditor']['extracted_payload']!r} signer={r['auditor']['signer_index']}")
        print(f"          crypto={r['latency_ms']['crypto']:.1f} ms "
              f"wall={r['latency_ms']['wall']:.1f} ms "
              f"share={r['latency_ms']['crypto_share']:.2%}")

    os.makedirs("results", exist_ok=True)
    with open("results/mcp.json", "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False)
    print("wrote results/mcp.json")


if __name__ == "__main__":
    main()
