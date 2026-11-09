"""Generate a multi-page draw.io sketch of the paper's figures.

Run:  python make_figures.py
Out:  veil-figures.drawio  (open with draw.io / diagrams.net)

These are layout sketches, not final art: boxes, labels and arrows only, so
they can be restyled (colours, fonts, icons) without moving anything.
"""

from __future__ import annotations

import html
import xml.etree.ElementTree as ET
from pathlib import Path

W, H = 1169, 827

FILL = {
    "org": "#dae8fc",
    "agent": "#ffffff",
    "platform": "#f8cecc",
    "extractor": "#d5e8d4",
    "verifier": "#e1d5e7",
    "log": "#fff2cc",
    "hi": "#ffe6cc",
    "none": "none",
}


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def box(cid, x, y, w, h, label, fill="none", dashed=False, fs=12, bold=False,
        stroke="#333333", rounded=True):
    style = (f"rounded={1 if rounded else 0};whiteSpace=wrap;html=1;"
             f"fillColor={FILL.get(fill, fill)};strokeColor={stroke};fontSize={fs};")
    if dashed:
        style += "dashed=1;"
    if bold:
        style += "fontStyle=1;"
    return (f'<mxCell id="{cid}" value="{esc(label)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')


def text(cid, x, y, w, h, label, fs=13, bold=False, align="left"):
    style = f"text;html=1;align={align};verticalAlign=middle;fontSize={fs};"
    if bold:
        style += "fontStyle=1;"
    return (f'<mxCell id="{cid}" value="{esc(label)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')


def edge(cid, s, t, label="", dashed=False, color="#333333", fs=11,
         exit_x=None, exit_y=None, entry_x=None, entry_y=None):
    style = f"endArrow=classic;html=1;strokeColor={color};fontSize={fs};"
    if dashed:
        style += "dashed=1;"
    if exit_x is not None:
        style += f"exitX={exit_x};exitY={exit_y};"
    if entry_x is not None:
        style += f"entryX={entry_x};entryY={entry_y};"
    return (f'<mxCell id="{cid}" value="{esc(label)}" style="{style}" edge="1" parent="1" '
            f'source="{s}" target="{t}"><mxGeometry relative="1" as="geometry"/></mxCell>')


def page(pid, name, cells):
    body = "".join(cells)
    return (f'<diagram id="{pid}" name="{name}">'
            f'<mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" '
            f'tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
            f'pageWidth="{W}" pageHeight="{H}" math="0" shadow="0">'
            f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{body}</root>'
            f'</mxGraphModel></diagram>')


def fig_system():
    c = [text("s_t", 30, 18, 900, 30, "Fig. 1  System model and trust boundaries", 16, True)]
    c.append(box("s_org", 50, 90, 330, 360, "", "org", dashed=True))
    c.append(text("s_orgt", 60, 96, 300, 24, "Organization O (trust boundary)", 12, True))
    for i in range(4):
        c.append(box(f"s_a{i}", 80, 140 + i * 72, 250, 52,
                     f"Agent {i + 1}\\n(sk_{i + 1}, dk_{i + 1}, pk_{i + 1})", "agent"))
    c.append(box("s_p", 470, 140, 240, 130,
                 "Platform P\\nlogs every message\\nholds every sk\\nforbids encryption", "platform"))
    c.append(box("s_x", 810, 110, 250, 110,
                 "Extractor X\\nsk_X  ->  dk_i\\nB: learns (mu, pi)\\nA: learns mu only", "extractor"))
    c.append(box("s_v", 810, 280, 250, 100, "Verifier V\\npublic: checks sigma", "verifier"))
    c.append(box("s_log", 470, 430, 240, 110, "Transparency log\\n(rt, sigma_org, c_i)", "log"))
    c.append(edge("s_e1", "s_a1", "s_p", "sigma, m", exit_x=1, exit_y=0.5,
                  entry_x=0, entry_y=0.3))
    c.append(edge("s_e2", "s_p", "s_v", "sigma, m", exit_x=1, exit_y=0.5,
                  entry_x=0, entry_y=0.5))
    c.append(edge("s_e3", "s_a1", "s_x", "hidden payload (mu)", dashed=True,
                  exit_x=1, exit_y=0.7, entry_x=0, entry_y=0.8))
    c.append(edge("s_e4", "s_org", "s_log", "rt, sigma_org", exit_x=0.5, exit_y=1,
                  entry_x=0.5, entry_y=0))
    c.append(edge("s_e5", "s_log", "s_v", "rt, sigma_org", exit_x=1, exit_y=0.3,
                  entry_x=0, entry_y=0.8))
    c.append(text("s_t1", 470, 290, 240, 30, "T1: confiscate sk", 11, False, "center"))
    c.append(text("s_t2", 50, 470, 330, 30, "T2: infer internal structure", 11, False, "center"))
    c.append(text("s_t3", 810, 400, 250, 30, "T3: harvest now, decide later", 11, False, "center"))
    return c


def fig_ring():
    c = [text("r_t", 30, 18, 900, 30, "Fig. 2  Decoy ring signature: one signer, n-1 free responses", 16, True)]
    boxes = []
    for i in range(4):
        x = 60 + i * 270
        b = box(f"r_b{i}", x, 140, 220, 130,
                f"branch {i + 1}\\nw = A z - c t\\nz in B", "hi" if i == 1 else "agent")
        boxes.append(b)
        c.append(b)
    for i in range(3):
        c.append(edge(f"r_e{i}", f"r_b{i}", f"r_b{i + 1}", "c' = H(...)", exit_x=1, exit_y=0.5,
                      entry_x=0, entry_y=0.5))
    c.append(edge("r_e3", "r_b3", "r_b0", "close the chain", exit_x=0.5, exit_y=1,
                  entry_x=0.5, entry_y=1))
    c.append(text("r_f1", 60, 300, 1000, 30,
                  "signer pi = 2:  z_pi = y + c_pi * s_pi   (the only pinned response)", 13, True))
    c.append(text("r_f2", 60, 340, 1000, 30,
                  "decoys 1, 3, 4:  z_j is sampled freely, uniformly in the box B", 13, False))
    c.append(box("r_v", 330, 430, 500, 90,
                 "Verifier: replay every w_j and c_j, check z_j in B,\\nand that the chain closes at c_1",
                 "verifier"))
    c.append(edge("r_e4", "r_v", "r_b0", "replay", exit_x=0.2, exit_y=0, entry_x=0.5, entry_y=1))
    return c


def fig_carrier():
    c = [text("c_t", 30, 18, 1000, 30, "Fig. 3  Carrier location determines what the extractor learns", 16, True)]
    c.append(text("c_a", 40, 60, 900, 26, "(a) attributable mode: payload inside the decoys (0 bytes)", 13, True))
    for i in range(4):
        c.append(box(f"c_d{i}", 40 + i * 140, 100, 120, 70,
                     "pinned" if i == 1 else "FPE_dk(r || mu)",
                     "hi" if i == 1 else "extractor", fs=11))
    c.append(box("c_x1", 640, 95, 300, 90,
                 "Extractor X (dk)\\nmu  +  pi = the failing index", "extractor"))
    c.append(edge("c_e1", "c_d2", "c_x1", "decode", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5))

    c.append(text("c_b", 40, 260, 1000, 26, "(b) anonymous mode: payload in an independent component (bytes)", 13, True))
    c.append(box("c_s", 40, 310, 300, 110, "signature sigma\\n(unchanged, verifies publicly)", "agent"))
    c.append(box("c_ct", 380, 310, 260, 110, "ct = Enc(pk_X, s)\\n(payload in s)", "extractor"))
    c.append(box("c_x2", 700, 300, 260, 100, "Extractor X (td)\\nmu only", "extractor"))
    c.append(edge("c_e2", "c_ct", "c_x2", "recover s", exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5))
    c.append(text("c_note", 40, 460, 900, 60,
                  "A warden holding sk decrypts the cover and learns nothing about mu;\\n"
                  "the extractor holding dk (or td) learns mu, and in (a) also pi.", 12, False))
    return c


def fig_enroll():
    c = [text("e_t", 30, 18, 1000, 30, "Fig. 4  Enrollment and provisioning (Section V-D)", 16, True)]
    names = ["Agent i", "Organization O", "Log", "Extractor X"]
    xs = [80, 380, 660, 900]
    for i, (n, x) in enumerate(zip(names, xs)):
        c.append(box(f"e_l{i}", x, 70, 170, 50, n, "org" if i == 1 else
                     ("extractor" if i == 3 else "agent"), bold=True))
        c.append(box(f"e_b{i}", x + 80, 700, 2, 2, "", "none", rounded=False))
        c.append(edge(f"e_v{i}", f"e_l{i}", f"e_b{i}", "", dashed=True, color="#999999"))
    msgs = [
        (0, 1, 150, "pk_i, proof of possession"),
        (0, 2, 210, "c_i = Encap(pk_X)"),
        (1, 2, 270, "rt = Merkle(leaf_i), sigma_org"),
        (2, 3, 330, "c_i, rt, sigma_org"),
    ]
    for k, (s, t, y, label) in enumerate(msgs):
        c.append(text(f"e_m{k}", min(xs[s], xs[t]) + 40, y - 22, 300, 20, label, 11))
        c.append(edge(f"e_ek{k}", f"e_l{s}", f"e_l{t}", "", exit_y=0.5, entry_y=0.5))
    c.append(text("e_n1", 900, 380, 250, 50, "X checks sigma_org,\\nthen derives dk_i", 11))
    c.append(text("e_n2", 80, 380, 250, 50, "Agent signs with\\nthe derived dk_i", 11))
    c.append(text("e_n3", 80, 560, 1000, 60,
                  "Only c_i is public: the platform sees a KEM ciphertext, never dk_i.\\n"
                  "Bind oid || ep || i || pk_i into the KDF so a ciphertext cannot be transplanted.",
                  12, False))
    return c


def fig_topologies():
    c = [text("t_t", 30, 18, 1100, 30, "Fig. 5  Connection topology decides what the platform sees", 16, True)]
    panels = [
        ("T1: organizational gateway", 40, "gateway"),
        ("T2: organizational credential", 410, "credential"),
        ("T3: per-agent connections", 780, "direct"),
    ]
    for k, (title, x0, mode) in enumerate(panels):
        c.append(text(f"t_h{k}", x0, 55, 330, 24, title, 13, True))
        for i in range(3):
            c.append(box(f"t_a{k}{i}", x0 + 10, 90 + i * 42, 80, 32, f"agent {i + 1}", "agent", fs=10))
        c.append(box(f"t_p{k}", x0 + 235, 110, 80, 80, "platform", "platform", fs=10))
        if mode == "gateway":
            c.append(box(f"t_g{k}", x0 + 120, 96, 80, 108, "org\ngateway", "org", fs=10))
            for i in range(3):
                c.append(edge(f"t_e{k}{i}", f"t_a{k}{i}", f"t_g{k}", "", exit_x=1, exit_y=0.5,
                              entry_x=0, entry_y=0.5))
            c.append(edge(f"t_gp{k}", f"t_g{k}", f"t_p{k}", "one endpoint", exit_x=1, exit_y=0.5,
                          entry_x=0, entry_y=0.5))
            c.append(text(f"t_s{k}", x0, 225, 330, 40, "sees: the organization\n(agent id stripped)", 11))
        elif mode == "credential":
            for i in range(3):
                c.append(edge(f"t_e{k}{i}", f"t_a{k}{i}", f"t_p{k}", "org cred" if i == 1 else "",
                              fs=9, exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5))
            c.append(text(f"t_s{k}", x0, 225, 330, 44,
                          "sees: the tenant\n(distinct connections, org credential)", 11))
        else:
            for i in range(3):
                c.append(edge(f"t_e{k}{i}", f"t_a{k}{i}", f"t_p{k}", f"cred {i + 1}", fs=9,
                              exit_x=1, exit_y=0.5, entry_x=0, entry_y=0.5))
            c.append(text(f"t_s{k}", x0, 225, 330, 40, "sees: the agent\n(transport metadata)", 11))
    c.append(text("t_n", 40, 290, 1100, 50,
                  "The cryptographic layer is identical in all three: same keys, same signature size, same extraction.\n"
                  "The topology only sets the anonymity set and what the platform can correlate.", 12, False))
    return c


def fig_workflow():
    c = [text("w_t", 30, 18, 1100, 30, "Fig. 6  Agent workflow: the platform verifies, the auditor reads", 16, True)]
    names = ["Planner (A)", "Retriever (B)", "Executor (A)", "Platform log", "Auditor X"]
    xs = [60, 270, 480, 690, 920]
    for i, (n, x) in enumerate(zip(names, xs)):
        fill = "platform" if i == 3 else ("extractor" if i == 4 else "agent")
        c.append(box(f"w_l{i}", x, 70, 150, 44, n, fill, bold=True, fs=10))
        c.append(box(f"w_b{i}", x + 75, 560, 2, 2, "", "none", rounded=False))
        c.append(edge(f"w_v{i}", f"w_l{i}", f"w_b{i}", "", dashed=True, color="#999999"))
    msgs = [
        (0, 1, 140, "1  plan / fetch"),
        (1, 0, 180, "2  document"),
        (0, 2, 220, "3  action"),
        (2, 0, 260, "4  summary"),
        (2, 3, 300, "5  status (hidden payload)"),
        (3, 4, 340, "log"),
    ]
    for k, (s, t, y, label) in enumerate(msgs):
        c.append(text(f"w_m{k}", min(xs[s], xs[t]) + 30, y - 20, 280, 18, label, 10))
        c.append(edge(f"w_e{k}", f"w_l{s}", f"w_l{t}", "", exit_y=0.5, entry_y=0.5,
                      dashed=(k == 5)))
    c.append(text("w_n1", 60, 390, 900, 60,
                  "Platform: verifies all five, holds every signing key, extracts nothing.\n"
                  "Auditor: derives dk_i, recovers the payload and the signer index (1 of 3).", 11))
    return c


def main():
    pages = [
        page("p1", "1-system-model", fig_system()),
        page("p2", "2-ring-chain", fig_ring()),
        page("p3", "3-carrier-location", fig_carrier()),
        page("p4", "4-enrollment", fig_enroll()),
        page("p5", "5-topologies", fig_topologies()),
        page("p6", "6-agent-workflow", fig_workflow()),
    ]
    xml = ('<mxfile host="app.diagrams.net" agent="veil" version="24.7.17">'
           + "".join(pages) + "</mxfile>")
    out = Path(__file__).with_name("veil-figures.drawio")
    out.write_text(xml, encoding="utf-8")
    ET.fromstring(xml)          # well-formedness check
    print(f"wrote {out} ({len(xml)} bytes, {len(pages)} pages)")


if __name__ == "__main__":
    main()
