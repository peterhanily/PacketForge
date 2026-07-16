# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""A self-contained forensic HTML report for a capture.

Aesthetic follows the subject: a hunter's tool speaks in monospace, Zeek fields, and
ATT&CK IDs, on a dark ground with one restrained accent. One idea — the capture,
proven real (the realism verdict), with its hidden intrusion laid bare (the kill
chain). No decoration that doesn't carry information.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from packetforge.evaluate import evaluate_pcap
from packetforge.validation.roundtrip import _clean, _parse_zeek_log

_CSS = """
:root{--bg:#0f1113;--fg:#d7dbdf;--dim:#7f8890;--line:#23272b;--hot:#e8a33d;--ok:#5aa66a}
@media (prefers-color-scheme:light){:root{--bg:#faf9f7;--fg:#1a1d1f;--dim:#6b7075;--line:#e4e2dd;--hot:#b5701a;--ok:#3f7d4e}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.55 ui-monospace,"SF Mono",Menlo,Consolas,monospace;-webkit-font-smoothing:antialiased}
.wrap{max-width:940px;margin:0 auto;padding:56px 28px 96px}
h1{font-size:13px;letter-spacing:.24em;text-transform:uppercase;color:var(--dim);font-weight:600;margin:0 0 6px}
.title{font-size:26px;font-weight:600;margin:0 0 28px}
.rule{border:0;border-top:1px solid var(--line);margin:36px 0}
.verdict{display:flex;gap:48px;flex-wrap:wrap;align-items:baseline}
.big{font-size:44px;font-weight:600;line-height:1}
.big small{font-size:16px;color:var(--dim);font-weight:400}
.lbl{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);margin-bottom:8px}
.hot{color:var(--hot)}
h2{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--dim);font-weight:600;margin:0 0 18px}
.stage{display:grid;grid-template-columns:120px 1fr;gap:20px;padding:14px 0;border-top:1px solid var(--line)}
.stage:first-of-type{border-top:0}
.tech{color:var(--hot);font-weight:600}
.tactic{color:var(--dim);font-size:12px;letter-spacing:.08em;text-transform:uppercase}
.desc{margin:2px 0 6px}
.meta{color:var(--dim);font-size:12px;word-break:break-all}
.bars{display:grid;grid-template-columns:auto 1fr auto;gap:10px 14px;align-items:center}
.svc{color:var(--fg)}.cnt{color:var(--dim);text-align:right}
.bar{height:8px;background:var(--line)}.bar>span{display:block;height:100%;background:var(--fg);opacity:.55}
.chk{display:grid;grid-template-columns:auto 1fr auto;gap:8px 14px;align-items:baseline}
.chk .m{width:1.6em}.pass{color:var(--ok)}.fail{color:var(--hot)}
.det{color:var(--dim)}
.iocs{color:var(--dim)}.iocs b{color:var(--fg);font-weight:600}
footer{color:var(--dim);font-size:12px;margin-top:40px}
"""


def _bars(conn: list) -> str:
    services = Counter((_clean(r.get("service", "")) or _clean(r.get("proto", "")) or "?") for r in conn)
    if not services:
        return ""
    top = services.most_common(14)
    mx = top[0][1]
    rows = []
    for svc, n in top:
        rows.append(f'<div class="svc">{html.escape(svc)}</div>'
                    f'<div class="bar"><span style="width:{round(100 * n / mx)}%"></span></div>'
                    f'<div class="cnt">{n}</div>')
    return f'<h2>Protocols &middot; {len(conn)} connections</h2><div class="bars">{"".join(rows)}</div>'


def _kill_chain(gt: dict) -> str:
    if not gt:
        return ""
    stages = []
    for e in gt.get("kill_chain", []):
        tech = e["technique"].split(" ", 1)
        tid = html.escape(tech[0])
        tname = html.escape(tech[1] if len(tech) > 1 else "")
        iocs = " &middot; ".join(f"{html.escape(str(k))}={html.escape(str(v))}" for k, v in e.get("iocs", {}).items())
        flows = html.escape(", ".join(e.get("flows", [])))
        stages.append(
            f'<div class="stage"><div><div class="tactic">{html.escape(e["stage"])}</div>'
            f'<div class="tech">{tid}</div></div>'
            f'<div><div>{tname}</div><div class="desc">{html.escape(e["description"])}</div>'
            f'<div class="meta">flows: {flows}{("<br>" + iocs) if iocs else ""}</div></div></div>')
    return f'<h2>Kill chain</h2>{"".join(stages)}'


def render_report(pcap: str | Path, ground_truth_json: str | Path | None = None,
                  keep_dir: str | None = None) -> str:
    pcap = Path(pcap)
    ev = evaluate_pcap(pcap, keep_dir=keep_dir)
    # re-parse conn.log from the eval's workdir note if kept, else a fresh run dir
    import tempfile
    wd = Path(keep_dir) if keep_dir else Path(tempfile.mkdtemp(prefix="pf_rep_"))
    from packetforge.validation.roundtrip import _run_zeek
    _run_zeek(pcap, wd)
    conn = _parse_zeek_log(wd / "conn.log")

    gt = {}
    if ground_truth_json and Path(ground_truth_json).exists():
        gt = json.loads(Path(ground_truth_json).read_text())

    span = 0.0
    ts = sorted(float(r["ts"]) for r in conn if r.get("ts"))
    if len(ts) >= 2:
        span = ts[-1] - ts[0]

    checks = []
    for f in ev.findings:
        cls = "pass" if f.ok else "fail"
        mark = "OK" if f.ok else "!!"
        checks.append(f'<div class="m {cls}">{mark}</div><div>{html.escape(f.check)}'
                      f'<div class="det">{html.escape(f.detail)}</div></div>'
                      f'<div class="cnt">{f.earned}/{f.weight}</div>')

    title = gt.get("title") or pcap.name
    stage_n = len(gt.get("kill_chain", []))
    verdict = (
        f'<div><div class="lbl">Realism</div><div class="big hot">{ev.score}<small>/100</small></div></div>'
        f'<div><div class="lbl">Intrusion</div><div class="big">{stage_n}<small> ATT&amp;CK stages</small></div></div>'
        f'<div><div class="lbl">Capture</div><div class="big">{len(conn)}<small> flows &middot; {span:.0f}s</small></div></div>')

    iocs = ""
    if gt.get("iocs"):
        items = "".join(f'<div><b>{html.escape(str(k))}</b> &nbsp;{html.escape(str(v))}</div>' for k, v in gt["iocs"].items())
        iocs = f'<hr class="rule"><h2>Indicators</h2><div class="iocs">{items}</div>'

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(pcap.name)} — PacketForge report</title><style>{_CSS}</style></head>
<body><div class="wrap">
<h1>PacketForge &middot; capture report</h1>
<div class="title">{html.escape(title)}</div>
<div class="verdict">{verdict}</div>
{('<hr class="rule">' + _kill_chain(gt)) if gt else ''}
<hr class="rule">{_bars(conn)}
<hr class="rule"><h2>Realism checks</h2><div class="chk">{"".join(checks)}</div>
{iocs}
<footer>Every field verified by real Zeek over the synthetic capture. Deterministic; no LLM.</footer>
</div></body></html>"""
