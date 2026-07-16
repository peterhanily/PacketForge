# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Blind-panel realism evaluator — a heuristic adversary that hunts synthetic tells.

Given a .pcap, this runs real Zeek/tshark and scores it the way a skeptical analyst
would: is the timing bursty or uniform? do hosts share a real vendor OUI or look
locally-administered? do "service" connections carry bytes? is it parseable and
clean? It returns a 0–100 score with concrete findings — a self-check that keeps us
honest and the basis for a quality gate (the same idea as EvidenceForge's eval).
"""

from __future__ import annotations

import shutil
import statistics
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from packetforge.validation.roundtrip import _clean, _parse_zeek_log, _run_tshark_expert, _run_zeek


@dataclass
class Finding:
    check: str
    weight: int
    earned: int
    detail: str

    @property
    def ok(self) -> bool:
        return self.earned >= self.weight


@dataclass
class EvalReport:
    findings: list = field(default_factory=list)

    @property
    def score(self) -> int:
        w = sum(f.weight for f in self.findings)
        e = sum(f.earned for f in self.findings)
        return round(100 * e / w) if w else 100

    def summary(self) -> str:
        lines = [f"Realism score: {self.score}/100"]
        for f in sorted(self.findings, key=lambda x: x.earned - x.weight):
            mark = "OK " if f.ok else "!! "
            lines.append(f"  {mark}{f.check:22} {f.earned}/{f.weight}  {f.detail}")
        return "\n".join(lines)


def _tshark_field(pcap: Path, field: str, disp: str | None = None) -> list:
    cmd = ["tshark", "-r", str(pcap), "-T", "fields", "-e", field]
    if disp:
        cmd += ["-Y", disp]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
    return [x.strip() for x in out.splitlines() if x.strip()]


def evaluate_pcap(pcap: str | Path, keep_dir: str | None = None) -> EvalReport:
    if not (shutil.which("zeek") and shutil.which("tshark")):
        raise RuntimeError("evaluation requires zeek + tshark on PATH")
    pcap = Path(pcap)
    workdir = Path(keep_dir) if keep_dir else Path(tempfile.mkdtemp(prefix="pf_eval_"))
    workdir.mkdir(parents=True, exist_ok=True)
    _run_zeek(pcap, workdir)
    conn = _parse_zeek_log(workdir / "conn.log")
    report = EvalReport()

    # 1) Parseability — Zeek + tshark must be clean (the base of any realism claim)
    weird = len(_parse_zeek_log(workdir / "weird.log")) + len(_parse_zeek_log(workdir / "reporter.log"))
    terr, twarn = _run_tshark_expert(pcap)
    problems = weird + terr + twarn
    report.findings.append(Finding(
        "parseability", 30, 30 if problems == 0 else max(0, 30 - 6 * problems),
        f"zeek weird/reporter={weird}, tshark errors/warnings={terr + twarn}"))

    # 2) Timing — bursty (real) vs uniform (synthetic tell). stdev/mean >> 1 is bursty.
    ts = sorted(float(r["ts"]) for r in conn if r.get("ts"))
    gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    if len(gaps) >= 8:
        mean, sd = statistics.mean(gaps), statistics.pstdev(gaps)
        ratio = sd / mean if mean else 0
        report.findings.append(Finding(
            "timing_burstiness", 25, 25 if ratio >= 1.5 else round(25 * min(1.0, ratio / 1.5)),
            f"inter-flow gap stdev/mean={ratio:.2f} (>=1.5 bursty, ~1.0 uniform tell)"))

    # 3) MAC realism — Ethernet fleets share one vendor OUI; 02:* / many OUIs = synthetic
    macs = _tshark_field(pcap, "eth.src")
    if macs:
        ouis = {m[:8].lower() for m in macs}
        locally_admin = any(int(m[:2], 16) & 0x02 for m in ouis if len(m) >= 2)
        good = (len(ouis) <= 2) and not locally_admin
        report.findings.append(Finding(
            "mac_vendor", 15, 15 if good else (7 if len(ouis) <= 2 else 0),
            f"{len(ouis)} distinct OUI(s), locally_administered={locally_admin}"))

    # 4) Byte plausibility — a recognized service that transfers 0 bytes is a tell
    svc_conns = [r for r in conn if _clean(r.get("service", "")) and _clean(r.get("proto", "")) == "tcp"]
    zero = [r for r in svc_conns if int(_clean(r.get("orig_bytes", "")) or 0)
            + int(_clean(r.get("resp_bytes", "")) or 0) == 0]
    if svc_conns:
        frac = len(zero) / len(svc_conns)
        report.findings.append(Finding(
            "byte_plausibility", 15, round(15 * (1 - frac)),
            f"{len(zero)}/{len(svc_conns)} service conns carry 0 bytes"))

    # 5) TTL plausibility — TTLs should cluster at real defaults (64/128/255), not junk
    ttls = {int(t) for t in _tshark_field(pcap, "ip.ttl") if t.isdigit()}
    if ttls:
        realistic = all(min(abs(t - d) for d in (64, 128, 255)) <= 5 for t in ttls)
        report.findings.append(Finding(
            "ttl_plausibility", 15, 15 if realistic else 5,
            f"observed TTLs={sorted(ttls)}"))

    return report
