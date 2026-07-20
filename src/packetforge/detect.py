# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Detection-testing harness — close the loop from capture to detection.

Because PacketForge generates the attack, the benign background, AND the ground truth,
it can answer the question a detection engineer actually has: *does my rule catch this
attack — and does it stay quiet on the noise?* This runs a Suricata ruleset over a
generated capture and scores its alerts against the ground truth: which ATT&CK
techniques were caught vs missed, and the false-positive load on benign traffic.

That makes PacketForge a detection lab, not just a capture generator — and it doubles
as a second, independent realism gate (Suricata, a different engine from Zeek).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DetectionReport:
    total_alerts: int = 0
    true_positives: int = 0          # alerts on a malicious flow
    false_positives: int = 0         # alerts on benign traffic
    techniques_caught: dict = field(default_factory=dict)   # technique -> alert count
    techniques_missed: list = field(default_factory=list)
    benign_flows: int = 0
    examples: list = field(default_factory=list)

    @property
    def fp_per_1k_benign(self) -> float:
        return round(1000.0 * self.false_positives / self.benign_flows, 1) if self.benign_flows else 0.0

    def summary(self) -> str:
        caught = len(self.techniques_caught)
        total_tech = caught + len(self.techniques_missed)
        lines = [
            f"Detection: {caught}/{total_tech} techniques caught  |  "
            f"{self.true_positives} true-positive alerts, {self.false_positives} false positives "
            f"({self.fp_per_1k_benign}/1k benign flows)",
        ]
        for tech, n in sorted(self.techniques_caught.items()):
            lines.append(f"  CAUGHT  {tech}  ({n} alerts)")
        for tech in sorted(self.techniques_missed):
            lines.append(f"  MISSED  {tech}")
        for ex in self.examples[:6]:
            lines.append(f"  fp: {ex}")
        return "\n".join(lines)


def suricata_available() -> bool:
    return bool(shutil.which("suricata"))


def _run_suricata(pcap: Path, rules: Path, workdir: Path) -> list:
    subprocess.run(
        ["suricata", "-r", str(pcap), "-S", str(rules), "-l", str(workdir), "-k", "none",
         # enable JA3/JA4 fingerprinting so ja3.hash rules can match (default is auto/off)
         "--set", "app-layer.protocols.tls.ja3-fingerprints=yes",
         "--set", "app-layer.protocols.tls.ja4-fingerprints=yes"],
        capture_output=True, text=True, check=False,
    )
    eve = workdir / "eve.json"
    alerts = []
    if eve.exists():
        for line in eve.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") == "alert":
                alerts.append(e)
    return alerts


def tls_ja3s(pcap: Path, rules: Path, workdir: Path) -> list:
    """JA3 fingerprints Suricata computed off the wire — handles TLS 1.0-1.3 (tshark's
    ``tls.handshake.ja3`` field is empty for older TLS, so it can't be used here). Returns
    ``[{digest, ja3_full, snis, count}]``; the computation is independent of PacketForge's IR."""
    workdir.mkdir(parents=True, exist_ok=True)
    _run_suricata(pcap, rules, workdir)
    eve = workdir / "eve.json"
    seen: dict = {}
    if eve.exists():
        for line in eve.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            ja3 = (e.get("tls") or {}).get("ja3") or {}
            digest = ja3.get("hash")
            if not digest:
                continue
            ent = seen.setdefault(digest, {"digest": digest, "ja3_full": ja3.get("string") or "",
                                           "count": 0, "snis": set()})
            ent["count"] += 1
            sni = (e.get("tls") or {}).get("sni")
            if sni:
                ent["snis"].add(sni)
    return list(seen.values())


def run_detection(pcap: str | Path, rules: str | Path, ground_truth_json: str | Path,
                  keep_dir: str | None = None) -> DetectionReport:
    if not suricata_available():
        raise RuntimeError("detection requires 'suricata' on PATH")
    pcap, rules = Path(pcap), Path(rules)
    gt = json.loads(Path(ground_truth_json).read_text())
    mal = gt.get("malicious_flows", [])
    # a set of unordered IP pairs that are malicious, and technique per pair
    tech_by_pair: dict = {}
    for f in mal:
        tech_by_pair[frozenset((f["src_ip"], f["dst_ip"]))] = f.get("technique", "")
    all_techs = {f.get("technique", "") for f in mal if f.get("technique")}

    workdir = Path(keep_dir) if keep_dir else Path(tempfile.mkdtemp(prefix="pf_det_"))
    workdir.mkdir(parents=True, exist_ok=True)
    alerts = _run_suricata(pcap, rules, workdir)

    report = DetectionReport(total_alerts=len(alerts))
    caught: dict = {}
    for a in alerts:
        pair = frozenset((a.get("src_ip"), a.get("dest_ip")))
        if pair in tech_by_pair:
            report.true_positives += 1
            tech = tech_by_pair[pair]
            caught[tech] = caught.get(tech, 0) + 1
        else:
            report.false_positives += 1
            report.examples.append(
                f"{a.get('src_ip')} -> {a.get('dest_ip')}:{a.get('dest_port')} "
                f"[{a.get('alert', {}).get('signature', '?')}]")
    report.techniques_caught = caught
    report.techniques_missed = sorted(all_techs - set(caught))
    # benign flows = distinct benign IP pairs seen by Suricata's flow log, approximated
    # by (total malicious flows subtracted from an estimate); use the GT count as a base.
    report.benign_flows = max(0, _flow_count(workdir) - len(mal))
    return report


def _flow_count(workdir: Path) -> int:
    """Count flows Suricata saw (from eve.json flow records), for an FP-rate denominator."""
    eve = workdir / "eve.json"
    n = 0
    if eve.exists():
        for line in eve.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                if json.loads(line).get("event_type") == "flow":
                    n += 1
            except json.JSONDecodeError:
                continue
    return n
