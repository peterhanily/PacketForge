# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Self-contained detection-CI bundles — the pcap ships with its answer key.

A bundle is everything a detection engineer needs in one directory: the capture, the *exact*
Zeek logs it produces, the ATT&CK ground truth, and a manifest that records the consistency
result and a content hash. Because generation is deterministic and the logs are the ones real
Zeek derived from these bytes, the bundle is reproducible and self-verifying: you can point a
detection at ``capture.pcap`` and grade it against ``GROUND_TRUTH.json`` without re-deriving
anything, and ``manifest.json`` tells you the packets and their Zeek logs agree.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from packetforge.compile.timeline import write_pcap
from packetforge.models.flowspec import FlowSet
from packetforge.validation import validate_flowset, validators_available


def write_bundle(fs: FlowSet, out_dir: str | Path, *, intrusion=None, salt: str = "") -> dict:
    """Write ``capture.pcap`` + its Zeek logs + ground truth + ``manifest.json`` into ``out_dir``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    consistency = None
    if validators_available():
        # validate_flowset writes capture.pcap and the Zeek logs into out_dir, and checks that
        # the packets and the logs Zeek derives from them agree field-for-field.
        report = validate_flowset(fs, keep_dir=str(out), salt=salt)
        consistency = {
            "ok": report.ok,
            "matched_flows": report.matched_flows, "total_flows": report.total_flows,
            "zeek_weird": report.zeek_weird, "zeek_reporter": report.zeek_reporter,
            "tshark_errors": report.tshark_errors, "tshark_warnings": report.tshark_warnings,
            "mismatches": [str(m) for m in report.mismatches],
        }
    else:
        write_pcap(fs, out / "capture.pcap", salt=salt)

    if intrusion is not None:
        from packetforge.scenarios import write_ground_truth
        write_ground_truth(intrusion, out / "GROUND_TRUTH.md", out / "GROUND_TRUTH.json")

    pcap = out / "capture.pcap"
    zeek_logs = sorted(p.name for p in out.glob("*.log"))
    manifest = {
        "pcap": pcap.name,
        "sha256": hashlib.sha256(pcap.read_bytes()).hexdigest() if pcap.exists() else None,
        "flows": len(fs.flows),
        "zeek_logs": zeek_logs,
        "ground_truth": "GROUND_TRUTH.json" if intrusion is not None else None,
        "consistency": consistency,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
