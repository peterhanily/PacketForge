# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""IP fragmentation: a reassembly / IDS-evasion transform that Zeek still reassembles."""

import random
import tempfile
from pathlib import Path

import pytest

from packetforge.compile.fragment import fragment_packets
from packetforge.compile.timeline import compile_flowset
from packetforge.environments import load_environment
from packetforge.models.flowspec import Flow, FlowSet, HttpL7
from packetforge.scenarios import build_attack
from packetforge.validation import validators_available
from scapy.layers.inet import IP


def _http_flow():
    return FlowSet(flows=[Flow(flow_id="h", transport="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.9",
        src_port=50000, dst_port=80, start_time=1_700_000_000.0, conn_state="SF",
        l7=HttpL7(host="x", uri="/data", response_body_len=3000))])


def test_oversized_packets_are_fragmented_others_pass_through():
    base = compile_flowset(_http_flow()).packets
    fragged = fragment_packets(base, fragsize=400)
    assert len(fragged) > len(base)                       # some packets were split
    assert all(IP not in p or len(p[IP].payload) <= 408 for p in fragged)  # each <= fragsize (8-aligned)
    frag_flagged = [p for p in fragged if IP in p and (p[IP].flags & 1 or p[IP].frag > 0)]
    assert frag_flagged, "expected IP fragments (MF flag or non-zero offset)"


def test_fragmentation_is_deterministic():
    base = compile_flowset(_http_flow()).packets
    a = [bytes(p) for p in fragment_packets(base, 400)]
    b = [bytes(p) for p in fragment_packets(base, 400)]
    assert a == b


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_zeek_reassembles_fragments_to_the_same_flow():
    import subprocess

    from packetforge.validation.roundtrip import _parse_zeek_log
    from scapy.utils import wrpcap
    fragged = fragment_packets(compile_flowset(_http_flow()).packets, fragsize=400)
    wd = Path(tempfile.mkdtemp())
    wrpcap(str(wd / "c.pcap"), fragged)
    subprocess.run(["zeek", "-r", str(wd / "c.pcap"), "detect_filtered_trace=F"],
                   cwd=str(wd), capture_output=True, text=True)
    assert not _parse_zeek_log(wd / "weird.log"), "fragmentation produced a Zeek weird"
    http = _parse_zeek_log(wd / "http.log")
    assert http and http[0].get("uri") == "/data"        # reassembled, the request recovered
    assert len(_parse_zeek_log(wd / "conn.log")) == 1     # one flow, not many


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_fragmenting_an_attack_preserves_its_detection_signal():
    import subprocess

    from packetforge.validation.roundtrip import _parse_zeek_log
    from scapy.utils import wrpcap
    env = load_environment("office")
    intr = build_attack("dns-exfil", env, 1_700_000_000.0, random.Random(1))
    fragged = fragment_packets(compile_flowset(FlowSet(flows=intr.flows)).packets, fragsize=200)
    wd = Path(tempfile.mkdtemp())
    wrpcap(str(wd / "c.pcap"), fragged)
    subprocess.run(["zeek", "-r", str(wd / "c.pcap"), "detect_filtered_trace=F"],
                   cwd=str(wd), capture_output=True, text=True)
    assert not _parse_zeek_log(wd / "weird.log")
    # the DNS-tunnel queries survive reassembly (same exfil domain visible in dns.log)
    dns = _parse_zeek_log(wd / "dns.log")
    assert any("exfil.evil.example" in r.get("query", "") for r in dns)
