# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""IPv6 / dual-stack: the TCP core and every protocol over it render Zeek-clean."""

import random

import pytest

from packetforge.compile.timeline import compile_flowset
from packetforge.environments import load_environment
from packetforge.models.flowspec import DnsL7, Flow, FlowSet, HttpL7, SmbL7, TlsL7
from packetforge.scenarios import build_attack, list_attacks
from packetforge.validation import validators_available
from scapy.layers.inet6 import IPv6

ENV = load_environment("office")
V6C, V6S = "2001:db8:10::40", "2001:db8:10::80"


def _flow(fid, l7, dport, src=V6C, dst=V6S):
    return Flow(flow_id=fid, transport="tcp", src_ip=src, dst_ip=dst, src_port=50000,
                dst_port=dport, start_time=1_700_000_000.0, conn_state="SF", l7=l7)


def test_tcp_core_emits_ipv6_when_endpoints_are_v6():
    pkts = compile_flowset(FlowSet(flows=[_flow("h", HttpL7(host="x", response_body_len=100), 80)])).packets
    assert all(IPv6 in p for p in pkts)
    assert all(p[IPv6].hlim in (64, 128) for p in pkts)  # hop limit carries the OS TTL


def test_v4_and_v6_agree_on_conn_shape():
    # The same HTTP exchange over v4 vs v6 must produce the same service and history —
    # the point of the fixture is that only the address family differs.
    from packetforge.compile.timeline import compile_flowset as cf
    v6 = cf(FlowSet(flows=[_flow("h6", HttpL7(host="x", response_body_len=200), 80)]))
    v4 = cf(FlowSet(flows=[Flow(flow_id="h4", transport="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.9",
            src_port=50000, dst_port=80, start_time=1_700_000_000.0, conn_state="SF",
            l7=HttpL7(host="x", response_body_len=200))]))
    assert v6.flows[0].expected["conn"]["history"] == v4.flows[0].expected["conn"]["history"]
    assert len(v6.packets) == len(v4.packets)


def test_ipv6_c2_registered_and_labeled():
    assert "ipv6-c2" in list_attacks()
    intr = build_attack("ipv6-c2", ENV, 1_700_000_000.0, random.Random(1))
    e = intr.ground_truth[0]
    assert e.technique.startswith("T1071.001")
    assert e.iocs["family"] == "ipv6" and ":" in e.iocs["c2_ip"]


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("name,l7,port", [
    ("http6", HttpL7(host="h", response_body_len=300), 80),
    ("tls6", TlsL7(server_name="s", version="TLS1.3", app_data_orig_bytes=200, app_data_resp_bytes=800), 443),
    ("smb6", SmbL7(share="\\\\SRV\\Share", read_file="x.pdf", file_bytes=2000), 445),
])
def test_tcp_protocols_over_ipv6_are_zeek_clean(name, l7, port, tmp_path):
    from packetforge.validation import validate_flowset
    report = validate_flowset(FlowSet(flows=[_flow(name, l7, port)]), keep_dir=str(tmp_path))
    assert report.ok, report.summary()


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_dns_aaaa_over_ipv6_and_ipv6_c2_scenario(tmp_path):
    from packetforge.validation import validate_flowset
    from packetforge.validation.roundtrip import _parse_zeek_log
    # AAAA answer carrying an IPv6 address is valid + logged.
    fs = FlowSet(flows=[Flow(flow_id="aaaa", transport="udp", src_ip="10.0.0.5", dst_ip="10.0.0.9",
        src_port=50000, dst_port=53, start_time=1_700_000_000.0,
        l7=DnsL7(qname="host.example.", qtype="AAAA", answers=["2606:4700::1111"]))])
    r1 = validate_flowset(fs, keep_dir=str(tmp_path / "dns"))
    assert r1.ok, r1.summary()
    # The full IPv6 C2 scenario is Zeek-clean and the beacons show up as v6 conns.
    intr = build_attack("ipv6-c2", ENV, 1_700_000_000.0, random.Random(1))
    r2 = validate_flowset(FlowSet(flows=intr.flows), keep_dir=str(tmp_path / "c2"))
    assert r2.zeek_weird == 0 and r2.zeek_reporter == 0, r2.summary()
    conns = _parse_zeek_log(tmp_path / "c2" / "conn.log")
    assert any(r.get("id.resp_h") == intr.ground_truth[0].iocs["c2_ip"] for r in conns)
