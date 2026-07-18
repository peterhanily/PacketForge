# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Multi-vantage projection: one incident, several sensor placements, each Zeek-clean."""

import tempfile
from pathlib import Path

import pytest

from packetforge.compile.timeline import compile_flowset
from packetforge.compile.vantage import Vantage, render_vantage, render_vantages, standard_vantages
from packetforge.models.flowspec import DnsL7, Flow, FlowSet, HttpL7
from packetforge.validation import validators_available
from scapy.layers.inet import IP
from scapy.layers.l2 import CookedLinux, Dot1Q, Ether

SUBNET = "10.10.0.0/16"
VICTIM = "10.10.0.40"


def _incident():
    # Two internal hosts, one talking to a third internal host, one resolving DNS.
    return FlowSet(flows=[
        Flow(flow_id="f-http", transport="tcp", src_ip=VICTIM, dst_ip="10.10.0.50",
             src_port=50000, dst_port=80, start_time=1_700_000_000.0, conn_state="SF",
             l7=HttpL7(host="intranet", response_body_len=200)),
        Flow(flow_id="f-dns", transport="udp", src_ip="10.10.0.41", dst_ip="10.10.0.9",
             src_port=51000, dst_port=53, start_time=1_700_000_001.0,
             l7=DnsL7(qname="x.corp.", answers=["10.10.0.7"])),
    ])


def _packets():
    return compile_flowset(_incident()).packets


def _ttls(pkts):
    return [p[IP].ttl for p in pkts if IP in p]


def test_edge_tap_source_nats_and_decrements_ttl():
    base = _packets()
    edge = render_vantage(base, Vantage("edge", hops=1, nat_subnet=SUBNET, nat_public="203.0.113.10"))
    ips = {p[IP].src for p in edge if IP in p} | {p[IP].dst for p in edge if IP in p}
    # Every internal (RFC1918) address is collapsed to the one public IP; none leak through.
    assert "203.0.113.10" in ips
    assert not any(a.startswith("10.10.") for a in ips), ips
    # One router hop => every TTL is one lower than the rendered base.
    assert _ttls(edge) == [t - 1 for t in _ttls(base)]


def test_core_span_carries_vlan_and_keeps_internal_ips():
    base = _packets()
    span = render_vantage(base, Vantage("core", vlan=10))
    assert all(Dot1Q in p and p[Dot1Q].vlan == 10 for p in span)
    # No NAT here: the real internal addresses are still visible on the trunk.
    assert any(p[IP].src == VICTIM for p in span if IP in p)
    assert _ttls(span) == _ttls(base)  # same hop, unchanged


def test_host_sensor_sees_only_its_flows_as_cooked_capture():
    base = _packets()
    host = render_vantage(base, Vantage(f"host-{VICTIM}", link_type="linux_sll", sees_host=VICTIM))
    assert host and all(CookedLinux in p and Ether not in p for p in host)
    # Only packets the victim is an endpoint of survive (its HTTP flow, not the other's DNS).
    assert all(VICTIM in (p[IP].src, p[IP].dst) for p in host if IP in p)
    assert len(host) < len(base)


def test_projection_is_deterministic():
    base = _packets()
    vs = standard_vantages(SUBNET, host=VICTIM)
    a = render_vantages(base, vs)
    b = render_vantages(base, vs)
    for name in a:
        assert [bytes(p) for p in a[name]] == [bytes(p) for p in b[name]], name


def test_standard_vantages_shape():
    vs = standard_vantages(SUBNET, host=VICTIM)
    names = [v.name for v in vs]
    assert names == ["edge-tap", "core-span", f"host-{VICTIM}"]
    assert standard_vantages(SUBNET) == vs[:2]  # no host vantage without a host


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_every_vantage_is_zeek_clean():
    from packetforge.validation.roundtrip import _parse_zeek_log, _run_zeek
    from scapy.utils import wrpcap
    base = _packets()
    for name, pkts in render_vantages(base, standard_vantages(SUBNET, host=VICTIM)).items():
        wd = Path(tempfile.mkdtemp(prefix=f"pf_van_{name}_"))
        pcap = wd / "c.pcap"
        wrpcap(str(pcap), pkts)
        _run_zeek(pcap, wd)
        assert not _parse_zeek_log(wd / "weird.log"), f"{name}: zeek weird"
        assert not _parse_zeek_log(wd / "reporter.log"), f"{name}: zeek reporter"
