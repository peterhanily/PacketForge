# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Encrypted-DNS (DoH/DoT) fixtures + configurable TLS ALPN."""

import random

import pytest

from packetforge.compile.timeline import compile_flowset
from packetforge.environments import load_environment
from packetforge.models.flowspec import Flow, FlowSet, TlsL7
from packetforge.scenarios import build_attack, list_attacks
from packetforge.validation import validators_available

ENV = load_environment("office")
PACK = ["doh-tunnel", "dot-tunnel"]


def test_encrypted_dns_attacks_registered():
    for name in PACK:
        assert name in list_attacks()


@pytest.mark.parametrize("name", PACK)
def test_builder_ground_truth(name):
    intr = build_attack(name, ENV, 1_700_000_000.0, random.Random(1))
    assert intr.flows and intr.ground_truth
    e = intr.ground_truth[0]
    assert e.technique.startswith("T1071.004")
    assert e.iocs["channel"] in ("doh", "dot")
    assert "resolver" in e.iocs and e.iocs["expected_signal"]
    assert all(f.flow_id.startswith("atk-") for f in intr.flows)


def test_alpn_is_configurable_and_deterministic():
    def render(alpn):
        fs = FlowSet(flows=[Flow(flow_id="t", transport="tcp", src_ip="10.0.0.5", dst_ip="1.1.1.1",
                    src_port=50000, dst_port=443, start_time=1_700_000_000.0, conn_state="SF",
                    l7=TlsL7(server_name="x", version="TLS1.2", client_profile="curl", alpn=alpn))])
        return b"".join(bytes(p) for p in compile_flowset(fs).packets)
    dot = render(["dot"])
    h2 = render(["h2", "http/1.1"])
    assert b"dot" in dot and b"dot" not in h2         # the advertised protocol is on the wire
    assert dot == render(["dot"])                      # deterministic


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("name,port,next_proto", [("doh-tunnel", "443", ""), ("dot-tunnel", "853", "dot")])
def test_encrypted_dns_is_zeek_clean_and_logged(name, port, next_proto, tmp_path):
    from packetforge.validation import validate_flowset
    from packetforge.validation.roundtrip import _parse_zeek_log
    intr = build_attack(name, ENV, 1_700_000_000.0, random.Random(1))
    report = validate_flowset(FlowSet(flows=intr.flows), keep_dir=str(tmp_path))
    assert report.zeek_weird == 0 and report.zeek_reporter == 0, report.summary()
    assert not report.mismatches, report.summary()
    ssl = _parse_zeek_log(tmp_path / "ssl.log")
    assert ssl, f"{name}: expected ssl.log rows"
    # Every session is TLS to the resolver on the expected port.
    assert all(r.get("id.resp_p") == port for r in ssl), {r.get("id.resp_p") for r in ssl}
    assert all(r.get("server_name") == "cloudflare-dns.com" for r in ssl)
    if next_proto:
        assert all(r.get("next_protocol") == next_proto for r in ssl), \
            {r.get("next_protocol") for r in ssl}
