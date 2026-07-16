# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The crown jewel: real Zeek/tshark must agree with what PacketForge rendered."""

import pytest
from conftest import EXAMPLE_FLOWS

from packetforge.models.flowspec import load_flowset
from packetforge.validation import validate_flowset, validators_available

pytestmark = pytest.mark.skipif(
    not validators_available(), reason="requires zeek + tshark on PATH"
)


def test_example_flowset_roundtrips_clean():
    fs = load_flowset(EXAMPLE_FLOWS)
    report = validate_flowset(fs)
    assert report.ok, "\n" + report.summary()
    assert report.matched_flows == report.total_flows
    assert report.zeek_weird == 0
    assert report.zeek_reporter == 0
    assert report.tshark_errors == 0
    assert report.tshark_warnings == 0
    assert report.mismatches == []


def test_grease_and_two_profiles_roundtrip_clean():
    """Two client profiles (GREASE browser + curl) round-trip clean with distinct JA3."""
    from packetforge.compile.timeline import compile_flowset
    from packetforge.models.flowspec import FlowSet
    from packetforge.validation import validate_flowset

    def mk(fid, port, prof, sni):
        return {"flow_id": fid, "transport": "tcp", "src_ip": "10.0.0.5",
                "dst_ip": f"93.1.1.{port}", "src_port": 50000 + port, "dst_port": 443,
                "start_time": 1700000000.0 + port, "conn_state": "SF",
                "l7": {"kind": "tls", "server_name": sni, "client_profile": prof,
                       "app_data_resp_bytes": 200}}
    fs = FlowSet.model_validate({"flows": [
        mk("browser", 1, "generic_browser", "a.example"),
        mk("curl", 2, "curl", "b.example")]})
    report = validate_flowset(fs)
    assert report.ok, "\n" + report.summary()
    ja3s = [cf.expected["ssl"]["ja3"] for cf in compile_flowset(fs).flows]
    assert ja3s[0] != ja3s[1]


def test_validator_catches_inconsistency():
    """A deliberately wrong author expectation must fail the gate (proves teeth)."""
    fs = load_flowset(EXAMPLE_FLOWS)
    # http_beacon is really SF; claim S0.
    http = next(f for f in fs.flows if f.flow_id == "http_beacon")
    http.expect.conn_state = "S0"
    report = validate_flowset(fs)
    assert not report.ok
    assert any(m.field == "conn_state" for m in report.mismatches)
