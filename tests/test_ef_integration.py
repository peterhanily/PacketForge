# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Local proof of the EvidenceForge FlowSpecEmitter seam — with NO EvidenceForge dependency.

`integration/evidenceforge/prove_local.py` proves the emitter maps EF's real model classes,
but it needs EF's venv. This proves the part that matters *without* importing EF: a canonical
event, mapped by the proposed emitter and compiled by PacketForge, yields a pcap whose real-Zeek
logs reproduce the event's own fields — the consistency-by-construction guarantee the integration
rests on — and that the opaque path carries the event's EXACT byte counts (what log-reconstruction
cannot). EF's SecurityEvent/contexts are duck-typed here as SimpleNamespace, since the emitter only
reads attributes.
"""

import datetime
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration" / "evidenceforge"))
from flowspec_emitter import event_to_flow  # noqa: E402

from packetforge.models.flowspec import CaptureMeta, Flow, FlowSet  # noqa: E402
from packetforge.validation import validators_available  # noqa: E402

_TS = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _ev(net, **ctx):
    base = {"dns": None, "http": None, "ssl": None}
    base.update(ctx)
    return NS(timestamp=_TS, event_type="connection", network=net, **base)


# The canonical events EvidenceForge would generate for a small incident.
_EVENTS = [
    _ev(NS(src_ip="10.10.0.30", src_port=51000, dst_ip="10.10.0.10", dst_port=53, protocol="udp",
           service="dns", orig_bytes=40, resp_bytes=90, conn_state="SF", zeek_uid="Cdns01"),
        dns=NS(query="evil.example", query_type="A", answers=["203.0.113.9"], rcode="NOERROR")),
    _ev(NS(src_ip="10.10.0.30", src_port=51001, dst_ip="203.0.113.9", dst_port=80, protocol="tcp",
           service="http", orig_bytes=180, resp_bytes=520, conn_state="SF", zeek_uid="Chttp1"),
        http=NS(method="GET", host="evil.example", uri="/beacon", status_code=200,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                request_body_len=0, response_body_len=300)),
    _ev(NS(src_ip="10.10.0.30", src_port=51002, dst_ip="203.0.113.9", dst_port=443, protocol="tcp",
           service="ssl", orig_bytes=700, resp_bytes=4000, conn_state="SF", zeek_uid="Cssl01"),
        ssl=NS(version="TLSv12", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
               server_name="secure.evil.example")),
    # analyzer-free service: the canonical event carries EXACT bytes the log path can't recover
    _ev(NS(src_ip="10.10.0.30", src_port=51003, dst_ip="10.10.0.20", dst_port=9300, protocol="tcp",
           service="", orig_bytes=1234, resp_bytes=5678, conn_state="SF", zeek_uid="Copq01")),
]


def _flowset():
    flows = [Flow(**f) for f in (event_to_flow(e) for e in _EVENTS) if f]
    return FlowSet(capture=CaptureMeta(description="ef-seam proof"), flows=flows)


def test_emitter_maps_every_event_and_carries_exact_bytes():
    fs = _flowset()
    assert len(fs.flows) == len(_EVENTS)
    opaque = [f for f in fs.flows if f.l7.kind == "opaque_tcp"][0]
    # the volumetric-fidelity claim: exact byte counts survive the mapping
    assert opaque.l7.orig_bytes == 1234 and opaque.l7.resp_bytes == 5678
    assert {f.l7.kind for f in fs.flows} == {"dns", "http", "tls", "opaque_tcp"}


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")
def test_ef_events_compile_to_a_zeek_consistent_pcap(tmp_path):
    from packetforge.validation import validate_flowset
    report = validate_flowset(_flowset(), keep_dir=str(tmp_path))
    # consistency-by-construction: real Zeek reproduces the events' fields, no malformed packets
    assert report.zeek_weird == 0 and report.zeek_reporter == 0, report.summary()
    assert report.matched_flows == report.total_flows, report.summary()

    from packetforge.validation.roundtrip import _parse_zeek_log
    dns = {r.get("query", "") for r in _parse_zeek_log(tmp_path / "dns.log")}
    ssl = {r.get("server_name", "") for r in _parse_zeek_log(tmp_path / "ssl.log")}
    http = {r.get("host", "") for r in _parse_zeek_log(tmp_path / "http.log")}
    assert "evil.example" in dns
    assert "secure.evil.example" in ssl
    assert "evil.example" in http


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")
def test_emitter_carries_event_duration_so_zeek_agrees(tmp_path):
    # The TLS duration-floor reconciliation: an event that carries a duration makes the pcap
    # render to it, so real Zeek recomputes ~that conn.log duration instead of PacketForge's own
    # sub-second handshake time (which would diverge by orders of magnitude from an asserted floor).
    from packetforge.validation import validate_flowset
    from packetforge.validation.roundtrip import _parse_zeek_log
    net = NS(src_ip="10.10.0.30", src_port=51099, dst_ip="203.0.113.9", dst_port=443, protocol="tcp",
             service="ssl", orig_bytes=700, resp_bytes=4000, conn_state="SF", zeek_uid="Cdur01",
             duration=1.8)
    ev = _ev(net, ssl=NS(version="TLSv12", cipher="x", server_name="s.example"))
    fd = event_to_flow(ev)
    assert fd["duration"] == 1.8   # carried from the event
    fs = FlowSet(capture=CaptureMeta(), flows=[Flow(**fd)])
    validate_flowset(fs, keep_dir=str(tmp_path))
    d = float(_parse_zeek_log(tmp_path / "conn.log")[0]["duration"])
    # within a few percent of the asserted duration (residual = Zeek excluding the final
    # teardown ACK); vs an unconstrained render that would be < 0.1s.
    assert 1.6 < d < 1.85, f"duration not reconciled to the event ({d:.3f}s vs 1.8s)"
