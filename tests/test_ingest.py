# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""EvidenceForge ingest + real-data round-trip on a synthetic EF-shaped fixture."""

import json

import pytest

from packetforge.ingest.evidenceforge import flowset_from_evidenceforge
from packetforge.validation import validators_available


def _write_ef(dirpath):
    conn = [
        {"ts": 1700000000.0, "uid": "U1", "id.orig_h": "10.0.0.5", "id.orig_p": 5000,
         "id.resp_h": "10.0.0.1", "id.resp_p": 53, "proto": "udp", "service": "dns",
         "conn_state": "SF", "orig_bytes": 40, "resp_bytes": 56, "orig_pkts": 1, "resp_pkts": 1},
        {"ts": 1700000001.0, "uid": "U2", "id.orig_h": "10.0.0.5", "id.orig_p": 6000,
         "id.resp_h": "93.1.1.1", "id.resp_p": 80, "proto": "tcp", "service": "http",
         "conn_state": "SF", "orig_bytes": 120, "resp_bytes": 300, "orig_pkts": 4, "resp_pkts": 3},
        {"ts": 1700000002.0, "uid": "U3", "id.orig_h": "10.0.0.5", "id.orig_p": 6001,
         "id.resp_h": "93.1.1.2", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
         "conn_state": "SF", "orig_bytes": 700, "resp_bytes": 4000, "orig_pkts": 8, "resp_pkts": 9},
        {"ts": 1700000003.0, "uid": "U4", "id.orig_h": "10.0.0.5", "id.orig_p": 6002,
         "id.resp_h": "10.0.0.9", "id.resp_p": 9999, "proto": "tcp", "service": "-",
         "conn_state": "SF", "orig_bytes": 500, "resp_bytes": 1500, "orig_pkts": 3, "resp_pkts": 3},
    ]
    dns = [{"ts": 1700000000.0, "uid": "U1", "query": "example.com", "qtype_name": "A",
            "rcode_name": "NOERROR", "answers": ["203.0.113.4"]}]
    http = [{"ts": 1700000001.0, "uid": "U2", "method": "GET", "host": "h.example", "uri": "/x",
             "user_agent": "UA/1.0", "status_code": 200, "request_body_len": 0, "response_body_len": 100}]
    ssl = [{"ts": 1700000002.0, "uid": "U3", "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "server_name": "sni.example"}]
    for name, rows in (("conn", conn), ("dns", dns), ("http", http), ("ssl", ssl)):
        (dirpath / f"{name}.json").write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_ingest_maps_services_to_kinds(tmp_path):
    _write_ef(tmp_path)
    fs, originals, stats = flowset_from_evidenceforge(tmp_path)
    kinds = sorted(f.l7.kind for f in fs.flows)
    assert kinds == ["dns", "http", "opaque_tcp", "tls"]
    assert stats.total_conn == 4


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_ef_roundtrip_is_clean_and_agrees(tmp_path):
    from packetforge.validation.ef_roundtrip import compare_against_ef
    _write_ef(tmp_path)
    fs, originals, stats = flowset_from_evidenceforge(tmp_path)
    report = compare_against_ef(fs, originals, stats)
    assert report.zeek_weird == 0 and report.zeek_reporter == 0
    assert report.tshark_errors == 0 and report.tshark_warnings == 0
    # every ingested flow round-trips and the IOC fields reproduce exactly
    for name in ("conn.proto", "conn.service", "dns.query", "http.host",
                 "ssl.server_name", "opaque.orig_bytes"):
        t = report.tallies.get(name)
        assert t is not None and t.matched == t.total and t.total > 0, f"{name}: {t}"
