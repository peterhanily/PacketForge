# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""TCP core: each conn_state produces the expected Zeek history + volumetrics."""

import random

import pytest

from packetforge.compile.tcp import TcpMessage, build_tcp_flow
from packetforge.fingerprints import resolve_endpoint

DATA = [TcpMessage(True, b"A" * 100), TcpMessage(False, b"B" * 200)]

CASES = [
    ("SF", DATA, "ShADadFf"),
    ("S0", [], "S"),
    ("REJ", [], "Sr"),
    ("RSTO", DATA, "ShADadR"),
    ("RSTR", DATA, "ShADadr"),
]


@pytest.mark.parametrize("state,messages,history", CASES)
def test_conn_state_history(state, messages, history):
    orig = resolve_endpoint("10.0.0.5", 40000, "windows_10")
    resp = resolve_endpoint("10.0.0.9", 445, "linux")
    r = build_tcp_flow(orig, resp, messages, 1700000000.0, 0.03,
                       random.Random(1), conn_state=state)
    assert r.summary["history"] == history
    assert r.summary["conn_state"] == state


def test_byte_and_packet_counts_measured_from_wire():
    orig = resolve_endpoint("10.0.0.5", 40000, "windows_10")
    resp = resolve_endpoint("10.0.0.9", 445, "linux")
    r = build_tcp_flow(orig, resp, DATA, 1700000000.0, 0.03,
                       random.Random(1), conn_state="SF")
    assert r.summary["orig_bytes"] == 100
    assert r.summary["resp_bytes"] == 200
    assert r.summary["orig_pkts"] >= 3  # SYN, ACK, data, FIN, ...
    assert r.summary["resp_pkts"] >= 2


def test_segmentation_respects_min_segments():
    orig = resolve_endpoint("10.0.0.5", 40000, "linux")
    resp = resolve_endpoint("10.0.0.9", 445, "linux")
    r = build_tcp_flow(orig, resp, [TcpMessage(True, b"X" * 300)], 1700000000.0, 0.03,
                       random.Random(1), conn_state="SF", min_segments=3)
    # 3 originator data segments requested, even though 300B fits in one MSS
    from scapy.layers.inet import IP, TCP
    data_pkts = [p for p in r.packets if p[IP].src == "10.0.0.5" and len(p[TCP].payload) > 0]
    assert len(data_pkts) >= 3
