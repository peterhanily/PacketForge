# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Opaque-UDP renderer: sized datagrams for non-DNS UDP services (krb/dhcp/ntp/...)."""

from __future__ import annotations

import random

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import Flow, OpaqueUdpL7
from packetforge.renderers.base import RenderResult, filler_bytes


def render_opaque_udp(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: OpaqueUdpL7 = flow.l7
    packets = []
    t = flow.start_time

    def dgram(from_orig: bool, payload: bytes, ts: float):
        s, d = (orig, resp) if from_orig else (resp, orig)
        p = (Ether(src=s.mac, dst=d.mac)
             / IP(src=s.ip, dst=d.ip, id=rng.randint(0, 0xFFFF), ttl=s.ttl)
             / UDP(sport=s.port, dport=d.port) / Raw(filler_bytes(len(payload), rng)))
        p.time = ts
        return p

    if spec.orig_bytes:
        packets.append(dgram(True, b"x" * spec.orig_bytes, t))
    if spec.resp_bytes:
        packets.append(dgram(False, b"x" * spec.resp_bytes, t + flow.rtt))

    orig_bytes = sum(len(p[UDP].payload) for p in packets if p[IP].src == orig.ip)
    resp_bytes = sum(len(p[UDP].payload) for p in packets if p[IP].src == resp.ip)
    conn = {
        "proto": "udp",
        "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
        "orig_pkts": sum(1 for p in packets if p[IP].src == orig.ip),
        "resp_pkts": sum(1 for p in packets if p[IP].src == resp.ip),
    }
    return RenderResult(packets=packets, expected={"conn": conn})
