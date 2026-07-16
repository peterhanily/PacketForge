# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""ICMP echo renderer."""

from __future__ import annotations

import random

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import Flow, IcmpL7
from packetforge.renderers.base import RenderResult, filler_bytes


def render_icmp(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: IcmpL7 = flow.l7
    packets = []
    t = flow.start_time
    ident = rng.randint(0, 0xFFFF)
    payload = filler_bytes(spec.payload_len, rng)
    for seq in range(spec.count):
        echo = (
            Ether(src=orig.mac, dst=resp.mac)
            / IP(src=orig.ip, dst=resp.ip, id=rng.randint(0, 0xFFFF), ttl=orig.ttl)
            / ICMP(type=8, id=ident, seq=seq)
            / Raw(payload)
        )
        echo.time = t
        packets.append(echo)
        reply = (
            Ether(src=resp.mac, dst=orig.mac)
            / IP(src=resp.ip, dst=orig.ip, id=rng.randint(0, 0xFFFF), ttl=resp.ttl)
            / ICMP(type=0, id=ident, seq=seq)
            / Raw(payload)
        )
        reply.time = t + flow.rtt
        packets.append(reply)
        t += flow.rtt + rng.uniform(0.8, 1.2)

    expected = {"conn": {"proto": "icmp"}}
    return RenderResult(packets=packets, expected=expected)
