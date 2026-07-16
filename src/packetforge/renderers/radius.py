# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""RADIUS renderer: Access-Request / Access-Accept (or Reject)."""

from __future__ import annotations

import random

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.radius import Radius, RadiusAttribute

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import Flow, RadiusL7
from packetforge.renderers.base import RenderResult


def render_radius(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: RadiusL7 = flow.l7
    rid = rng.randint(0, 255)
    req = (Ether(src=orig.mac, dst=resp.mac)
           / IP(src=orig.ip, dst=resp.ip, ttl=orig.ttl, id=rng.randint(0, 0xFFFF))
           / UDP(sport=orig.port, dport=resp.port)
           / Radius(code=1, id=rid, authenticator=rng.randbytes(16),
                    attributes=[RadiusAttribute(type=1, value=spec.username.encode())]))
    req.time = flow.start_time
    rep = (Ether(src=resp.mac, dst=orig.mac)
           / IP(src=resp.ip, dst=orig.ip, ttl=resp.ttl, id=rng.randint(0, 0xFFFF))
           / UDP(sport=resp.port, dport=orig.port)
           / Radius(code=2 if spec.accept else 3, id=rid, authenticator=rng.randbytes(16)))
    rep.time = flow.start_time + flow.rtt

    return RenderResult(packets=[req, rep], expected={"conn": {"proto": "udp"}, "produces": "radius"})
