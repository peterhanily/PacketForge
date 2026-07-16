# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""NTP renderer: client (mode 3) / server (mode 4) time exchanges."""

from __future__ import annotations

import random

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.ntp import NTP

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import Flow, NtpL7
from packetforge.renderers.base import RenderResult


def render_ntp(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: NtpL7 = flow.l7
    packets = []
    t = flow.start_time
    # NTP timestamps are seconds since 1900. Pin them explicitly — scapy fills the
    # `orig`/`sent` fields with wall-clock time when left None, which breaks determinism.
    _ntp = lambda x: x + 2208988800.0  # noqa: E731
    for _ in range(spec.count):
        req = (Ether(src=orig.mac, dst=resp.mac)
               / IP(src=orig.ip, dst=resp.ip, ttl=orig.ttl, id=rng.randint(0, 0xFFFF))
               / UDP(sport=orig.port, dport=resp.port)
               / NTP(version=spec.version, mode=3, ref=0, orig=0, recv=0, sent=_ntp(t)))
        req.time = t
        rep = (Ether(src=resp.mac, dst=orig.mac)
               / IP(src=resp.ip, dst=orig.ip, ttl=resp.ttl, id=rng.randint(0, 0xFFFF))
               / UDP(sport=resp.port, dport=orig.port)
               / NTP(version=spec.version, mode=4, stratum=spec.stratum,
                     ref=_ntp(t - 3600), orig=_ntp(t), recv=_ntp(t + flow.rtt / 2), sent=_ntp(t + flow.rtt)))
        rep.time = t + flow.rtt
        packets += [req, rep]
        t += flow.rtt + rng.uniform(1.0, 2.0)

    return RenderResult(packets=packets,
                        expected={"conn": {"proto": "udp"}, "produces": "ntp"})
