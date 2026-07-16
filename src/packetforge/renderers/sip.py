# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""SIP renderer: a request/response over UDP (VoIP signalling)."""

from __future__ import annotations

import random

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import Flow, SipL7
from packetforge.renderers.base import RenderResult


def render_sip(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: SipL7 = flow.l7
    call_id = f"{rng.randint(0, 0xFFFFFFFF):x}@{spec.domain}"
    branch = f"z9hG4bK{rng.randint(0, 0xFFFFFFFF):x}"
    ftag = f"{rng.randint(0, 0xFFFF):x}"
    uri = f"sip:{spec.domain}" if spec.method == "REGISTER" else f"sip:{spec.user}@{spec.domain}"
    hdrs = (f"Via: SIP/2.0/UDP {orig.ip}:{orig.port};branch={branch}\r\n"
            f"From: <sip:{spec.user}@{spec.domain}>;tag={ftag}\r\n"
            f"To: <sip:{spec.user}@{spec.domain}>\r\n"
            f"Call-ID: {call_id}\r\nCSeq: 1 {spec.method}\r\n"
            f"Contact: <sip:{spec.user}@{orig.ip}>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
    req = f"{spec.method} {uri} SIP/2.0\r\n" + hdrs
    rsp = (f"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP {orig.ip}:{orig.port};branch={branch}\r\n"
           f"From: <sip:{spec.user}@{spec.domain}>;tag={ftag}\r\n"
           f"To: <sip:{spec.user}@{spec.domain}>;tag={rng.randint(0, 0xFFFF):x}\r\n"
           f"Call-ID: {call_id}\r\nCSeq: 1 {spec.method}\r\nContent-Length: 0\r\n\r\n")

    q = (Ether(src=orig.mac, dst=resp.mac)
         / IP(src=orig.ip, dst=resp.ip, ttl=orig.ttl, id=rng.randint(0, 0xFFFF))
         / UDP(sport=orig.port, dport=resp.port) / Raw(req.encode()))
    q.time = flow.start_time
    a = (Ether(src=resp.mac, dst=orig.mac)
         / IP(src=resp.ip, dst=orig.ip, ttl=resp.ttl, id=rng.randint(0, 0xFFFF))
         / UDP(sport=resp.port, dport=orig.port) / Raw(rsp.encode()))
    a.time = flow.start_time + flow.rtt
    return RenderResult(packets=[q, a], expected={"conn": {"proto": "udp"}, "produces": "sip"})
