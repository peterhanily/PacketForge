# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""SNMP renderer: get-request / response exchanges."""

from __future__ import annotations

import random

from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPvarbind

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import Flow, SnmpL7
from packetforge.renderers.base import RenderResult


def render_snmp(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: SnmpL7 = flow.l7
    packets = []
    t = flow.start_time
    for _ in range(spec.count):
        req_id = rng.randint(1, 0x7FFFFFFF)
        get = (Ether(src=orig.mac, dst=resp.mac)
               / IP(src=orig.ip, dst=resp.ip, ttl=orig.ttl, id=rng.randint(0, 0xFFFF))
               / UDP(sport=orig.port, dport=resp.port)
               / SNMP(community=spec.community,
                      PDU=SNMPget(id=req_id, varbindlist=[SNMPvarbind(oid=ASN1_OID(spec.oid))])))
        get.time = t
        rep = (Ether(src=resp.mac, dst=orig.mac)
               / IP(src=resp.ip, dst=orig.ip, ttl=resp.ttl, id=rng.randint(0, 0xFFFF))
               / UDP(sport=resp.port, dport=orig.port)
               / SNMP(community=spec.community,
                      PDU=SNMPresponse(id=req_id, varbindlist=[
                          SNMPvarbind(oid=ASN1_OID(spec.oid), value=ASN1_STRING(spec.value.encode()))])))
        rep.time = t + flow.rtt
        packets += [get, rep]
        t += flow.rtt + rng.uniform(2.0, 5.0)

    return RenderResult(packets=packets, expected={"conn": {"proto": "udp"}, "produces": "snmp"})
