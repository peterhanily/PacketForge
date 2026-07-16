# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""DNS renderer: one query and (optionally) its response, over UDP."""

from __future__ import annotations

import random

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import DnsL7, Flow
from packetforge.renderers.base import RenderResult

_RCODES = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "REFUSED": 5}


def render_dns(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: DnsL7 = flow.l7
    txid = rng.randint(0, 0xFFFF)
    packets = []

    query = (
        Ether(src=orig.mac, dst=resp.mac)
        / IP(src=orig.ip, dst=resp.ip, id=rng.randint(0, 0xFFFF), ttl=orig.ttl)
        / UDP(sport=orig.port, dport=resp.port)
        / DNS(id=txid, rd=1, qd=DNSQR(qname=spec.qname, qtype=spec.qtype))
    )
    query.time = flow.start_time
    packets.append(query)

    # Answer RRs are rendered only for address types (rdata is an IP); other qtypes
    # still produce a valid response whose query/qtype Zeek logs.
    answerable = spec.qtype in ("A", "AAAA")
    if spec.respond:
        an = None
        if spec.rcode == "NOERROR" and spec.answers and answerable:
            for ip in spec.answers:
                rr = DNSRR(rrname=spec.qname, type=spec.qtype, ttl=300, rdata=ip)
                an = rr if an is None else an / rr
        reply = (
            Ether(src=resp.mac, dst=orig.mac)
            / IP(src=resp.ip, dst=orig.ip, id=rng.randint(0, 0xFFFF), ttl=resp.ttl)
            / UDP(sport=resp.port, dport=orig.port)
            / DNS(
                id=txid, qr=1, aa=0, ra=1, rd=1, rcode=_RCODES.get(spec.rcode, 0),
                qd=DNSQR(qname=spec.qname, qtype=spec.qtype),
                an=an,
                ancount=len(spec.answers) if (spec.rcode == "NOERROR" and answerable) else 0,
            )
        )
        reply.time = flow.start_time + rng.uniform(0.002, 0.02)
        packets.append(reply)

    expected = {
        "conn": {"service": "dns", "proto": "udp"},
        "dns": {
            "query": spec.qname.rstrip("."),
            "qtype_name": spec.qtype,
            "rcode_name": spec.rcode,
            "answers": list(spec.answers) if (spec.rcode == "NOERROR" and answerable) else [],
        },
    }
    return RenderResult(packets=packets, expected=expected)
