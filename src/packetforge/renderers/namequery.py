# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""LLMNR / NBT-NS / mDNS name resolution — with an optional poisoned (Responder-style) reply.

The victim broadcasts/multicasts a name query its DNS server didn't answer; if ``poison_from``
is set, an attacker races a spoofed reply claiming that name for its own IP. Zeek parses all
three protocols with its DNS analyzer, so both the query and the poisoned answer land in
``dns.log`` (the answer's rdata is the attacker's address — the machine-in-the-middle tell).
"""

from __future__ import annotations

import hashlib
import random

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNS_ADD_ENTRY, NBNSHeader, NBNSQueryRequest, NBNSQueryResponse

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import Flow, NameQueryL7
from packetforge.renderers.base import RenderResult

_PORT = {"llmnr": 5355, "nbns": 137, "mdns": 5353}
# LLMNR (RFC 4795) and mDNS (RFC 6762) recommend TTL 255 as a link-local check; NBT-NS is a
# normal broadcast datagram.
_TTL = {"llmnr": 255, "mdns": 255, "nbns": 128}


def _l2_dst(ip: str) -> str:
    """The Ethernet destination for a query: the IPv4-multicast MAC, or broadcast."""
    o = [int(x) for x in ip.split(".")]
    if 224 <= o[0] <= 239:  # 01:00:5e + low 23 bits of the group address
        return "01:00:5e:%02x:%02x:%02x" % (o[1] & 0x7F, o[2], o[3])
    return "ff:ff:ff:ff:ff:ff"


def _attacker_mac(ip: str, like_mac: str) -> str:
    """A deterministic MAC for the (off-path) poisoning host, under the same vendor OUI as
    the segment's other hosts — a rogue *internal* machine blends in, it isn't a random NIC."""
    oui = like_mac.rsplit(":", 3)[0]
    h = hashlib.sha256(ip.encode()).digest()
    return "%s:%02x:%02x:%02x" % (oui, h[0], h[1], h[2])


def render_namequery(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: NameQueryL7 = flow.l7
    port = _PORT[spec.protocol]
    txid = rng.randint(0, 0xFFFF)

    if spec.protocol == "nbns":
        q_l7 = NBNSHeader(NAME_TRN_ID=txid, NM_FLAGS=0x11) / NBNSQueryRequest(
            QUESTION_NAME=spec.qname.upper()[:15])
    elif spec.protocol == "llmnr":
        q_l7 = LLMNRQuery(id=txid, qd=DNSQR(qname=spec.qname, qtype=spec.qtype))
    else:  # mdns
        q_l7 = DNS(id=0, rd=0, qd=DNSQR(qname=spec.qname, qtype=spec.qtype))

    query = (Ether(src=orig.mac, dst=_l2_dst(flow.dst_ip))
             / IP(src=orig.ip, dst=flow.dst_ip, id=rng.randint(0, 0xFFFF), ttl=_TTL[spec.protocol])
             / UDP(sport=orig.port, dport=port) / q_l7)
    query.time = flow.start_time
    packets = [query]

    if spec.poison_from:
        # The attacker unicasts a spoofed answer back to the victim, claiming the name.
        if spec.protocol == "nbns":
            r_l7 = NBNSHeader(NAME_TRN_ID=txid, OPCODE=0, NM_FLAGS=0x50, ANCOUNT=1) / NBNSQueryResponse(
                RR_NAME=spec.qname.upper()[:15], RDLENGTH=6,
                ADDR_ENTRY=[NBNS_ADD_ENTRY(NB_ADDRESS=spec.poison_from)])
        elif spec.protocol == "llmnr":
            r_l7 = LLMNRResponse(id=txid, qr=1, qd=DNSQR(qname=spec.qname, qtype=spec.qtype),
                                 an=DNSRR(rrname=spec.qname, type=spec.qtype, rdata=spec.poison_from, ttl=30))
        else:  # mdns
            r_l7 = DNS(id=0, qr=1, aa=1, qd=DNSQR(qname=spec.qname, qtype=spec.qtype),
                       an=DNSRR(rrname=spec.qname, type=spec.qtype, rdata=spec.poison_from, ttl=120))
        reply = (Ether(src=_attacker_mac(spec.poison_from, orig.mac), dst=orig.mac)
                 / IP(src=spec.poison_from, dst=orig.ip, id=rng.randint(0, 0xFFFF), ttl=128)
                 / UDP(sport=port, dport=orig.port) / r_l7)
        reply.time = flow.start_time + flow.rtt
        packets.append(reply)

    return RenderResult(packets=packets, expected={"produces": "dns"})
