# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""DHCP renderer: a full DORA (Discover/Offer/Request/Ack) exchange."""

from __future__ import annotations

import random

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import mac2str

from packetforge.compile.tcp import Endpoint
from packetforge.models.flowspec import DhcpL7, Flow
from packetforge.renderers.base import RenderResult


def render_dhcp(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: DhcpL7 = flow.l7
    chaddr = mac2str(orig.mac) + b"\x00" * 10
    xid = rng.randint(0, 0xFFFFFFFF)
    packets = []

    def msg(op: int, mtype: str, ts: float, **bootp):
        client = op == 1
        opts = [("message-type", mtype)]
        if mtype in ("offer", "ack"):
            opts += [("server_id", spec.server_ip), ("lease_time", spec.lease_time),
                     ("subnet_mask", spec.subnet_mask)]
            if spec.gateway:
                opts.append(("router", spec.gateway))
            if spec.dns_server:
                opts.append(("name_server", spec.dns_server))
        else:
            opts.append(("param_req_list", [1, 3, 6, 15]))
            if spec.hostname:
                opts.append(("hostname", spec.hostname))
        p = (
            Ether(src=orig.mac if client else resp.mac, dst="ff:ff:ff:ff:ff:ff" if client else orig.mac)
            / IP(src="0.0.0.0" if client else spec.server_ip,
                 dst="255.255.255.255" if client else spec.assigned_ip,
                 ttl=orig.ttl if client else resp.ttl)
            / UDP(sport=68 if client else 67, dport=67 if client else 68)
            / BOOTP(op=op, xid=xid, chaddr=chaddr, yiaddr=bootp.get("yiaddr", "0.0.0.0"),
                    siaddr=bootp.get("siaddr", "0.0.0.0"))
            / DHCP(options=opts + ["end"])
        )
        p.time = ts
        return p

    t = flow.start_time
    packets.append(msg(1, "discover", t))
    packets.append(msg(2, "offer", t + rng.uniform(0.005, 0.02), yiaddr=spec.assigned_ip, siaddr=spec.server_ip))
    packets.append(msg(1, "request", t + rng.uniform(0.03, 0.06)))
    packets.append(msg(2, "ack", t + rng.uniform(0.07, 0.1), yiaddr=spec.assigned_ip, siaddr=spec.server_ip))

    # DHCP is broadcast; its conn 5-tuple doesn't match the flow, so verify via dhcp.log.
    return RenderResult(packets=packets, expected={"produces": "dhcp", "skip_conn": True})
