# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""LDAP renderer: a simple bind (+ optional searches) — the AD directory workhorse."""

from __future__ import annotations

import random

from scapy.layers.ldap import (
    LDAP,
    LDAP_Authentication_simple,
    LDAP_BindRequest,
    LDAP_BindResponse,
    LDAP_SearchRequest,
    LDAP_SearchResponseResultDone,
)

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, LdapL7
from packetforge.renderers.base import RenderResult


def render_ldap(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: LdapL7 = flow.l7
    mid = 1
    messages = [
        TcpMessage(True, bytes(LDAP(messageID=mid, protocolOp=LDAP_BindRequest(
            version=3, bind_name=spec.bind_dn.encode(),
            authentication=LDAP_Authentication_simple(spec.password.encode()))))),
        # Omit the optional referral / serverSaslCreds fields: scapy otherwise encodes
        # them as empty context tags (a3 00 a7 00 87 00), which Wireshark's BER/LDAP
        # dissector rejects as "field beyond the end of the sequence".
        TcpMessage(False, bytes(LDAP(messageID=mid, protocolOp=LDAP_BindResponse(
            resultCode=0, matchedDN=b"", diagnosticMessage=b"",
            referral=None, serverSaslCreds=None, serverSaslCredsWrap=None)))),
    ]
    for base in spec.searches:
        mid += 1
        messages.append(TcpMessage(True, bytes(LDAP(messageID=mid, protocolOp=LDAP_SearchRequest(
            baseObject=base.encode())))))
        messages.append(TcpMessage(False, bytes(LDAP(messageID=mid, protocolOp=LDAP_SearchResponseResultDone(
            resultCode=0, matchedDN=b"", diagnosticMessage=b"", referral=None)))))

    result = build_tcp_flow(orig, resp, messages, start_time=flow.start_time,
                            rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
    conn = dict(result.summary)
    conn["proto"] = "tcp"
    return RenderResult(packets=result.packets, expected={"conn": conn, "produces": "ldap"})
