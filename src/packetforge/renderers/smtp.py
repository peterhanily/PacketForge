# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Cleartext SMTP delivery renderer over the TCP core.

Renders the real command/response ping-pong (banner, EHLO, MAIL FROM, RCPT TO, DATA,
message, QUIT) so Zeek's SMTP analyzer logs mailfrom/rcptto/subject to smtp.log. The
server greets first, so the first application message travels responder->originator.
"""

from __future__ import annotations

import random

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, SmtpL7
from packetforge.renderers.base import RenderResult, text_filler


def _angle(addr: str) -> str:
    return addr if addr.startswith("<") else f"<{addr}>"


def _bare(addr: str) -> str:
    return addr.strip("<>")


def render_smtp(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: SmtpL7 = flow.l7
    C, S = True, False  # message direction: client=originator, server=responder

    def line(s: str) -> bytes:
        return s.encode() + b"\r\n"

    messages = [
        TcpMessage(S, line(f"220 {spec.server_banner}")),
        TcpMessage(C, line(f"EHLO {spec.helo}")),
        TcpMessage(S, line("250-mail.example") + line("250-PIPELINING") + line("250 8BITMIME")),
        TcpMessage(C, line(f"MAIL FROM:{_angle(spec.mail_from)}")),
        TcpMessage(S, line("250 2.1.0 Ok")),
    ]
    for rcpt in spec.rcpt_to:
        messages.append(TcpMessage(C, line(f"RCPT TO:{_angle(rcpt)}")))
        messages.append(TcpMessage(S, line("250 2.1.5 Ok")))
    messages.append(TcpMessage(C, line("DATA")))
    messages.append(TcpMessage(S, line("354 End data with <CR><LF>.<CR><LF>")))

    headers = [
        f"From: {spec.from_header or spec.mail_from}",
        f"To: {spec.to_header or ', '.join(spec.rcpt_to)}",
        f"Subject: {spec.subject}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=us-ascii",
    ]
    body = text_filler(spec.body_len, rng)
    dot = b"\r\n".join(h.encode() for h in headers) + b"\r\n\r\n" + body + b"\r\n.\r\n"
    messages.append(TcpMessage(C, dot))
    messages.append(TcpMessage(S, line("250 2.0.0 Ok: queued")))
    messages.append(TcpMessage(C, line("QUIT")))
    messages.append(TcpMessage(S, line("221 2.0.0 Bye")))

    result = build_tcp_flow(
        orig, resp, messages, start_time=flow.start_time, rtt=flow.rtt,
        rng=rng, conn_state=flow.conn_state,
    )
    conn = dict(result.summary)
    conn["service"] = "smtp"
    conn["proto"] = "tcp"
    expected = {
        "conn": conn,
        # Zeek strips the angle brackets from MAIL FROM / RCPT TO.
        "smtp": {
            "mailfrom": _bare(spec.mail_from),
            "rcptto": {_bare(r) for r in spec.rcpt_to},
            "subject": spec.subject,
        },
    }
    return RenderResult(packets=result.packets, expected=expected)
