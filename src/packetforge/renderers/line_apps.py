# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Cleartext line-oriented app renderers: POP3, IMAP, IRC."""

from __future__ import annotations

import random

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, ImapL7, IrcL7, Pop3L7
from packetforge.renderers.base import RenderResult

C, S = True, False


def _line(s: str) -> bytes:
    return s.encode() + b"\r\n"


def _finish(flow, orig, resp, rng, messages, *, service=None, produces=None) -> RenderResult:
    result = build_tcp_flow(orig, resp, messages, start_time=flow.start_time,
                            rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
    conn = dict(result.summary)
    conn["proto"] = "tcp"
    if service:
        conn["service"] = service
    expected = {"conn": conn}
    if produces:
        expected["produces"] = produces
    return RenderResult(packets=result.packets, expected=expected)


def render_pop3(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: Pop3L7 = flow.l7
    messages = [
        TcpMessage(S, _line("+OK POP3 server ready")),
        TcpMessage(C, _line(f"USER {spec.user}")), TcpMessage(S, _line("+OK")),
        TcpMessage(C, _line(f"PASS {spec.password}")), TcpMessage(S, _line("+OK logged in")),
        TcpMessage(C, _line("STAT")), TcpMessage(S, _line("+OK 2 320")),
        TcpMessage(C, _line("QUIT")), TcpMessage(S, _line("+OK bye")),
    ]
    return _finish(flow, orig, resp, rng, messages, service="pop3")


def render_imap(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: ImapL7 = flow.l7
    messages = [
        TcpMessage(S, _line("* OK IMAP4rev1 server ready")),
        TcpMessage(C, _line(f"a1 LOGIN {spec.user} {spec.password}")),
        TcpMessage(S, _line("a1 OK LOGIN completed")),
        TcpMessage(C, _line("a2 SELECT INBOX")),
        TcpMessage(S, _line("* 3 EXISTS") + _line("a2 OK [READ-WRITE] SELECT completed")),
        TcpMessage(C, _line("a3 LOGOUT")),
        TcpMessage(S, _line("* BYE Logging out") + _line("a3 OK LOGOUT completed")),
    ]
    return _finish(flow, orig, resp, rng, messages, service="imap")


def render_irc(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: IrcL7 = flow.l7
    messages = [
        TcpMessage(C, _line(f"NICK {spec.nick}")),
        TcpMessage(C, _line(f"USER {spec.nick} 0 * :{spec.nick}")),
        TcpMessage(S, _line(f":irc.example 001 {spec.nick} :Welcome")),
        TcpMessage(C, _line(f"JOIN {spec.channel}")),
        TcpMessage(S, _line(f":{spec.nick} JOIN {spec.channel}")),
        TcpMessage(C, _line(f"PRIVMSG {spec.channel} :checkin")),
        TcpMessage(C, _line("QUIT :bye")),
    ]
    return _finish(flow, orig, resp, rng, messages, produces="irc")
