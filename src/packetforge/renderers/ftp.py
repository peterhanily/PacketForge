# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""FTP renderer: a cleartext control session (server greets first)."""

from __future__ import annotations

import random
from dataclasses import replace

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, FtpL7
from packetforge.renderers.base import RenderResult
from packetforge.renderers.file_bodies import file_for

# Reply codes for a few common commands; anything else gets a generic 200.
_REPLIES = {"SYST": "215 UNIX Type: L8", "PWD": '257 "/"', "TYPE": "200 Switching to Binary mode.",
            "FEAT": "211 End", "LIST": "150 Here comes the directory listing."}


def render_ftp(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: FtpL7 = flow.l7
    C, S = True, False

    def line(s: str) -> bytes:
        return s.encode() + b"\r\n"

    messages = [
        TcpMessage(S, line(spec.banner)),
        TcpMessage(C, line(f"USER {spec.user}")),
        TcpMessage(S, line("331 Please specify the password.")),
        TcpMessage(C, line(f"PASS {spec.password}")),
        TcpMessage(S, line("230 Login successful.")),
    ]
    for cmd in spec.commands:
        verb = cmd.split(" ", 1)[0].upper()
        messages.append(TcpMessage(C, line(cmd)))
        messages.append(TcpMessage(S, line(_REPLIES.get(verb, "200 OK."))))

    data_packets: list = []
    if spec.retrieve_file:
        # Passive mode: server advertises a data port; the client opens a second
        # connection to it and the server streams the file over it (RETR = download).
        content, _ = file_for(spec.retrieve_file, spec.file_bytes, rng)
        pasv_port = 50000 + rng.randint(1, 15000)
        p1, p2 = pasv_port >> 8, pasv_port & 0xFF
        octets = resp.ip.replace(".", ",")
        messages += [
            TcpMessage(C, line("PASV")),
            TcpMessage(S, line(f"227 Entering Passive Mode ({octets},{p1},{p2}).")),
            TcpMessage(C, line(f"RETR {spec.retrieve_file}")),
            TcpMessage(S, line("150 Opening BINARY mode data connection.")),
            TcpMessage(S, line("226 Transfer complete.")),
        ]
        data_client = replace(orig, port=(orig.port + 1) & 0xFFFF or 1025)
        data_server = replace(resp, port=pasv_port)
        data = build_tcp_flow(data_client, data_server, [TcpMessage(S, content)],
                              start_time=flow.start_time + 1.5, rtt=flow.rtt, rng=rng,
                              conn_state="SF")
        data_packets = data.packets

    messages.append(TcpMessage(C, line("QUIT")))
    messages.append(TcpMessage(S, line("221 Goodbye.")))

    result = build_tcp_flow(orig, resp, messages, start_time=flow.start_time,
                            rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
    conn = dict(result.summary)
    conn["service"] = "ftp"  # Zeek tagging the conn 'ftp' confirms the analyzer ran
    conn["proto"] = "tcp"
    return RenderResult(packets=result.packets + data_packets, expected={"conn": conn})
