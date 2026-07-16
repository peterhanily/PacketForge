# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""SSH renderer: cleartext version banners + KEXINIT, then opaque encrypted packets.

Post-banner traffic is framed as valid RFC 4253 binary packets (length-prefixed) so
Zeek's SSH analyzer parses the flow and logs ssh.log without malformed events; the
packet contents are opaque.
"""

from __future__ import annotations

import random

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, SshL7
from packetforge.renderers.base import RenderResult

_KEX_LISTS = [
    "curve25519-sha256", "ssh-ed25519",
    "chacha20-poly1305@openssh.com", "chacha20-poly1305@openssh.com",
    "umac-64-etm@openssh.com", "umac-64-etm@openssh.com",
    "none", "none", "", "",
]


def _namelist(s: str) -> bytes:
    b = s.encode()
    return len(b).to_bytes(4, "big") + b


def _ssh_packet(payload: bytes, rng: random.Random) -> bytes:
    """Wrap a payload in an RFC 4253 binary packet (length + pad_len + payload + pad)."""
    pad_len = 8 - ((5 + len(payload)) % 8)
    if pad_len < 4:
        pad_len += 8
    packet_len = 1 + len(payload) + pad_len
    return packet_len.to_bytes(4, "big") + bytes([pad_len]) + payload + rng.randbytes(pad_len)


def _kexinit(rng: random.Random) -> bytes:
    payload = bytes([20]) + rng.randbytes(16)  # SSH_MSG_KEXINIT + cookie
    for nl in _KEX_LISTS:
        payload += _namelist(nl)
    payload += bytes([0]) + (0).to_bytes(4, "big")  # first_kex_follows + reserved
    return payload


def render_ssh(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: SshL7 = flow.l7
    half = max(1, spec.payload_bytes // 2)
    messages = [
        TcpMessage(True, (spec.client_version + "\r\n").encode()),
        TcpMessage(False, (spec.server_version + "\r\n").encode()),
        TcpMessage(True, _ssh_packet(_kexinit(rng), rng)),
        TcpMessage(False, _ssh_packet(_kexinit(rng), rng)),
        TcpMessage(True, _ssh_packet(bytes([21]), rng)),   # NEWKEYS
        TcpMessage(False, _ssh_packet(bytes([21]), rng)),
        TcpMessage(True, _ssh_packet(rng.randbytes(half), rng)),      # encrypted, opaque
        TcpMessage(False, _ssh_packet(rng.randbytes(half), rng)),
    ]
    result = build_tcp_flow(orig, resp, messages, start_time=flow.start_time,
                            rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
    conn = dict(result.summary)
    conn["service"] = "ssh"
    conn["proto"] = "tcp"
    return RenderResult(packets=result.packets,
                        expected={"conn": conn, "produces": "ssh",
                                  "ssh": {"client": spec.client_version,
                                          "server": spec.server_version}})
