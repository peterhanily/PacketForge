# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Opaque-TCP renderer: an honest TCP shell for binary protocols.

Correct handshake, teardown, and volumetrics; the application bytes are opaque and
sized to the spec. No L7 dissection is claimed — this is what a sensor without the
right dissector sees, so it is realistic precisely by being honest.
"""

from __future__ import annotations

import random

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, OpaqueTcpL7
from packetforge.renderers.base import RenderResult, filler_bytes


def render_opaque_tcp(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: OpaqueTcpL7 = flow.l7
    messages = []
    # An optional literal prefix (signature-conditioning) rides at the start of the
    # originator stream; without it, output is byte-identical to before (lit == b"").
    lit = bytes.fromhex(spec.orig_literal_hex) if spec.orig_literal_hex else b""
    n_orig = max(spec.orig_bytes, len(lit))
    if n_orig:
        messages.append(TcpMessage(True, lit + filler_bytes(n_orig - len(lit), rng)))
    if spec.resp_bytes:
        messages.append(TcpMessage(False, filler_bytes(spec.resp_bytes, rng)))

    result = build_tcp_flow(
        orig, resp, messages,
        start_time=flow.start_time, rtt=flow.rtt, rng=rng,
        conn_state=flow.conn_state, min_segments=spec.segments,
    )
    conn = dict(result.summary)
    conn["proto"] = "tcp"
    return RenderResult(packets=result.packets, expected={"conn": conn})
