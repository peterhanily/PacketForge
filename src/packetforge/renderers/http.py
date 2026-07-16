# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Cleartext HTTP renderer over the TCP core."""

from __future__ import annotations

import base64
import random

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, HttpL7
from packetforge.renderers.base import HTTP_REASONS, RenderResult, filler_bytes
from packetforge.renderers.file_bodies import file_for


def _headers_block(lines: list[str], extra: dict) -> str:
    for k, v in extra.items():
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n"


def render_http(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: HttpL7 = flow.l7

    req_body = filler_bytes(spec.request_body_len, rng)
    req_lines = [f"{spec.method} {spec.uri} HTTP/1.1", f"Host: {spec.host}"]
    if spec.user_agent:  # omit an empty header rather than sending "User-Agent: "
        req_lines.append(f"User-Agent: {spec.user_agent}")
    req_lines.append("Accept: */*")
    if req_body:
        req_lines.append(f"Content-Length: {len(req_body)}")
    request = _headers_block(req_lines, spec.request_headers).encode() + req_body

    # A real, typed file the responder "serves", so Export Objects yields a valid file.
    ctype = spec.response_headers.get("Content-Type")
    if spec.response_body_b64 is not None:
        resp_body = base64.b64decode(spec.response_body_b64)
    else:
        resp_body, detected_ct = file_for(spec.uri, spec.response_body_len, rng)
        ctype = ctype or detected_ct
    if spec.status in (204, 304):
        resp_body = b""  # these responses carry no body (RFC 7230)
    reason = spec.reason or HTTP_REASONS.get(spec.status, "OK")
    resp_lines = [
        f"HTTP/1.1 {spec.status} {reason}",
        "Server: nginx",
        f"Content-Type: {ctype or 'text/html; charset=utf-8'}",
        f"Content-Length: {len(resp_body)}",
    ]
    extra = {k: v for k, v in spec.response_headers.items() if k != "Content-Type"}
    response = _headers_block(resp_lines, extra).encode() + resp_body

    result = build_tcp_flow(
        orig, resp,
        [TcpMessage(True, request), TcpMessage(False, response)],
        start_time=flow.start_time, rtt=flow.rtt, rng=rng, conn_state=flow.conn_state,
    )

    conn = dict(result.summary)
    conn["service"] = "http"
    conn["proto"] = "tcp"
    expected = {
        "conn": conn,
        "http": {
            "method": spec.method,
            "host": spec.host,
            "uri": spec.uri,
            "user_agent": spec.user_agent,
            "status_code": spec.status,
            "request_body_len": len(req_body),
            "response_body_len": len(resp_body),
        },
    }
    return RenderResult(packets=result.packets, expected=expected)
