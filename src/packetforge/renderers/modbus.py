# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Modbus/TCP renderer: read-holding-registers exchanges (OT/ICS)."""

from __future__ import annotations

import random

from scapy.contrib.modbus import (
    ModbusADURequest,
    ModbusADUResponse,
    ModbusPDU03ReadHoldingRegistersRequest,
    ModbusPDU03ReadHoldingRegistersResponse,
)

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, ModbusL7
from packetforge.renderers.base import RenderResult


def render_modbus(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: ModbusL7 = flow.l7
    messages = []
    for i in range(spec.count):
        tid = (i + 1) & 0xFFFF
        req = bytes(ModbusADURequest(transId=tid, unitId=spec.unit_id)
                    / ModbusPDU03ReadHoldingRegistersRequest(startAddr=spec.start_addr,
                                                             quantity=spec.quantity))
        rsp = bytes(ModbusADUResponse(transId=tid, unitId=spec.unit_id)
                    / ModbusPDU03ReadHoldingRegistersResponse(
                        registerVal=[rng.randint(0, 0xFFFF) for _ in range(spec.quantity)]))
        messages += [TcpMessage(True, req), TcpMessage(False, rsp)]

    result = build_tcp_flow(orig, resp, messages, start_time=flow.start_time,
                            rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
    conn = dict(result.summary)
    conn["service"] = "modbus"
    conn["proto"] = "tcp"
    return RenderResult(packets=result.packets, expected={"conn": conn, "produces": "modbus"})
