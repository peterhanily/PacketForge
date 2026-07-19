# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Compile a FlowSet to an ordered packet timeline and a .pcap.

This is the parse/render/output split borrowed from Flowsynth: the FlowSet is the
parsed IR, each flow is rendered by its protocol renderer, and the merged, time-
ordered packets are written to libpcap. Every flow is seeded independently from its
``flow_id`` so output is byte-identical across runs and order-independent.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scapy.layers.l2 import CookedLinux, Ether
from scapy.utils import mac2str, wrpcap

from packetforge.fingerprints import resolve_endpoint
from packetforge.models.flowspec import Flow, FlowSet
from packetforge.renderers import RENDERERS


def _to_linux_sll(packets: list) -> list:
    """Rewrite Ethernet frames as Linux SLL (cooked) — what a host-side tcpdump yields.

    The capture point changes the link layer: a SPAN/TAP sees Ethernet; a per-host
    tcpdump sees SLL with no destination MAC. Modeling this is the 'kind of tap' signal.
    """
    out = []
    for p in packets:
        if Ether in p:
            eth = p[Ether]
            sll = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6,
                              src=mac2str(eth.src), proto=eth.type) / eth.payload
            sll.time = p.time
            out.append(sll)
        else:
            out.append(p)
    return out


@dataclass
class CompiledFlow:
    flow_id: str
    kind: str
    key: dict  # {orig_h, orig_p, resp_h, resp_p, proto} for locating the Zeek row
    expected: dict  # renderer-measured expectations, checked against Zeek
    ir_expect: Optional[dict] = None  # author-declared expectations from IR


@dataclass
class CompileResult:
    packets: list = field(default_factory=list)
    flows: list = field(default_factory=list)  # list[CompiledFlow]


def _seed(flow: Flow, salt: str) -> random.Random:
    ident = f"{salt}|{flow.flow_id}|{flow.src_ip}:{flow.src_port}>{flow.dst_ip}:{flow.dst_port}"
    return random.Random(int.from_bytes(hashlib.sha256(ident.encode()).digest()[:8], "big"))


def compile_flowset(fs: FlowSet, salt: str = "") -> CompileResult:
    from packetforge.compile.tcp import _TEXTURE, TEXTURES

    result = CompileResult()
    token = _TEXTURE.set(TEXTURES[fs.capture.texture])
    try:
        _compile_flows(fs, salt, result)
    finally:
        _TEXTURE.reset(token)
    # Stable sort by timestamp; equal-time packets keep deterministic insertion order.
    result.packets.sort(key=lambda p: float(p.time))
    if fs.capture.link_type == "linux_sll":
        result.packets = _to_linux_sll(result.packets)
    return result


def _compile_flows(fs: FlowSet, salt: str, result: CompileResult) -> None:
    from packetforge.compile.tcp import _SEG_BYTES

    for flow in fs.flows:
        kind = flow.l7.kind
        if kind not in RENDERERS:
            raise ValueError(
                f"no renderer registered for L7 kind {kind!r} (flow_id={flow.flow_id}); "
                f"available: {sorted(RENDERERS)}"
            )
        rng = _seed(flow, salt)
        oui = fs.capture.mac_oui
        orig = resolve_endpoint(flow.src_ip, flow.src_port, flow.src_os, oui,
                                window=flow.syn_window, ttl=flow.syn_ttl)
        resp = resolve_endpoint(flow.dst_ip, flow.dst_port, flow.dst_os, oui)
        seg_token = _SEG_BYTES.set(flow.seg_bytes)
        try:
            rendered = RENDERERS[kind](flow, orig, resp, rng)
        finally:
            _SEG_BYTES.reset(seg_token)
        # Exact-duration control: linearly rescale this flow's packet times to span the target
        # duration, so real Zeek recomputes exactly flow.duration (used to agree with an upstream
        # source of truth). Only touches timestamps — byte counts, conn_state and history are intact.
        if flow.duration is not None and len(rendered.packets) >= 2:
            t0 = min(float(p.time) for p in rendered.packets)
            span = max(float(p.time) for p in rendered.packets) - t0
            if span > 0:
                scale = flow.duration / span
                for p in rendered.packets:
                    p.time = t0 + (float(p.time) - t0) * scale
        result.packets.extend(rendered.packets)
        result.flows.append(
            CompiledFlow(
                flow_id=flow.flow_id,
                kind=kind,
                key={
                    "orig_h": flow.src_ip,
                    "orig_p": flow.src_port,
                    "resp_h": flow.dst_ip,
                    "resp_p": flow.dst_port,
                    "proto": flow.transport,
                },
                expected=rendered.expected,
                ir_expect=flow.expect.model_dump(exclude_none=True) if flow.expect else None,
            )
        )


def write_pcap(fs: FlowSet, out_path: str | Path, salt: str = "") -> CompileResult:
    result = compile_flowset(fs, salt=salt)
    wrpcap(str(out_path), result.packets)
    return result
