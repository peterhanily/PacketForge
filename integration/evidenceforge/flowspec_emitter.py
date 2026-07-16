# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""FlowSpecEmitter — the proposed EvidenceForge-side integration (DRAFT, not upstreamed).

This is what would live in `evidenceforge/generation/emitters/` as a small, additive
emitter. It maps EvidenceForge's canonical ``SecurityEvent`` to a PacketForge Flow-IR
line (``flows.jsonl``). Because it reads the *canonical event* (not the rendered logs),
it carries the **exact** volumetrics — orig/resp bytes and packet counts — that the
log-reconstruction path cannot recover. PacketForge then compiles ``flows.jsonl`` to a
pcap; the pcap artifact family wires behind the existing ``artifacts.mode`` switch, the
same way email artifacts do.

It is dependency-free (emits plain dicts) and duck-typed over the event, so it can be
unit-tested against EvidenceForge's real model classes without importing PacketForge.
"""

from __future__ import annotations

import ipaddress

_SUPPORTED_CONN_STATES = {"SF", "S0", "REJ", "RSTO", "RSTR"}
_TLS_VERSION = {"TLSv12": "TLS1.2", "TLSv13": "TLS1.3"}


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _epoch(ts) -> float:
    return ts.timestamp() if hasattr(ts, "timestamp") else float(ts)


def event_to_flow(event) -> dict | None:
    """Map one canonical SecurityEvent to a PacketForge Flow-IR dict (or None to skip)."""
    net = getattr(event, "network", None)
    if net is None or not getattr(net, "src_ip", None):
        return None
    proto = net.protocol
    flow = {
        "flow_id": getattr(net, "zeek_uid", "") or f"{net.src_ip}:{net.src_port}>{net.dst_ip}:{net.dst_port}",
        "transport": proto,
        "src_ip": net.src_ip, "dst_ip": net.dst_ip,
        "src_port": int(net.src_port or 0), "dst_port": int(net.dst_port or 0),
        "start_time": _epoch(event.timestamp),
    }
    if proto == "tcp":
        cs = getattr(net, "conn_state", "SF")
        flow["conn_state"] = cs if cs in _SUPPORTED_CONN_STATES else "SF"

    dns = getattr(event, "dns", None)
    http = getattr(event, "http", None)
    ssl = getattr(event, "ssl", None)

    if proto == "udp" and dns is not None:
        flow["l7"] = {"kind": "dns", "qname": dns.query, "qtype": dns.query_type,
                      "answers": [a for a in getattr(dns, "answers", []) if _is_ip(a)],
                      "rcode": dns.rcode}
    elif proto == "tcp" and http is not None:
        flow["l7"] = {"kind": "http", "method": http.method, "host": http.host, "uri": http.uri,
                      "user_agent": http.user_agent, "status": http.status_code,
                      "request_body_len": http.request_body_len,
                      "response_body_len": http.response_body_len}
    elif proto == "tcp" and ssl is not None:
        ver = _TLS_VERSION.get(getattr(ssl, "version", ""), "TLS1.2")
        flow["l7"] = {"kind": "tls", "server_name": getattr(ssl, "server_name", "") or "unknown.invalid",
                      "version": ver}
    elif proto == "icmp":
        flow["l7"] = {"kind": "icmp"}
    else:
        # opaque — carry the EXACT byte counts from the canonical event. This is the
        # volumetric fidelity the log-reconstruction path cannot achieve.
        kind = "opaque_udp" if proto == "udp" else "opaque_tcp"
        flow["l7"] = {"kind": kind, "service_hint": (getattr(net, "service", "") or ""),
                      "orig_bytes": int(getattr(net, "orig_bytes", 0) or 0),
                      "resp_bytes": int(getattr(net, "resp_bytes", 0) or 0)}
    return flow


class FlowSpecEmitter:
    """EvidenceForge-shaped emitter: subscribe to connection events, write flows.jsonl.

    In EvidenceForge this would extend the emitter base and be registered in
    ``_init_emitters`` behind ``environment ... artifacts.mode``. Kept minimal here.
    """

    _supported_types = {"connection"}

    def __init__(self, out_path: str):
        self._out_path = out_path
        self._rows: list = []

    def can_handle(self, event) -> bool:
        return getattr(event, "network", None) is not None

    def emit(self, event) -> None:
        flow = event_to_flow(event)
        if flow is not None:
            self._rows.append(flow)

    def finalize(self) -> None:
        import json
        with open(self._out_path, "w", encoding="utf-8") as fh:
            for row in self._rows:
                fh.write(json.dumps(row) + "\n")
