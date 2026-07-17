# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Resolve (ip, port, os) into a ready-to-render TCP ``Endpoint``.

Keeps L2-L4 identity (MAC, TTL, window, SYN option order) consistent with the host's
OS, so the packet layer never contradicts what the log layer says the host is.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

import yaml

from packetforge.compile.tcp import Endpoint

_TCP_DIR = Path(__file__).parent / "tcp"
_JA3_DIR = Path(__file__).parent / "ja3"


def mac_for_ip(ip: str, oui: str | None = None) -> str:
    """Deterministic MAC for an IP (stable across runs).

    With an ``oui`` (a real vendor's 3-octet prefix), internal hosts share that vendor
    like a real fleet; otherwise falls back to a locally-administered 0x02 prefix.
    """
    h = hashlib.sha256(f"mac:{ip}".encode()).digest()
    if oui:
        prefix = ":".join(oui.strip().split(":")[:3])
        return prefix + ":" + ":".join(f"{b:02x}" for b in h[:3])
    return "02:" + ":".join(f"{b:02x}" for b in h[:5])


def _to_scapy_options(raw: list) -> list:
    """Convert YAML option rows into scapy TCP option tuples."""
    out = []
    for name, value in raw:
        if name in ("NOP", "EOL"):
            out.append((name, None))
        elif name == "SAckOK":
            out.append(("SAckOK", b""))
        elif name in ("MSS", "WScale"):
            out.append((name, int(value)))
        else:
            raise ValueError(f"unsupported TCP option in profile: {name!r}")
    return out


@lru_cache(maxsize=None)
def _load_tcp_profile(os_name: str) -> tuple:
    path = _TCP_DIR / f"{os_name}.yaml"
    if not path.exists():
        available = sorted(p.stem for p in _TCP_DIR.glob("*.yaml"))
        raise ValueError(f"unknown OS profile {os_name!r}; available: {available}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    # tuple so it's hashable/cacheable; rebuilt into an Endpoint per use.
    return (int(data["ttl"]), int(data["window"]), tuple(map(tuple, data["syn_options"])),
            bool(data.get("tcp_timestamps", False)))


def load_ja3_profile(name: str) -> dict:
    """Load a TLS client fingerprint profile (numeric fields) by name."""
    path = _JA3_DIR / f"{name}.yaml"
    if not path.exists():
        available = sorted(p.stem for p in _JA3_DIR.glob("*.yaml"))
        raise ValueError(f"unknown JA3 profile {name!r}; available: {available}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def resolve_endpoint(ip: str, port: int, os_name: str, oui: str | None = None,
                     window: int | None = None, ttl: int | None = None) -> Endpoint:
    p_ttl, p_window, raw_opts, timestamps = _load_tcp_profile(os_name)
    return Endpoint(
        ip=ip,
        port=port,
        mac=mac_for_ip(ip, oui),
        ttl=ttl if ttl is not None else p_ttl,
        window=window if window is not None else p_window,
        syn_options=_to_scapy_options([list(o) for o in raw_opts]),
        timestamps=timestamps,
    )
