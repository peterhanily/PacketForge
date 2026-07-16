# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""JA3 TLS client fingerprinting.

JA3 = md5 of ``SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`` where
each list is ``-``-joined decimals and GREASE values are excluded. Because the
ClientHello PacketForge emits is built from the same numeric profile these values
come from, the emitted bytes and the declared JA3 agree by construction.
"""

from __future__ import annotations

import hashlib


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa) are excluded from JA3."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _join(values: list) -> str:
    return "-".join(str(v) for v in values if not is_grease(v))


def ja3_string(version: int, ciphers: list, extensions: list,
               curves: list, point_formats: list) -> str:
    return ",".join([
        str(version),
        _join(ciphers),
        _join(extensions),
        _join(curves),
        _join(point_formats),
    ])


def ja3_hash(version: int, ciphers: list, extensions: list,
             curves: list, point_formats: list) -> str:
    s = ja3_string(version, ciphers, extensions, curves, point_formats)
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()


def ja3_to_profile(ja3_string_value: str) -> dict:
    """Parse a JA3 string into a TLS client profile the renderer can emit.

    Lets an analog reproduce a JA3 observed on the wire (e.g. a malware fingerprint the
    profiler extracted from a reference capture) — the emitted ClientHello then computes
    the same JA3. Signature algorithms aren't in JA3, so a common default is supplied.
    """
    parts = ja3_string_value.split(",")
    if len(parts) != 5:
        raise ValueError(f"not a JA3 string: {ja3_string_value!r}")

    def nums(s: str) -> list:
        return [int(x) for x in s.split("-") if x != ""]

    ciphers = nums(parts[1])
    return {
        "profile": "ja3:" + ja3_string_value,
        "grease": False,
        "tls_version": int(parts[0]),
        "ciphers": ciphers,
        "extensions": nums(parts[2]),
        "curves": nums(parts[3]),
        "point_formats": nums(parts[4]),
        "signature_algorithms": [1027, 1025, 1283, 1281, 1537, 1281, 1025],
        "server_cipher": next((c for c in ciphers if c not in (0,)), 49200),
    }
