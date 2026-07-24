# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Inert-by-construction, asserted across EVERY attack (not just the BZAR pack).

test_bzar_pack checks that no capability/LOLBin token appears on the wire for the 8 BZAR
attacks — whose DCE-RPC stubs are zero filler, so a raw substring check is exact. The other
attacks carry large random-filler bodies (letters/digits/space), where a short token like
``wmic`` appears by pure chance in ~1 MB of filler. That is inert noise, not a smuggled
capability. This asserts the real invariant across all 26 attacks: a forbidden token is only
ever a *coincidental* match inside the punctuation-free filler alphabet — a functional command
(which needs punctuation: ``.exe``, ``/c``, ``\\``, ``-enc``, ``:``) never appears on the wire.
"""

from __future__ import annotations

import random

import pytest
from scapy.packet import Raw

from packetforge.compile.timeline import compile_flowset
from packetforge.environments import load_environment
from packetforge.models.flowspec import FlowSet
from packetforge.scenarios import ATTACKS, build_attack

# LOLBin / command tokens that would indicate a real capability was smuggled onto the wire.
_FORBIDDEN = [
    b"cmd.exe", b"cmd /c", b"cmd /k", b"powershell", b"pwsh", b"rundll32", b"regsvr32",
    b"certutil", b"bitsadmin", b"mshta", b"wscript", b"cscript", b"wmic", b"net user",
    b"net localgroup", b"whoami", b"schtasks", b"\\System32\\", b"-enc ", b"-EncodedCommand",
]
# The inert filler alphabet (renderers/file_bodies.py): letters, digits, space — no
# punctuation, so a functional command cannot be spelled out within it.
_FILLER = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")
_START = 1_700_000_000.0


def _envfor(name: str) -> str:
    if "imds" in name:
        return "aws-vpc"
    if "cloud-exfil" in name:
        return "azure-vnet"
    if "k8s" in name:
        return "k8s"
    if "modbus" in name:
        return "ot"
    return "office"


def _non_coincidental_hits(blob: bytes):
    """Forbidden tokens on the wire that are NOT a chance match inside inert filler: a token
    is coincidental iff a ±16-byte window around it is entirely filler-alphabet (so it fell
    inside a random filler body, with no command punctuation to make it functional)."""
    low = blob.lower()
    out = []
    for tok in _FORBIDDEN:
        start = 0
        while (i := low.find(tok.lower(), start)) >= 0:
            start = i + 1
            window = blob[max(0, i - 16):i + len(tok) + 16]
            if not all(c in _FILLER for c in window):
                out.append((tok, window))
    return out


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_no_smuggled_capability_on_the_wire(name):
    env = load_environment(_envfor(name))
    comp = compile_flowset(FlowSet(flows=build_attack(name, env, _START, random.Random(1)).flows))
    blob = b"".join(bytes(p[Raw].load) for p in comp.packets if p.haslayer(Raw))
    hits = _non_coincidental_hits(blob)
    assert not hits, f"{name}: non-coincidental capability token(s) on the wire: {hits[:3]}"
