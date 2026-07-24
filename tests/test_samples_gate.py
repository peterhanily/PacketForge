# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Regression guard: every committed sample capture must pass the zeek+tshark gate.

The gallery's whole claim is that these captures are Zeek-clean and tshark-clean (DESIGN.md
§7). This asserts it on the *committed* pcaps directly — so a change that reintroduces a Zeek
weird or a tshark malformation into any shipped sample fails CI, not a hunter's trust.
"""

from __future__ import annotations

import glob

import pytest

from packetforge.validation.roundtrip import gate_pcap, validators_available

_CAPTURES = sorted(glob.glob("samples/*/capture*.pcap"))


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.skipif(not _CAPTURES, reason="no committed sample captures found")
@pytest.mark.parametrize("pcap", _CAPTURES)
def test_committed_sample_passes_strict_gate(pcap):
    report = gate_pcap(pcap)
    assert report["ok"], f"{pcap} fails the gate: {report}"
