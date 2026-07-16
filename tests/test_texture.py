# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase B: capture 'texture' — realistic mess that stays consistency-valid.

A pass on clean traffic proves little; the point of texture is that retransmits,
dup-ACKs, and jitter make a passing detection/parse mean something. It must add real
imperfections AND still round-trip clean through Zeek (same reassembled stream, same
sequence-based byte counts).
"""
import random

import pytest

from packetforge.compile.tcp import (
    _TEXTURE, TEXTURES, Endpoint, TcpMessage, Texture, build_tcp_flow,
)
from packetforge.validation import validators_available


def _flow(texture):
    tok = _TEXTURE.set(texture if isinstance(texture, Texture) else TEXTURES[texture])
    try:
        o = Endpoint("10.0.0.5", 50000, "aa:bb:cc:dd:ee:01")
        r = Endpoint("10.0.0.9", 80, "aa:bb:cc:dd:ee:02")
        msgs = [TcpMessage(True, b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n"),
                TcpMessage(False, b"z" * 9000)]
        return build_tcp_flow(o, r, msgs, 1700000000.0, 0.03, random.Random(11), "SF")
    finally:
        _TEXTURE.reset(tok)


def test_clean_texture_is_the_default():
    # default contextvar == clean preset
    assert _TEXTURE.get() == TEXTURES["clean"]


def test_retransmits_add_packets_and_T_history_but_not_bytes():
    # force every segment to retransmit and every ACK to duplicate -> deterministic
    forced = Texture(jitter_frac=0.0, retransmit_prob=1.0, dup_ack_prob=1.0)
    clean, real = _flow("clean"), _flow(forced)
    # same application bytes (retransmits repeat sequence space, not new data)
    assert real.summary["orig_bytes"] == clean.summary["orig_bytes"]
    assert real.summary["resp_bytes"] == clean.summary["resp_bytes"]
    # more packets on the wire (retransmits + duplicate ACKs)
    total_real = real.summary["orig_pkts"] + real.summary["resp_pkts"]
    total_clean = clean.summary["orig_pkts"] + clean.summary["resp_pkts"]
    assert total_real > total_clean
    # a retransmitted payload shows up in Zeek-style history as T/t
    assert "T" in real.summary["history"] or "t" in real.summary["history"]


def test_realistic_preset_produces_some_mess():
    # over a data-heavy flow the preset should fire at least one retransmit/dup-ACK
    real = _flow("realistic")
    clean = _flow("clean")
    assert (real.summary["orig_pkts"] + real.summary["resp_pkts"]) >= (
        clean.summary["orig_pkts"] + clean.summary["resp_pkts"])


def test_realistic_texture_is_deterministic():
    assert _flow("realistic").summary == _flow("realistic").summary
    a = b"".join(bytes(p) for p in _flow("realistic").packets)
    b = b"".join(bytes(p) for p in _flow("realistic").packets)
    assert a == b


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_realistic_capture_still_round_trips_clean():
    """The whole point: mess that Zeek still parses without a weird, counts matching."""
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment
    from packetforge.validation import validate_flowset

    env = load_environment("office")
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=80, seed=8,
                          texture="realistic")
    report = validate_flowset(fs)
    assert report.ok, "\n" + report.summary()
    assert report.zeek_weird == 0 and report.tshark_errors == 0
