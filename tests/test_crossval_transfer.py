# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase D: multi-tool cross-validation + transfer proof."""

import random

import pytest

from packetforge.validation import validators_available


def _synthetic_office(tmp_path, seed=1):
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment
    from packetforge.scenarios import build_attack
    env = load_environment("office")
    intr = build_attack("kerberoasting", env, 1700000100.0, random.Random(seed))
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=60, seed=seed,
                          storyline=intr.flows)
    pcap = tmp_path / "office.pcap"
    write_pcap(fs, pcap)
    return pcap, fs


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_crossval_independent_tools_agree(tmp_path):
    from packetforge.crossval import cross_validate
    pcap, fs = _synthetic_office(tmp_path)
    report = cross_validate(pcap, flowset=fs, workdir=str(tmp_path / "xv"))
    # zeek + tshark at minimum ran and parsed cleanly
    assert report.tools["zeek"]["available"] and report.tools["zeek"]["parsed"]
    assert report.tools["tshark"]["parsed"]
    # zeek and tshark independently see kerberos in the same capture
    assert "krb_tcp" in report.tools["zeek"]["detail"]["services"]
    assert any("kerberos" in p for p in report.tools["tshark"]["detail"]["protocols"])
    # if the external JA3 tool ran, its digests match ours byte-for-byte
    if report.ja3_agreement:
        assert all(a["match"] for a in report.ja3_agreement.values())


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_transfer_proof_reproduces_protocols(tmp_path):
    """Profile a capture, synthesize an analog, confirm the analog reproduces the
    protocols independent tools saw in the original."""
    from packetforge.environments import load_environment
    from packetforge.transfer import profile_pcap, synthesize_analog, transfer_proof

    pcap, _ = _synthetic_office(tmp_path, seed=2)
    prof = profile_pcap(pcap, workdir=str(tmp_path / "prof"))
    assert "kerberos" in prof.services and "dns" in prof.services

    analog = synthesize_analog(prof, load_environment("office"), seed=2)
    assert analog.flows, "analog should reproduce the profiled services"

    report = transfer_proof(pcap, load_environment("office"), seed=2,
                            workdir=str(tmp_path / "xfer"))
    assert report.transferred >= 70.0, report.render()  # most protocols reproduced
    assert report.analog_agree                            # the analog itself is clean
