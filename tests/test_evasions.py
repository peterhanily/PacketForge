# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase B: evasion modifiers + rule-robustness measurement.

The artifact that matters: the same rule catches the clean attack and MISSES the
evasive one, quantifying rule brittleness. Each modifier is a pure flow-field
mutation, so captures stay deterministic and Zeek-clean.
"""
import random

import pytest

from packetforge.environments import load_environment
from packetforge.models.flowspec import TlsL7
from packetforge.scenarios import build_attack, list_evasions
from packetforge.validation import validators_available


def test_domain_fronting_keeps_dest_changes_sni():
    env = load_environment("office")
    clean = build_attack("phishing-intrusion", env, 1700000100.0, random.Random(1))
    evad = build_attack("phishing-intrusion", env, 1700000100.0, random.Random(1),
                        evasions=("domain-fronting",))
    c2 = clean.iocs["c2_domain"]
    clean_beacons = {f.flow_id: f for f in clean.flows if isinstance(f.l7, TlsL7)}
    evad_beacons = {f.flow_id: f for f in evad.flows if isinstance(f.l7, TlsL7)}
    assert clean_beacons and evad_beacons
    for fid, cf in clean_beacons.items():
        ef = evad_beacons[fid]
        assert cf.l7.server_name == c2           # clean SNI is the C2 domain
        assert ef.l7.server_name != c2           # fronted SNI is a benign CDN
        assert ef.dst_ip == cf.dst_ip            # real destination IP unchanged
    assert "domain-fronting" in evad.evasions


def test_all_evasions_apply_and_are_recorded():
    env = load_environment("office")
    for ev in list_evasions():
        atk = "dns-exfil" if ev == "dns-depth" else "phishing-intrusion"
        intr = build_attack(atk, env, 1700000100.0, random.Random(2), evasions=(ev,))
        assert ev in intr.evasions


def test_unknown_evasion_rejected():
    env = load_environment("office")
    with pytest.raises(ValueError):
        build_attack("phishing-intrusion", env, 1.0, random.Random(0), evasions=("nope",))


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_evasive_capture_round_trips_clean():
    from packetforge.compose import compose_scenario
    from packetforge.validation import validate_flowset
    env = load_environment("office")
    intr = build_attack("phishing-intrusion", env, 1700000100.0, random.Random(3),
                        evasions=("domain-fronting", "port-hopping", "slow-and-low"))
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=40, seed=3,
                          storyline=intr.flows)
    report = validate_flowset(fs)
    assert report.ok, "\n" + report.summary()


@pytest.mark.skipif(not __import__("packetforge.detect", fromlist=["suricata_available"]).suricata_available(),
                    reason="requires suricata on PATH")
def test_domain_fronting_evades_the_sni_rule(tmp_path):
    """Clean: C2 caught via the SNI IOC. Evasive: same rule misses it."""
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.detect import run_detection
    from packetforge.scenarios import write_ground_truth

    repo = __import__("pathlib").Path(__file__).resolve().parent.parent
    rules = repo / "detection" / "example.rules"
    env = load_environment("office")

    def detect(evasions):
        intr = build_attack("phishing-intrusion", env, 1700000100.0, random.Random(4),
                            evasions=evasions)
        fs = compose_scenario(env, start_time=1700000000.0, noise_flows=60, seed=4,
                              storyline=intr.flows)
        pcap = tmp_path / f"c{len(evasions)}.pcap"
        write_pcap(fs, pcap)
        gt = tmp_path / f"c{len(evasions)}.json"
        write_ground_truth(intr, tmp_path / f"c{len(evasions)}.md", gt)
        return run_detection(pcap, rules, gt)

    clean = detect(())
    evasive = detect(("domain-fronting",))
    c2 = "T1071.001/.004 Web + DNS C2"
    assert c2 in clean.techniques_caught, "clean run should catch C2 via SNI\n" + clean.summary()
    assert c2 not in evasive.techniques_caught, "domain-fronting should evade the SNI rule\n" + evasive.summary()
