# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""ATT&CK intrusion storyline + ground truth."""

import random

import pytest

from packetforge.environments import load_environment
from packetforge.scenarios import build_attack, build_intrusion, list_attacks, write_ground_truth
from packetforge.validation import validators_available


def test_intrusion_has_attack_stages():
    intr = build_intrusion(load_environment("office"), 1700000000.0, random.Random(1))
    assert len(intr.flows) >= 10
    stages = {e.stage for e in intr.ground_truth}
    assert {"Initial Access", "Command and Control", "Lateral Movement", "Exfiltration"} <= stages
    assert all(e.technique.startswith("T1") for e in intr.ground_truth)
    assert all(f.flow_id.startswith("atk-") for f in intr.flows)


def test_ground_truth_written(tmp_path):
    intr = build_intrusion(load_environment("office"), 1700000000.0, random.Random(1))
    md, js = tmp_path / "GT.md", tmp_path / "GT.json"
    write_ground_truth(intr, md, js)
    text = md.read_text()
    assert "GROUND TRUTH" in text and "T1071" in text
    import json
    data = json.loads(js.read_text())
    assert data["iocs"]["c2_domain"] and len(data["kill_chain"]) == len(intr.ground_truth)


@pytest.mark.parametrize("name", ["brute-force", "ddos-syn-flood", "dns-exfil",
                                  "phishing-intrusion", "port-scan", "ransomware"])
def test_attack_builds_with_ground_truth(name):
    assert name in list_attacks()
    intr = build_attack(name, load_environment("office"), 1700000000.0, random.Random(1))
    assert intr.flows and intr.ground_truth
    assert all(f.flow_id.startswith("atk-") for f in intr.flows)
    assert all(e.technique.startswith("T1") for e in intr.ground_truth)


def test_attack_intensity_scales_volume():
    env = load_environment("office")
    lo = build_attack("dns-exfil", env, 1700000000.0, random.Random(1), intensity=0.5)
    hi = build_attack("dns-exfil", env, 1700000000.0, random.Random(1), intensity=3.0)
    assert len(hi.flows) > len(lo.flows)


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("name", ["dns-exfil", "ddos-syn-flood", "port-scan",
                                  "brute-force", "ransomware"])
def test_attack_roundtrips_clean(name):
    from packetforge.compose import compose_scenario
    from packetforge.validation import validate_flowset
    env = load_environment("office")
    intr = build_attack(name, env, 1700000200.0, random.Random(1))
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=40, seed=2, storyline=intr.flows)
    report = validate_flowset(fs)
    assert report.ok, f"{name}:\n" + report.summary()


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_intrusion_roundtrips_clean():
    from packetforge.compose import compose_scenario
    from packetforge.validation import validate_flowset
    env = load_environment("office")
    intr = build_intrusion(env, 1700000200.0, random.Random(1))
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=60, seed=2, storyline=intr.flows)
    report = validate_flowset(fs)
    assert report.ok, "\n" + report.summary()
