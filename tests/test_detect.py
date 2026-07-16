# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Detection-testing harness."""

import random

import pytest

from packetforge.detect import suricata_available

pytestmark = pytest.mark.skipif(not suricata_available(), reason="requires suricata on PATH")

REPO = __import__("pathlib").Path(__file__).resolve().parent.parent
RULES = REPO / "detection" / "example.rules"


def test_detection_catches_attack_no_false_positives(tmp_path):
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.detect import run_detection
    from packetforge.environments import load_environment
    from packetforge.scenarios import build_attack, write_ground_truth

    env = load_environment("office")
    intr = build_attack("phishing-intrusion", env, 1700000200.0, random.Random(1))
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=60, seed=2, storyline=intr.flows)
    pcap = tmp_path / "c.pcap"
    write_pcap(fs, pcap)
    gt = tmp_path / "gt.json"
    write_ground_truth(intr, tmp_path / "gt.md", gt)

    report = run_detection(pcap, RULES, gt)
    # the example rules catch the C2 stage, and fire on no benign flow
    assert report.techniques_caught, "\n" + report.summary()
    assert report.false_positives == 0, "\n" + report.summary()
    assert report.true_positives >= 1
