# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The blind-panel realism evaluator."""

import pytest

from packetforge.validation import validators_available

pytestmark = pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")


def test_composed_capture_scores_high(tmp_path):
    from packetforge.compose import compose_scenario
    from packetforge.compile.timeline import write_pcap
    from packetforge.environments import load_environment
    from packetforge.evaluate import evaluate_pcap

    fs = compose_scenario(load_environment("office"), start_time=1700000000.0,
                          noise_flows=100, seed=9)
    pcap = tmp_path / "c.pcap"
    write_pcap(fs, pcap)
    report = evaluate_pcap(pcap)
    # after the timing + MAC fixes a well-formed capture should score highly
    assert report.score >= 90, "\n" + report.summary()
    # the specific tells the audits fixed must pass
    by = {f.check: f for f in report.findings}
    assert by["timing_burstiness"].ok and by["mac_vendor"].ok and by["parseability"].ok
