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


def test_empty_or_unparseable_capture_scores_zero_not_a_vacuous_hundred(tmp_path):
    from packetforge.evaluate import EvalReport, evaluate_pcap

    # a file that is not a capture at all must not score 100 for lack of complaints
    garbage = tmp_path / "garbage.pcap"
    garbage.write_bytes(b"\x00" * 64 + b"not a pcap")
    report = evaluate_pcap(garbage)
    assert report.score == 0
    assert not report.findings[0].ok and "no packets" in report.findings[0].detail
    # and a report with no findings is 0, not a free 100
    assert EvalReport().score == 0
