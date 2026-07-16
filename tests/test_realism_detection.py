# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase 1: detection-outcome realism — do detections behave the same on synthetic as real?"""

import pytest

from packetforge.detect import suricata_available
from packetforge.realism_detection import _js_divergence
from packetforge.validation import validators_available


def test_js_divergence_bounds():
    assert _js_divergence({"a": 5, "b": 5}, {"a": 5, "b": 5}) == 0.0        # identical
    assert _js_divergence({"a": 10}, {"b": 10}) == 1.0                       # disjoint
    assert _js_divergence({}, {}) == 0.0                                     # both empty
    assert _js_divergence({"a": 1}, {}) == 1.0                               # one fired nothing
    mid = _js_divergence({"a": 8, "b": 2}, {"a": 2, "b": 8})
    assert 0.0 < mid < 1.0                                                   # partial overlap


@pytest.mark.skipif(not (suricata_available() and validators_available()),
                    reason="requires suricata + zeek + tshark")
def test_detection_outcome_runs_and_reports(tmp_path):
    """The metric computes valid divergences over a matched synthetic analog.

    Uses a PacketForge capture as the 'real' stand-in (a real reference isn't shipped);
    this exercises the machinery — profiling, matching, dual detection, divergence — not
    the realism claim itself.
    """
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment
    from packetforge.realism_detection import detection_outcome

    repo = __import__("pathlib").Path(__file__).resolve().parent.parent
    ref = compose_scenario(load_environment("office"), start_time=1700000000.0,
                           noise_flows=120, seed=7)
    ref_pcap = tmp_path / "ref.pcap"
    write_pcap(ref, ref_pcap)

    rep = detection_outcome(ref_pcap, load_environment("home"),
                            repo / "detection" / "example.rules", seed=1, workdir=str(tmp_path))
    assert rep.service_counts, "should profile the reference into per-service counts"
    assert rep.real_duration > 0 and rep.synth_duration > 0
    assert 0.0 <= rep.alert_js <= 1.0
    assert 0.0 <= rep.sig_coverage <= 1.0
    assert rep.real_fp_per_hr >= 0.0 and rep.synth_fp_per_hr >= 0.0
    assert "Detection-outcome realism" in rep.render()
