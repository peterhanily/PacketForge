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


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")
def test_profile_reference_conditions_the_analog(tmp_path):
    """V3: the reference's fingerprint marginals are captured and the analog draws from them."""
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment
    from packetforge.realism_detection import matched_synthetic, profile_reference

    ref = compose_scenario(load_environment("office"), start_time=1700000000.0,
                           noise_flows=120, seed=7)
    ref_pcap = tmp_path / "ref.pcap"
    write_pcap(ref, ref_pcap)
    prof = profile_reference(ref_pcap, tmp_path / "z")
    assert prof.syn_windows and prof.syn_ttls and prof.ia_means, "no fingerprint marginals captured"
    analog = matched_synthetic(prof, load_environment("office"), seed=1)
    tcp = [f for f in analog.flows if f.transport == "tcp" and f.syn_window is not None]
    assert tcp and all(f.syn_window in prof.syn_windows for f in tcp), "conditioning not applied"
