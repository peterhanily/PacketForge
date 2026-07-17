# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase 4: the versioned realism scorecard + CI regression check."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packetforge.scorecard import (
    build_scorecard,
    compare_scorecards,
    regressions,
    render_comparison,
    run_scorecard,
)
from packetforge.validation import validators_available

_BASELINE = Path(__file__).resolve().parents[1] / "realism-scorecard.json"


def _validity(ok=True, matched=100, total=100):
    return SimpleNamespace(ok=ok, matched_flows=matched, total_flows=total,
                           packet_count=500, zeek_weird=0, tshark_errors=0)


def _realism(auc=0.55, held=0.55, baseline=0.0):
    return SimpleNamespace(c2st_auc=auc, held_out_auc=held, mmd=1.2, n_real=200, n_synth=200,
                           real_baseline_auc=baseline,
                           tells=[("first_window", 0.4, 0.3), ("conn_state", 0.3, 0.2)])


def _detection(js=0.1, cov=0.9):
    return SimpleNamespace(alert_js=js, real_fp_per_hr=210.0, synth_fp_per_hr=180.0,
                           sig_coverage=cov, ruleset="et-open")


META = {"reference": {"name": "ref.pcap"}, "generator": {"seed": 1337}}


def test_all_gates_passing_reads_pass_and_names_no_gaps():
    card = build_scorecard(meta=META, validity=_validity(), realism=_realism(0.55),
                           detection=_detection(0.1))
    assert card["verdict"] == "pass"
    assert card["honest_gaps"] == []
    assert card["schema_version"] == "1.0"
    assert card["gates"]["realism"]["top_tells"][0] == "first_window"


def test_gaps_are_named_not_smoothed_over():
    card = build_scorecard(meta=META, validity=_validity(),
                           realism=_realism(0.94), detection=_detection(1.0))
    assert card["verdict"] == "gap"
    assert len(card["honest_gaps"]) == 2
    assert any("0.94" in g and "first_window" in g for g in card["honest_gaps"])
    assert any("JS is 1.0" in g for g in card["honest_gaps"])


def test_realism_passes_when_within_the_real_vs_real_floor():
    # AUC 0.97 is far above the absolute 0.65 bar, but a distinct real capture scores 0.95 against
    # the reference — the synth is no more separable than real-vs-real, so the gate passes.
    card = build_scorecard(meta=META, validity=_validity(),
                           realism=_realism(0.97, baseline=0.95), detection=_detection(0.1))
    assert card["gates"]["realism"]["verdict"] == "pass"
    assert card["gates"]["realism"]["real_baseline_auc"] == 0.95
    assert card["honest_gaps"] == []


def test_realism_gaps_when_above_the_real_vs_real_floor():
    card = build_scorecard(meta=META, validity=_validity(),
                           realism=_realism(0.99, baseline=0.90), detection=_detection(0.1))
    assert card["gates"]["realism"]["verdict"] == "gap"
    assert any("distinct real capture scores 0.9" in g for g in card["honest_gaps"])


def test_c2st_auc_between_calibrates_at_half_and_separates_distinct():
    pytest.importorskip("sklearn", reason="needs the [realism] extra")
    import numpy as np

    from packetforge.realism import c2st_auc_between
    rng = np.random.RandomState(0)
    a = rng.normal(0, 1, size=(120, 6))
    b_same = rng.normal(0, 1, size=(120, 6))     # same distribution -> ~0.5
    b_far = rng.normal(4, 1, size=(120, 6))      # shifted -> separable
    assert c2st_auc_between(a, b_same) < 0.65, "same distribution should look ~indistinguishable"
    assert c2st_auc_between(a, b_far) > 0.9, "clearly different distributions should separate"


def test_a_failing_validity_gate_fails_overall():
    card = build_scorecard(meta=META, validity=_validity(ok=False, matched=90),
                           realism=_realism(0.55))
    assert card["verdict"] == "fail"
    assert card["gates"]["validity"]["matched_ratio"] == 0.9


def test_no_gates_is_not_run():
    assert build_scorecard(meta=META)["verdict"] == "not-run"


def test_compare_flags_a_realism_regression_but_forgives_noise():
    base = build_scorecard(meta=META, realism=_realism(0.80), detection=_detection(0.10))
    worse = build_scorecard(meta=META, realism=_realism(0.90), detection=_detection(0.10))
    noise = build_scorecard(meta=META, realism=_realism(0.82), detection=_detection(0.10))
    better = build_scorecard(meta=META, realism=_realism(0.70), detection=_detection(0.10))

    reg = {c["path"]: c["status"] for c in compare_scorecards(base, worse)}
    assert reg["gates.realism.c2st_auc"] == "regressed"          # +0.10 > tol 0.05
    assert regressions(compare_scorecards(base, worse))          # non-empty
    assert not regressions(compare_scorecards(base, noise))      # +0.02 within tol
    assert not regressions(compare_scorecards(base, better))     # improvement is not a regression
    imp = {c["path"]: c["status"] for c in compare_scorecards(base, better)}
    assert imp["gates.realism.c2st_auc"] == "improved"           # -0.10 lower is better


def test_compare_handles_a_missing_metric_and_renders():
    base = build_scorecard(meta=META, realism=_realism(0.80))          # no detection gate
    cur = build_scorecard(meta=META, realism=_realism(0.80), detection=_detection(0.1))
    comparison = compare_scorecards(base, cur)
    assert any(c["status"] == "missing" for c in comparison)
    assert "no regressions" in render_comparison(comparison)
    assert "REGRESSED" in render_comparison(compare_scorecards(
        build_scorecard(meta=META, detection=_detection(0.1)),
        build_scorecard(meta=META, detection=_detection(0.9)),
    ))


@pytest.mark.skipif(not _BASELINE.exists(), reason="committed baseline scorecard not present")
def test_committed_baseline_is_valid_and_leaks_nothing():
    """CI guard: the checked-in scorecard stays schema-valid, self-consistent, and clean."""
    card = json.loads(_BASELINE.read_text())
    assert card["schema_version"] == "1.0"
    assert card["verdict"] in {"pass", "gap", "fail", "not-run"}
    assert set(card["gates"]) <= {"validity", "realism", "detection"}
    # a scorecard never regresses against itself
    assert not regressions(compare_scorecards(card, card))
    # the published artifact must carry no absolute or local filesystem paths
    blob = json.dumps(card)
    assert "/private/" not in blob and "/Users/" not in blob and "/tmp/" not in blob
    if "detection" in card["gates"]:
        assert "/" not in card["gates"]["detection"]["ruleset"]     # basename only


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")
def test_run_scorecard_refuses_an_empty_reference(tmp_path):
    """A non-pcap reference must raise, not emit a vacuous verdict=pass."""
    from packetforge.environments import load_environment
    garbage = tmp_path / "garbage.pcap"
    garbage.write_bytes(b"\x00" * 64 + b"not a pcap")
    with pytest.raises(ValueError, match="no parseable flows"):
        run_scorecard(garbage, load_environment("office"), seed=1, workdir=tmp_path / "wd")


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")
def test_run_scorecard_end_to_end(tmp_path):
    pytest.importorskip("sklearn", reason="scorecard needs the [realism] extra")
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment

    # a synthetic capture stands in for the "real" reference
    ref = compose_scenario(load_environment("office"), start_time=1700000000.0,
                           noise_flows=120, seed=7, texture="realistic")
    ref_pcap = tmp_path / "ref.pcap"
    write_pcap(ref, ref_pcap)

    card = run_scorecard(ref_pcap, load_environment("office"), seed=1337, workdir=tmp_path / "wd")
    assert card["schema_version"] == "1.0"
    assert card["verdict"] in {"pass", "gap", "fail"}
    assert set(card["gates"]) == {"validity", "realism"}          # no rules -> no detection gate
    assert 0.0 <= card["gates"]["realism"]["c2st_auc"] <= 1.0
    assert card["reference"]["sha256"] and card["reference"]["flows"] > 0
    # comparing a scorecard to itself is never a regression
    assert not regressions(compare_scorecards(card, card))
