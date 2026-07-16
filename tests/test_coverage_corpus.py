# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase C: coverage matrix, FP benchmark, and the detection-CI corpus."""

import pytest

from packetforge.corpus import CORPUS_VERSION, build_corpus, diff_scorecards
from packetforge.detect import suricata_available
from packetforge.environments import load_environment

REPO = __import__("pathlib").Path(__file__).resolve().parent.parent
RULES = REPO / "detection" / "example.rules"


def test_corpus_build_is_deterministic_and_content_addressed(tmp_path):
    m1 = build_corpus(tmp_path / "a")
    m2 = build_corpus(tmp_path / "b")
    assert m1["corpus_version"] == CORPUS_VERSION
    assert m1["captures"], "corpus should contain captures"
    sha1 = {c["name"]: c["sha256"] for c in m1["captures"]}
    sha2 = {c["name"]: c["sha256"] for c in m2["captures"]}
    assert sha1 == sha2, "corpus must be byte-reproducible (content-addressable)"
    # every capture is labeled with its ground-truth techniques
    assert all(c["techniques"] for c in m1["captures"])


def test_diff_scorecards_flags_regressions_and_gains():
    base = {"scores": [
        {"name": "a", "techniques_caught": ["T1", "T2"], "false_positives": 0},
        {"name": "b", "techniques_caught": ["T3"], "false_positives": 0},
    ]}
    current = {"scores": [
        {"name": "a", "techniques_caught": ["T1"], "false_positives": 2},   # lost T2, +FP
        {"name": "b", "techniques_caught": ["T3", "T9"], "false_positives": 0},  # gained T9
    ]}
    d = diff_scorecards(base, current)
    assert {"capture": "a", "technique": "T2"} in d["regressions"]
    assert d["new_false_positives"] == [{"capture": "a", "was": 0, "now": 2}]
    assert {"capture": "b", "technique": "T9"} in d["gains"]
    assert d["ok"] is False


def test_diff_scorecards_clean_when_equal():
    card = {"scores": [{"name": "a", "techniques_caught": ["T1"], "false_positives": 0}]}
    assert diff_scorecards(card, card)["ok"] is True


@pytest.mark.skipif(not suricata_available(), reason="requires suricata on PATH")
def test_coverage_matrix_catches_kerberoasting_zero_fp(tmp_path):
    from packetforge.coverage import build_coverage_matrix
    env = load_environment("office")
    matrix = build_coverage_matrix(env, RULES, attacks=["kerberoasting", "dns-exfil"],
                                   noise_flows=40, seed=1, workdir=tmp_path)
    caught, total = matrix.technique_totals
    assert caught >= 2                                   # both attacks caught
    assert sum(r.false_positives for r in matrix.rows) == 0
    assert "Attack" in matrix.to_markdown()


@pytest.mark.skipif(not suricata_available(), reason="requires suricata on PATH")
def test_fp_benchmark_reports_a_rate(tmp_path):
    from packetforge.coverage import fp_benchmark
    env = load_environment("office")
    bench = fp_benchmark(env, RULES, duration_s=600.0, volume="normal", seed=5, workdir=tmp_path)
    assert bench.benign_flows > 0
    assert bench.fp_per_hour >= 0.0                      # a real number, even if 0
