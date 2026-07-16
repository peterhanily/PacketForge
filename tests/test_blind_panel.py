# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase 3: the human blind-panel harness (EvidenceForge's realism bar for packets)."""
import json

import pytest

from packetforge.blind_panel import score_quiz
from packetforge.validation import validators_available


def _write(tmp, key, guesses):
    (tmp / "answers.json").write_text(json.dumps(key))
    (tmp / "guesses.txt").write_text(guesses)
    return score_quiz(tmp / "answers.json", tmp / "guesses.txt")


def test_scorer_calibration(tmp_path):
    key = {"1": "real", "2": "synth", "3": "real", "4": "synth"}
    perfect = _write(tmp_path, key, "1: real\n2: synth\n3: real\n4: synth\n")
    assert perfect.accuracy == 1.0 and perfect.n == 4
    wrong = _write(tmp_path, key, "1: synth\n2: real\n3: synth\n4: real\n")
    assert wrong.accuracy == 0.0
    allreal = _write(tmp_path, key, "1: real\n2: real\n3: real\n4: real\n")
    assert allreal.accuracy == 0.5  # half the labels are real
    assert allreal.synth_as_real == 2 and allreal.real_as_synth == 0


def test_scorer_ignores_blank_and_bad_lines(tmp_path):
    key = {"1": "real", "2": "synth"}
    r = _write(tmp_path, key, "1: real\n2:\n\nnonsense\n2: synth\n")
    assert r.n == 2 and r.correct == 2  # blank/garbage skipped, valid ones counted


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")
def test_generate_quiz_produces_a_blind_quiz(tmp_path):
    import random

    from packetforge.blind_panel import generate_quiz
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment

    # two different-looking captures stand in for real vs synthetic
    for env, seed, name in (("office", 1, "a"), ("home", 2, "b")):
        fs = compose_scenario(load_environment(env), start_time=1700000000.0,
                              noise_flows=80, seed=seed, storyline=None)
        write_pcap(fs, tmp_path / f"{name}.pcap")
    out = tmp_path / "quiz"
    generate_quiz(tmp_path / "a.pcap", tmp_path / "b.pcap", out, n=6, seed=random.Random(0).randint(1, 9))
    key = json.loads((out / "answers.json").read_text())
    assert (out / "quiz.md").exists() and (out / "guesses.txt").exists()
    assert 1 <= len(key) <= 12 and set(key.values()) <= {"real", "synth"}
    assert "Blind realism panel" in (out / "quiz.md").read_text()
