# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The validation trinity — fidelity (C2ST), utility (TSTR), non-leakage (DCR)."""

import pytest

from packetforge.compose import compose_scenario
from packetforge.compile.timeline import write_pcap
from packetforge.environments import load_environment
from packetforge.validation import validators_available


def _cap(path, env, seed):
    fs = compose_scenario(load_environment(env), start_time=1_700_000_000.0, duration_s=200.0,
                          noise_flows=140, seed=seed)
    write_pcap(fs, path)
    return path


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_validation_trinity_reports_all_three_legs(tmp_path):
    from packetforge.trinity import validation_trinity
    # Two distinct synthetic captures stand in for real/synth here (no external pcap needed);
    # the trinity machinery is the unit under test, not the realism verdict.
    ref = _cap(tmp_path / "ref.pcap", "office", 1)
    syn = _cap(tmp_path / "syn.pcap", "office", 2)
    rep = validation_trinity(syn, ref, workdir=str(tmp_path / "wd"))

    assert 0.0 <= rep.fidelity_c2st <= 1.0
    # utility: a flow->service classifier trained on one capture transfers to the other
    u = rep.utility
    if not u.inconclusive:
        assert 0.0 <= u.tstr_accuracy <= 1.0
        assert len(u.classes) >= 2
    # non-leakage: DCR is non-negative and the verdict is one of the known states
    n = rep.nonleakage
    assert n.dcr_median >= 0.0
    assert n.verdict in {"generated", "replay-risk", "INCONCLUSIVE"}
    assert "fidelity" in rep.render() and "utility" in rep.render()


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_nonleakage_flags_a_replay(tmp_path):
    # A capture scored against ITSELF should look like a replay: every flow's nearest real
    # flow is itself (distance ~0), so near-replay fraction is high.
    from packetforge.trinity import nonleakage
    cap = _cap(tmp_path / "c.pcap", "home", 5)
    rep = nonleakage(cap, cap, tmp_path / "wd")
    if not rep.inconclusive:
        assert rep.dcr_median == 0.0 or rep.near_replay_frac > 0.5
        assert rep.verdict == "replay-risk"
