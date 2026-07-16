# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 2: the realism audit (classifier two-sample test).

The test that matters is calibration: two captures from the *same* generator must score
~0.5 (indistinguishable), and two clearly *different* distributions must score high.
A metric that always says "distinguishable" would be worthless.
"""
import subprocess

import pytest

from packetforge.validation import validators_available

pytest.importorskip("sklearn", reason="realism audit needs the [realism] extra")
pytestmark = pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")


def _zeek_of(env, seed, tmp, label):
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment
    fs = compose_scenario(load_environment(env), start_time=1700000000.0, noise_flows=400,
                          seed=seed, texture="realistic")
    pcap = tmp / f"{label}.pcap"
    write_pcap(fs, pcap)
    wd = tmp / f"zeek_{label}"
    wd.mkdir()
    subprocess.run(["zeek", "-C", "-r", str(pcap), "detect_filtered_trace=F"],
                   cwd=str(wd), capture_output=True, text=True, check=False)
    return wd, pcap


def test_c2st_is_calibrated(tmp_path):
    from packetforge.realism import audit
    # same generator, different seeds -> the adversary should NOT tell them apart
    (a, ap), (b, bp) = _zeek_of("home", 21, tmp_path, "a"), _zeek_of("home", 22, tmp_path, "b")
    same = audit(a, b, ap, bp)
    # a clearly different environment -> the adversary SHOULD tell them apart
    ot, otp = _zeek_of("ot", 21, tmp_path, "ot")
    diff = audit(a, ot, ap, otp)

    assert 0.0 <= same.c2st_auc <= 1.0 and 0.0 <= diff.c2st_auc <= 1.0
    assert same.c2st_auc < 0.70, f"same distribution scored {same.c2st_auc:.3f} (should be ~0.5)"
    assert diff.c2st_auc > 0.80, f"different distributions scored {diff.c2st_auc:.3f} (should be high)"
    assert diff.c2st_auc > same.c2st_auc + 0.15  # separation is meaningful
    # the held-out learner (Goodhart guard) agrees on the separation
    assert diff.held_out_auc > same.held_out_auc


def test_audit_refuses_empty_captures_instead_of_claiming_0_5(tmp_path):
    from packetforge.realism import audit
    # two empty zeek workdirs (no conn.log) — nothing to compare. Must raise, not
    # return a vacuous 0.5 "indistinguishable".
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    with pytest.raises(ValueError, match="no flows to compare"):
        audit(a, b)


def test_report_names_the_rich_tells(tmp_path):
    from packetforge.realism import _PKT_FEATURES, audit
    (a, ap), (ot, otp) = _zeek_of("home", 21, tmp_path, "a"), _zeek_of("ot", 21, tmp_path, "ot")
    rep = audit(a, ot, ap, otp)
    assert rep.tells and len(rep.tells[0]) == 3          # (feature, ks, importance)
    assert all(0.0 <= ks <= 1.0 for _, ks, _ in rep.tells)
    # the rich packet features are present in the feature set
    assert set(_PKT_FEATURES) & {name for name, _, _ in rep.tells}
    assert rep.mmd >= 0.0 and "held-out" in rep.render()
