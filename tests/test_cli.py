# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""CLI boundary behaviour: user mistakes get a clean error, not a stack trace."""
from packetforge.cli import main


def test_unknown_env_is_a_clean_error(capsys, tmp_path):
    rc = main(["scenario", "--env", "NOPE", "-o", str(tmp_path / "x.pcap")])
    err = capsys.readouterr().err
    assert rc == 2
    assert err.startswith("ERROR:") and "unknown environment" in err
    assert "Traceback" not in err


def test_unknown_attack_is_a_clean_error(capsys, tmp_path):
    rc = main(["scenario", "--env", "office", "--attack", "nope", "-o", str(tmp_path / "x.pcap")])
    err = capsys.readouterr().err
    assert rc == 2 and "unknown attack" in err and "Traceback" not in err


def test_missing_flowspec_is_a_clean_error(capsys, tmp_path):
    rc = main(["compile", str(tmp_path / "no-such.yaml"), "-o", str(tmp_path / "x.pcap")])
    err = capsys.readouterr().err
    assert rc == 2 and "ERROR:" in err and "Traceback" not in err


def test_a_valid_scenario_still_succeeds(tmp_path):
    out = tmp_path / "ok.pcap"
    rc = main(["scenario", "--env", "office", "--seed", "1", "-o", str(out)])
    assert rc == 0 and out.exists() and out.stat().st_size > 0
