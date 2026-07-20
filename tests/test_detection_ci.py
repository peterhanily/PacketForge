# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Detection-CI surface — deterministic fixtures + suricata-verify export."""

from pathlib import Path

import pytest

from packetforge.detection_ci import Fixture, write_suricata_verify
from packetforge.validation import validators_available

REPO = Path(__file__).resolve().parent.parent
ET_JA3 = REPO / "detection" / "etopen" / "rules" / "emerging-ja3.rules"


def test_suricata_verify_export_structure(tmp_path):
    # The exporter is a pure transform of a Fixture + a golden SID histogram — no tools needed.
    fake_pcap = tmp_path / "cap.pcap"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # a minimal pcap header
    fx = Fixture(attack="dridex", env="office", seed=1, pcap=fake_pcap, ground_truth=fake_pcap,
                 _benign_pcap=fake_pcap, expected_sids={2028365: 6})
    out = write_suricata_verify(fx, tmp_path / "sv", ET_JA3)
    assert (out / "test.pcap").exists()
    yaml = (out / "test.yaml").read_text()
    assert "alert.signature_id: 2028365" in yaml
    assert "count: 6" in yaml
    assert "requires:" in yaml and "checks:" in yaml


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_fixture_renders_attack_and_benign_twin(tmp_path):
    from packetforge.detection_ci import packetforge_fixture
    fx = packetforge_fixture("kerberoasting", env="office", seed=3, flows=30, out_dir=str(tmp_path))
    assert fx.pcap.exists() and fx._benign_pcap.exists()
    assert fx.ground_truth.exists()               # the answer key ships with the fixture
    assert any(fx.zeek_dir.glob("*.log"))         # real Zeek logs the fixture produces


@pytest.mark.skipif(not (validators_available() and ET_JA3.exists()),
                    reason="requires suricata + tshark + ET ja3 ruleset")
def test_real_family_fixture_fires_and_stays_quiet_on_benign(tmp_path):
    # A malware-JA3 fixture (inert) should trip the real ET rule; the benign twin must not.
    import subprocess

    from packetforge.compile.timeline import write_pcap
    from packetforge.detection_ci import _sid_histogram
    from packetforge.environments import load_environment
    from packetforge.malware_transfer import build_reference
    if not subprocess.run(["suricata", "-V"], capture_output=True).returncode == 0:
        pytest.skip("suricata not runnable")
    env = load_environment("office")
    atk = tmp_path / "atk.pcap"
    write_pcap(build_reference("dridex", env, seed=1, beacons=6, noise_flows=8), atk)
    ben = tmp_path / "ben.pcap"
    from packetforge.compose import compose_scenario
    write_pcap(compose_scenario(env, start_time=1_700_000_000.0, noise_flows=40, seed=1), ben)
    assert 2028365 in _sid_histogram(atk, ET_JA3)          # fires on the attack
    assert 2028365 not in _sid_histogram(ben, ET_JA3)      # quiet on benign (no false positive)
