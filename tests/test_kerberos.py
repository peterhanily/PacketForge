# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase A: faithful Kerberos + the AD roasting attacks.

The value claim is specific: real Zeek logs the ticket enctype, so an RC4 downgrade
is visible; a detection fires on the roast and stays silent on benign AES AD auth.
"""

import random

import pytest

from packetforge.environments import load_environment
from packetforge.models.flowspec import KerberosL7
from packetforge.scenarios import build_asrep_roasting, build_kerberoasting
from packetforge.validation import validators_available


def test_kerberoasting_is_rc4_tgs_burst():
    env = load_environment("office")
    intr = build_kerberoasting(env, 1700000000.0, random.Random(1))
    roast = [f for f in intr.flows if "roast" in f.flow_id]
    assert len(roast) >= 4
    # every roast ticket forces RC4 (etype 23) and requests a TGS
    assert all(isinstance(f.l7, KerberosL7) and f.l7.etype == 23 and f.l7.request_type == "TGS"
               for f in roast)
    # distinct SPNs (the enumeration tell)
    assert len({f.l7.service for f in roast}) >= 4
    assert "T1558.003" in intr.ground_truth[0].technique


def test_asrep_roasting_has_no_preauth_rc4():
    env = load_environment("office")
    intr = build_asrep_roasting(env, 1700000000.0, random.Random(1))
    assert intr.flows and all(
        isinstance(f.l7, KerberosL7) and f.l7.request_type == "AS"
        and f.l7.preauth is False and f.l7.etype == 23 for f in intr.flows)
    assert "T1558.004" in intr.ground_truth[0].technique


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_rc4_downgrade_visible_to_zeek(tmp_path):
    """Real Zeek must log the roast tickets as rc4-hmac (the downgrade signal)."""
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.validation import validate_flowset

    env = load_environment("office")
    intr = build_kerberoasting(env, 1700000200.0, random.Random(1))
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=40, seed=1,
                          storyline=intr.flows)
    report = validate_flowset(fs)
    assert report.ok, "\n" + report.summary()  # clean: no weird/reporter, kerberos.log present

    # and the enctype string is actually in the capture Zeek parsed
    pcap = tmp_path / "k.pcap"
    write_pcap(fs, pcap)
    import subprocess
    out = subprocess.run(["zeek", "-C", "-r", str(pcap)], cwd=tmp_path,
                         capture_output=True, text=True)
    klog = (tmp_path / "kerberos.log")
    assert klog.exists(), out.stderr
    body = klog.read_text()
    assert "rc4-hmac" in body and "aes256-cts-hmac-sha1-96" in body  # attack + benign both present


@pytest.mark.skipif(not __import__("packetforge.detect", fromlist=["suricata_available"]).suricata_available(),
                    reason="requires suricata on PATH")
def test_kerberoasting_caught_zero_fp_on_benign_ad(tmp_path):
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.detect import run_detection
    from packetforge.scenarios import write_ground_truth

    repo = __import__("pathlib").Path(__file__).resolve().parent.parent
    env = load_environment("office")
    intr = build_kerberoasting(env, 1700000200.0, random.Random(1))
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=80, seed=2,
                          storyline=intr.flows)
    pcap = tmp_path / "k.pcap"
    write_pcap(fs, pcap)
    gt = tmp_path / "gt.json"
    write_ground_truth(intr, tmp_path / "gt.md", gt)

    report = run_detection(pcap, repo / "detection" / "example.rules", gt)
    assert report.techniques_caught, "\n" + report.summary()  # RC4 downgrade caught
    assert report.false_positives == 0, "\n" + report.summary()  # silent on benign AES AD auth
