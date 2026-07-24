# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Cloud east-west: VXLAN mirror/overlay capture + a Kubernetes cluster-lateral scenario."""

import random
import tempfile

import pytest

from packetforge.compile.timeline import compile_flowset
from packetforge.compile.vantage import mirror_vantage, render_vantage
from packetforge.environments import list_environments, load_environment
from packetforge.models.flowspec import FlowSet
from packetforge.scenarios import build_attack, list_attacks
from packetforge.validation import validators_available
from scapy.layers.vxlan import VXLAN


def _mirror(attack, env="office"):
    intr = build_attack(attack, load_environment(env), 1_700_000_000.0, random.Random(1))
    base = compile_flowset(FlowSet(flows=intr.flows)).packets
    return render_vantage(base, mirror_vantage()), intr


def test_mirror_vxlan_encapsulates_every_frame():
    pkts, _ = _mirror("psexec-lateral")
    assert pkts and all(VXLAN in p and p[VXLAN].vni == 5001 for p in pkts)


def test_mirror_excludes_link_local_imds_traffic():
    """A cloud traffic mirror never carries link-local (169.254/16): the IMDS is host-terminated
    and link-scoped, so IMDS-SSRF traffic must appear only on an on-host vantage, never a mirror.
    (AWS VPC Traffic Mirroring / GCP Packet Mirroring exclude 169.254/16 by construction.)"""
    from packetforge.compile.vantage import Vantage
    intr = build_attack("imds-ssrf", load_environment("aws-vpc"), 1_700_000_000.0, random.Random(1))
    base = compile_flowset(FlowSet(flows=intr.flows)).packets
    imds = b"\xa9\xfe\xa9\xfe"  # 169.254.169.254
    assert any(imds in bytes(p) for p in base), "scenario should contain IMDS traffic"
    mirror = render_vantage(base, mirror_vantage())
    assert not any(imds in bytes(p) for p in mirror), "IMDS leaked into the mirror capture"
    on_host = render_vantage(base, Vantage("host", link_type="ethernet"))
    assert any(imds in bytes(p) for p in on_host), "IMDS missing from the on-host vantage"


def test_mirror_is_deterministic():
    a, _ = _mirror("k8s-lateral", env="k8s")
    b, _ = _mirror("k8s-lateral", env="k8s")
    assert [bytes(p) for p in a] == [bytes(p) for p in b]


def test_k8s_environment_and_attack_registered():
    assert "k8s" in list_environments()
    assert "k8s-lateral" in list_attacks()
    intr = build_attack("k8s-lateral", load_environment("k8s"), 1_700_000_000.0, random.Random(1))
    e = intr.ground_truth[0]
    assert e.technique.startswith("T1613")
    assert e.iocs["api_server"] == "10.96.0.1" and e.iocs["pod_count"] >= 3


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_k8s_lateral_is_zeek_clean_inner():
    from packetforge.validation import validate_flowset
    intr = build_attack("k8s-lateral", load_environment("k8s"), 1_700_000_000.0, random.Random(1))
    report = validate_flowset(FlowSet(flows=intr.flows), keep_dir=tempfile.mkdtemp())
    assert report.ok, report.summary()


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("attack,env", [("k8s-lateral", "k8s"), ("psexec-lateral", "office")])
def test_mirror_decapsulates_to_inner_conns_zeek_clean(attack, env, tmp_path):
    import subprocess

    from packetforge.validation.roundtrip import _parse_zeek_log
    from scapy.utils import wrpcap
    pkts, intr = _mirror(attack, env=env)
    wrpcap(str(tmp_path / "m.pcap"), pkts)
    subprocess.run(["zeek", "-r", str(tmp_path / "m.pcap"), "FilteredTraceDetection::enable=F"],
                   cwd=str(tmp_path), capture_output=True, text=True)
    # Zeek decapsulates VXLAN: no weird, a tunnel.log entry, and the inner conns are logged.
    assert not _parse_zeek_log(tmp_path / "weird.log"), "mirror produced a Zeek weird"
    tun = _parse_zeek_log(tmp_path / "tunnel.log")
    assert tun and all(r.get("tunnel_type") == "Tunnel::VXLAN" for r in tun)
    conn = _parse_zeek_log(tmp_path / "conn.log")
    # inner (non-VTEP) conns are present alongside the outer tunnel conns
    assert any(not r["id.orig_h"].startswith("10.0.0") for r in conn)
