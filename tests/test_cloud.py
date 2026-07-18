# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Cloud (AWS/Azure/GCP/OCI) environments + north-south attacks (IMDS SSRF, cloud exfil)."""

import random

import pytest

from packetforge.environments import list_environments, load_environment
from packetforge.models.flowspec import FlowSet
from packetforge.scenarios import build_attack, list_attacks
from packetforge.validation import validators_available

CLOUDS = ["aws-vpc", "azure-vnet", "gcp-vpc", "oci-vcn"]


def test_cloud_environments_registered_and_valid():
    for name in CLOUDS:
        assert name in list_environments()
        env = load_environment(name)          # validates the YAML against the model
        assert env.link_type == "linux_sll"   # per-instance capture agent
        assert env.sensor.nat == "source"      # egress via a NAT gateway


def test_cloud_attacks_registered():
    for name in ("imds-ssrf", "cloud-exfil"):
        assert name in list_attacks()


@pytest.mark.parametrize("cloud,md_host,storage", [
    ("aws-vpc", "169.254.169.254", "s3.amazonaws.com"),
    ("azure-vnet", "169.254.169.254", "blob.core.windows.net"),
    ("gcp-vpc", "metadata.google.internal", "storage.googleapis.com"),
    ("oci-vcn", "169.254.169.254", "oraclecloud.com"),
])
def test_attacks_are_provider_aware(cloud, md_host, storage):
    env = load_environment(cloud)
    imds = build_attack("imds-ssrf", env, 1_700_000_000.0, random.Random(1))
    assert imds.ground_truth[0].technique.startswith("T1552.005")
    # the IMDS request targets the right metadata endpoint for this provider
    assert any(f.l7.host == md_host for f in imds.flows if f.l7.kind == "http")
    assert all(f.dst_ip == "169.254.169.254" for f in imds.flows if f.l7.kind == "http")

    exfil = build_attack("cloud-exfil", env, 1_700_000_000.0, random.Random(1))
    assert exfil.ground_truth[0].technique.startswith("T1567.002")
    assert storage in exfil.ground_truth[0].iocs["storage"]


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("cloud", CLOUDS)
def test_cloud_attacks_are_zeek_clean_and_show_the_signal(cloud, tmp_path):
    from packetforge.validation import validate_flowset
    from packetforge.validation.roundtrip import _parse_zeek_log
    env = load_environment(cloud)

    imds = build_attack("imds-ssrf", env, 1_700_000_000.0, random.Random(1))
    r1 = validate_flowset(FlowSet(flows=imds.flows), keep_dir=str(tmp_path / "imds"))
    assert r1.ok, r1.summary()
    http = _parse_zeek_log(tmp_path / "imds" / "http.log")
    assert any(r.get("id.resp_h") == "169.254.169.254" for r in http), "expected HTTP to the metadata IP"

    exfil = build_attack("cloud-exfil", env, 1_700_000_000.0, random.Random(1))
    r2 = validate_flowset(FlowSet(flows=exfil.flows), keep_dir=str(tmp_path / "exfil"))
    assert r2.ok, r2.summary()
    conn = _parse_zeek_log(tmp_path / "exfil" / "conn.log")
    # the exfil is upload-heavy: some session sends >100 KB out.
    assert max((int(r.get("orig_bytes", "0") or 0) for r in conn), default=0) > 100_000
