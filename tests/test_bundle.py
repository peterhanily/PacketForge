# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Self-contained detection-CI bundles: the pcap ships with its Zeek logs + answer key."""

import json
import os
import random

import pytest

from packetforge.bundle import write_bundle
from packetforge.compose import compose_scenario
from packetforge.environments import load_environment
from packetforge.scenarios import build_attack
from packetforge.validation import validators_available

ENV = load_environment("office")


def _bundle(out_dir):
    intr = build_attack("ransomware", ENV, 1_700_000_100.0, random.Random(3))
    fs = compose_scenario(ENV, start_time=1_700_000_000.0, noise_flows=40, seed=3, storyline=intr.flows)
    return write_bundle(fs, out_dir, intrusion=intr)


def test_bundle_writes_pcap_ground_truth_and_manifest(tmp_path):
    m = _bundle(tmp_path / "b")
    files = set(os.listdir(tmp_path / "b"))
    assert {"capture.pcap", "GROUND_TRUTH.json", "GROUND_TRUTH.md", "manifest.json"} <= files
    assert m["sha256"] and m["flows"] > 100 and m["ground_truth"] == "GROUND_TRUTH.json"


def test_manifest_is_content_addressed_and_deterministic(tmp_path):
    a = _bundle(tmp_path / "a")
    b = _bundle(tmp_path / "b")
    assert a["sha256"] == b["sha256"]                      # byte-reproducible capture
    saved = json.loads((tmp_path / "a" / "manifest.json").read_text())
    assert saved["sha256"] == a["sha256"]


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_bundle_ships_the_zeek_logs_and_records_consistency(tmp_path):
    m = _bundle(tmp_path / "b")
    # the exact Zeek logs the capture produces are in the bundle...
    assert "conn.log" in m["zeek_logs"] and "dns.log" in m["zeek_logs"]
    assert (tmp_path / "b" / "conn.log").exists()
    # ...and the manifest records that the packets and those logs agree.
    assert m["consistency"]["ok"] is True
    assert m["consistency"]["matched_flows"] == m["consistency"]["total_flows"]
    assert m["consistency"]["zeek_weird"] == 0


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_relative_output_dir_still_produces_zeek_logs(tmp_path, monkeypatch):
    # Regression: a relative keep_dir must not break the Zeek run (it read the pcap relative
    # to its own cwd and found nothing). Run from tmp_path with a relative bundle dir.
    monkeypatch.chdir(tmp_path)
    m = _bundle("rel-bundle")
    assert m["zeek_logs"], "relative output dir produced no Zeek logs"
    assert m["consistency"]["matched_flows"] == m["consistency"]["total_flows"]
