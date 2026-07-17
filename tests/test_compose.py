# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Environments and the scenario composer."""

import pytest

from packetforge.compose import compose_scenario
from packetforge.environments import list_environments, load_environment
from packetforge.validation import validators_available

ENVS = ["office", "home", "cloud", "ot"]


def test_environments_load():
    assert set(ENVS).issubset(set(list_environments()))
    assert load_environment("cloud").link_type == "linux_sll"
    assert load_environment("office").link_type == "ethernet"


def test_compose_is_deterministic():
    env = load_environment("office")
    a = compose_scenario(env, start_time=1700000000.0, noise_flows=40, seed=7)
    b = compose_scenario(env, start_time=1700000000.0, noise_flows=40, seed=7)
    assert [f.model_dump() for f in a.flows] == [f.model_dump() for f in b.flows]


def test_compose_propagates_link_type():
    fs = compose_scenario(load_environment("cloud"), start_time=1700000000.0, noise_flows=10, seed=1)
    assert fs.capture.link_type == "linux_sll"


def test_client_os_is_a_population():
    """R1: internal hosts draw from an OS mix, so the SYN fingerprint isn't a single value."""
    fs = compose_scenario(load_environment("office"), start_time=1700000000.0,
                          noise_flows=250, seed=1)
    oses = {f.src_os for f in fs.flows if f.transport == "tcp"}
    assert len(oses) >= 3, f"client OS population collapsed to {oses}"


def test_connection_states_are_diverse():
    """R3: real networks fail connections — the capture is not ~100% SF."""
    fs = compose_scenario(load_environment("office"), start_time=1700000000.0,
                          noise_flows=250, seed=1)
    states = {f.conn_state for f in fs.flows if f.transport == "tcp" and f.conn_state}
    assert {"S0", "REJ"} & states, f"no failed connections present: {states}"
    assert len(states) >= 3, f"conn_state diversity too low: {states}"


def test_flow_sizes_are_heavy_tailed():
    """R2: a heavy tail of bulk transfers, so packet sizes aren't uniformly small."""
    fs = compose_scenario(load_environment("office"), start_time=1700000000.0,
                          noise_flows=300, seed=1)
    sizes = [getattr(f.l7, "response_body_len", 0) or getattr(f.l7, "app_data_resp_bytes", 0)
             for f in fs.flows]
    assert max(sizes) > 50_000, "no elephant flows — the full-size packet mode is missing"


def test_benign_false_positive_surface_is_present_and_labeled():
    """R4: the capture carries benign IDS noise, each flow labeled with its expected SID."""
    fs = compose_scenario(load_environment("office"), start_time=1700000000.0,
                          duration_s=600, noise_flows=100, seed=1)
    labeled = [f for f in fs.flows if f.expected_alert]
    assert len(labeled) >= 10, "benign false-positive surface is missing"
    assert all(all(isinstance(s, int) for s in f.expected_alert) for f in labeled)


def test_storyline_is_woven_in():
    env = load_environment("office")
    from packetforge.models.flowspec import DnsL7, Flow
    story = [Flow(flow_id="evil", transport="udp", src_ip="10.10.0.30", dst_ip="10.10.0.10",
                  src_port=51000, dst_port=53, start_time=1700000100.0,
                  l7=DnsL7(qname="evil.example.", answers=["203.0.113.9"]))]
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=20, seed=1, storyline=story)
    assert any(f.flow_id == "evil" for f in fs.flows)


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("envname", ENVS)
def test_composed_scenario_roundtrips_clean(envname):
    from packetforge.validation import validate_flowset
    env = load_environment(envname)
    fs = compose_scenario(env, start_time=1700000000.0, duration_s=600, noise_flows=80, seed=3)
    report = validate_flowset(fs)
    assert report.ok, f"{envname}:\n" + report.summary()
    assert report.zeek_weird == 0 and report.tshark_errors == 0
