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


def test_ambient_clients_send_varied_originator_bytes():
    """Real clients don't send ~0 app bytes: request headers/cookies and the odd upload give
    the originator a spread. A near-constant orig volume is an easy synthetic tell (l_orig_bytes)."""
    fs = compose_scenario(load_environment("home"), start_time=1700000000.0,
                          noise_flows=300, seed=3)
    orig = [getattr(f.l7, "app_data_orig_bytes", 0) or getattr(f.l7, "request_body_len", 0)
            for f in fs.flows if getattr(f.l7, "kind", "") in ("tls", "http")]
    nonzero = [b for b in orig if b > 0]
    assert len(nonzero) >= 10, "ambient web clients send ~0 originator bytes"
    assert max(nonzero) > 5_000, "no upload tail in originator bytes"
    assert len(set(nonzero)) > 5, "originator bytes not varied (a constant is a tell)"


def test_benign_false_positive_surface_is_present_and_labeled():
    """R4: the capture carries benign IDS noise, each flow labeled with its expected SID."""
    fs = compose_scenario(load_environment("office"), start_time=1700000000.0,
                          duration_s=600, noise_flows=100, seed=1)
    labeled = [f for f in fs.flows if f.expected_alert]
    assert len(labeled) >= 10, "benign false-positive surface is missing"
    assert all(all(isinstance(s, int) for s in f.expected_alert) for f in labeled)


def test_conn_state_plan_folds_zeek_taxonomy():
    """V4: the full 13-state Zeek taxonomy folds onto the five renderable states."""
    from packetforge.compose import _conn_state_plan
    # 70 established (SF+OTH+S1 -> SF, plus RSTO/RSTR), 30 failed (S0+RSTOS0+SH -> S0, REJ)
    plan = _conn_state_plan({"SF": 50, "OTH": 8, "S1": 4, "RSTO": 6, "RSTR": 2,
                             "S0": 14, "RSTOS0": 3, "SH": 3, "REJ": 10})
    assert plan is not None
    assert abs(plan.fail_frac - 0.30) < 1e-9, "failure rate should be (14+3+3+10)/100"
    est_states, est_w = plan.established
    assert dict(zip(est_states, est_w)) == {"SF": 62, "RSTO": 6, "RSTR": 2}  # SF+OTH+S1
    fail_states, fail_w = plan.failed
    assert dict(zip(fail_states, fail_w)) == {"S0": 20, "REJ": 10}           # S0+RSTOS0+SH
    assert _conn_state_plan({}) is None and _conn_state_plan({"OTH": 0}) is None


def test_analog_reproduces_reference_failure_rate():
    """V4: synthesize_analog conditions its failure rate on the reference's conn_state mix."""
    from packetforge.transfer import Profile, synthesize_analog
    prof = Profile(services={"tls": 30, "dns": 20, "http": 20}, total_conns=70, duration=600.0,
                   conn_states={"SF": 60, "S0": 30, "REJ": 10})  # 40% failures
    fs = synthesize_analog(prof, load_environment("office"), seed=5)
    failed = [f for f in fs.flows if f.conn_state in ("S0", "REJ")]
    established = [f for f in fs.flows if f.conn_state in ("SF", "RSTO", "RSTR")]
    frac = len(failed) / (len(failed) + len(established))
    assert 0.30 < frac < 0.50, f"failure rate {frac:.2f} not conditioned toward the ref's 0.40"
    # and the S0:REJ ratio follows the reference (~3:1), not the built-in 6:4
    s0, rej = sum(f.conn_state == "S0" for f in failed), sum(f.conn_state == "REJ" for f in failed)
    assert s0 > rej, f"S0:REJ ratio not conditioned (S0={s0} REJ={rej})"


def test_originator_bytes_are_conditioned_on_the_reference():
    """V5: synthesize_analog grows client byte volume toward the reference's orig_bytes."""
    from packetforge.models.flowspec import HttpL7, TlsL7
    from packetforge.transfer import Profile, synthesize_analog
    # a reference whose TLS/HTTP clients send far more than the composer's bare defaults
    prof = Profile(services={"tls": 25, "http": 25}, total_conns=50, duration=600.0,
                   orig_bytes={"tls": [3000, 8000, 40000], "http": [700, 1500, 9000]})
    fs = synthesize_analog(prof, load_environment("office"), seed=9)
    tls_orig = [f.l7.app_data_orig_bytes for f in fs.flows if isinstance(f.l7, TlsL7)]
    http = [f.l7 for f in fs.flows if isinstance(f.l7, HttpL7)]
    assert tls_orig and max(tls_orig) > 30_000, "TLS client app-data not conditioned upward"
    # HTTP grows via a fat cookie (stays a GET) or, past the header bound, a POST body
    grown = [h for h in http if h.request_body_len > 0 or "Cookie" in h.request_headers]
    assert grown, "HTTP originator volume not conditioned"
    assert any(h.method == "POST" and h.request_body_len > 2048 for h in http), \
        "large HTTP targets should spill into a request body"


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
