# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""LAN adversary-in-the-middle: LLMNR/NBT-NS/mDNS + Responder-style poisoning (T1557.001)."""

import random

import pytest

from packetforge.compile.timeline import compile_flowset
from packetforge.environments import load_environment
from packetforge.models.flowspec import Flow, FlowSet, NameQueryL7
from packetforge.scenarios import build_attack, list_attacks
from packetforge.validation import validators_available

ENV = load_environment("office")


def _nq(protocol, dst, dport, qname, poison=None):
    return FlowSet(flows=[Flow(flow_id=f"nq-{protocol}", transport="udp", src_ip="10.10.0.40",
        dst_ip=dst, src_port=54000, dst_port=dport, start_time=1_700_000_000.0,
        l7=NameQueryL7(protocol=protocol, qname=qname, poison_from=poison))])


def test_name_resolution_renders_query_and_optional_poison():
    # query only
    one = compile_flowset(_nq("mdns", "224.0.0.251", 5353, "printer.local")).packets
    assert len(one) == 1
    # query + poisoned reply
    two = compile_flowset(_nq("llmnr", "224.0.0.252", 5355, "wpad", "10.10.0.66")).packets
    assert len(two) == 2
    assert compile_flowset(_nq("llmnr", "224.0.0.252", 5355, "wpad", "10.10.0.66")).packets[0].time \
        == two[0].time  # deterministic


def test_poison_reply_comes_from_the_attacker_not_the_multicast_group():
    from scapy.layers.inet import IP
    pkts = compile_flowset(_nq("llmnr", "224.0.0.252", 5355, "wpad", "10.10.0.66")).packets
    query, reply = pkts
    assert query[IP].dst == "224.0.0.252"          # victim -> multicast
    assert reply[IP].src == "10.10.0.66"           # attacker answers...
    assert reply[IP].dst == "10.10.0.40"           # ...straight back to the victim


def test_llmnr_poisoning_registered_and_labeled():
    assert "llmnr-poisoning" in list_attacks()
    intr = build_attack("llmnr-poisoning", ENV, 1_700_000_000.0, random.Random(1))
    e = intr.ground_truth[0]
    assert e.technique.startswith("T1557.001")
    assert e.iocs["attacker"] and e.iocs["expected_signal"]
    # the storyline: LLMNR poison flows + the follow-on SMB auth to the attacker
    kinds = [f.l7.kind for f in intr.flows]
    assert "namequery" in kinds and "smb" in kinds
    assert all(f.flow_id.startswith("atk-") for f in intr.flows)


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("protocol,dst,dport", [
    ("llmnr", "224.0.0.252", 5355), ("nbns", "10.10.255.255", 137), ("mdns", "224.0.0.251", 5353)])
def test_name_resolution_is_zeek_clean(protocol, dst, dport, tmp_path):
    from packetforge.validation import validate_flowset
    report = validate_flowset(_nq(protocol, dst, dport, "TESTNAME", "10.10.0.66"),
                              keep_dir=str(tmp_path))
    assert report.zeek_weird == 0 and report.zeek_reporter == 0, report.summary()
    assert not report.mismatches, report.summary()


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
def test_llmnr_poisoning_shows_the_poison_and_the_smb_auth(tmp_path):
    from packetforge.validation import validate_flowset
    from packetforge.validation.roundtrip import _parse_zeek_log
    intr = build_attack("llmnr-poisoning", ENV, 1_700_000_000.0, random.Random(1))
    attacker = intr.ground_truth[0].iocs["attacker"]
    report = validate_flowset(FlowSet(flows=intr.flows), keep_dir=str(tmp_path))
    assert report.zeek_weird == 0 and report.zeek_reporter == 0, report.summary()
    # The poisoned LLMNR answer (attacker IP) is visible in dns.log...
    answers = {a for r in _parse_zeek_log(tmp_path / "dns.log")
               for a in r.get("answers", "").split(",") if a not in ("", "-")}
    assert attacker in answers, answers
    # ...and the victim then authenticated to that attacker over SMB.
    assert any(r.get("id.resp_h") == attacker and str(r.get("id.resp_p")) == "445"
               for r in _parse_zeek_log(tmp_path / "conn.log")), "expected SMB to the attacker"
