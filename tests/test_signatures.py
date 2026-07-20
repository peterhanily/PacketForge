# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Signature-conditioning rule-inverter — parse, invert, and refuse malicious rules."""

import random

from packetforge.environments import load_environment
from packetforge.signatures import (
    _decode_content,
    conditioned_fp_flows,
    invert,
    parse_rules,
)

# A tiny inline ruleset covering each predicate shape the inverter dispatches on, plus a
# MALWARE rule that must be refused. No external ET Open ruleset needed.
_RULES = r'''
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CHAT Skype User-Agent detected"; flow:established,to_server; http.user_agent; content:"Skype"; classtype:policy-violation; sid:2002157; rev:13;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET POLICY GetLatest"; flow:established,to_server; http.uri; content:"/ui/"; nocase; content:"/getlatestversion?ver="; nocase; classtype:policy-violation; sid:2001595; rev:13;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 1863 (msg:"GPL CHAT MSN user search"; flow:established,to_server; content:"CAL "; depth:4; nocase; classtype:policy-violation; sid:2101990; rev:3;)
alert udp $HOME_NET 17500 -> any 17500 (msg:"ET FILE_SHARING Dropbox Broadcasting"; content:"{|22|host_int|22 3a| "; depth:13; classtype:policy-violation; sid:2012648; rev:4;)
alert ip [86.107.194.0/23,89.18.16.0/22] any -> $HOME_NET any (msg:"ET DROP Spamhaus Listed"; classtype:misc-attack; sid:2400012; rev:4769;)
alert dns $HOME_NET any -> any any (msg:"ET DNS Query to a *.top domain"; dns.query; content:".top"; nocase; endswith; classtype:bad-unknown; sid:2023883; rev:3;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Evil Beacon"; content:"evilbeacon"; classtype:trojan-activity; sid:9999999; rev:1;)
'''


def _rules(tmp_path):
    p = tmp_path / "inline.rules"
    p.write_text(_RULES)
    return parse_rules(p)


def test_decode_content_ascii_and_hex():
    assert _decode_content("Skype") == b"Skype"
    assert _decode_content("{|22|host_int|22 3a| ") == b'{"host_int": '
    assert _decode_content("|00 ff|") == b"\x00\xff"


def test_parse_extracts_sids_and_buffers(tmp_path):
    rules = _rules(tmp_path)
    assert rules["ET CHAT Skype User-Agent detected"].sid == 2002157
    ua = rules["ET CHAT Skype User-Agent detected"].contents
    assert any(c.buffer == "http.user_agent" and c.data == b"Skype" for c in ua)
    uri = rules["ET POLICY GetLatest"].contents
    assert [c.data for c in uri if c.buffer == "http.uri"] == [b"/ui/", b"/getlatestversion?ver="]
    assert rules["ET DROP Spamhaus Listed"].src_iplist == ["86.107.194.0/23", "89.18.16.0/22"]
    # the .top rule's content is parsed with an endswith anchor
    top = rules["ET DNS Query to a *.top domain"].contents
    assert any(c.buffer == "dns.query" and c.data == b".top" and c.pos == "end" for c in top)


def test_dns_endswith_places_content_as_suffix(tmp_path):
    from packetforge.signatures import _dns_qname
    rules = _rules(tmp_path)
    qname = _dns_qname(rules["ET DNS Query to a *.top domain"])
    assert qname.rstrip(".").endswith(".top")   # endswith anchor honored


def test_forbidden_malware_rule_is_refused(tmp_path):
    rules = _rules(tmp_path)
    evil = rules["ET MALWARE Evil Beacon"]
    assert not evil.renderable
    env = load_environment("office")
    assert invert(evil, env, client="10.10.0.5", dst_ip="203.0.113.9", sport=1100,
                  start=1_700_000_000.0, flow_id="x") is None


def test_invert_dispatches_by_predicate_shape(tmp_path):
    rules = _rules(tmp_path)
    env = load_environment("office")
    kinds = {}
    for msg, r in rules.items():
        f = invert(r, env, client="10.10.0.5", dst_ip="203.0.113.9", sport=1100,
                   start=1_700_000_000.0, flow_id="x")
        if f is not None:
            kinds[msg] = f.l7.kind
            assert f.expected_alert == [r.sid]
    assert kinds["ET CHAT Skype User-Agent detected"] == "http"
    assert kinds["ET POLICY GetLatest"] == "http"
    assert kinds["GPL CHAT MSN user search"] == "opaque_tcp"
    assert kinds["ET FILE_SHARING Dropbox Broadcasting"] == "opaque_udp"
    assert kinds["ET DROP Spamhaus Listed"] == "opaque_tcp"
    # The UA content really is carried on the wire (so Suricata's http.user_agent matches).
    ua_flow = invert(rules["ET CHAT Skype User-Agent detected"], env, client="10.10.0.5",
                     dst_ip="203.0.113.9", sport=1100, start=1_700_000_000.0, flow_id="x")
    assert "Skype" in ua_flow.l7.user_agent
    # The MSN literal is placed at the head of the opaque payload.
    msn = invert(rules["GPL CHAT MSN user search"], env, client="10.10.0.5", dst_ip="203.0.113.9",
                 sport=1100, start=1_700_000_000.0, flow_id="x")
    assert bytes.fromhex(msn.l7.orig_literal_hex).startswith(b"CAL ")


def test_conditioned_fp_flows_matches_target_and_reports_unmatched(tmp_path):
    rules = _rules(tmp_path)
    env = load_environment("office")
    clients = ["10.10.0.5", "10.10.0.6", "10.10.0.7"]
    target = {"ET CHAT Skype User-Agent detected": 5, "GPL CHAT MSN user search": 2,
              "Some Rule Not In Our Set": 3}
    flows, unmatched = conditioned_fp_flows(target, env, clients, start_time=1_700_000_000.0,
                                            duration=300.0, rng=random.Random(1), rules=rules)
    # 7 renderable triggers (5 + 2); the unknown signature is surfaced, never silently dropped.
    assert len(flows) == 7
    assert unmatched == {"Some Rule Not In Our Set": 3}
    assert all(f.expected_alert for f in flows)


def test_conditioning_is_deterministic(tmp_path):
    rules = _rules(tmp_path)
    env = load_environment("office")
    clients = ["10.10.0.5", "10.10.0.6"]
    target = {"ET CHAT Skype User-Agent detected": 4}
    a, _ = conditioned_fp_flows(target, env, clients, start_time=1_700_000_000.0,
                                duration=300.0, rng=random.Random(7), rules=rules)
    b, _ = conditioned_fp_flows(target, env, clients, start_time=1_700_000_000.0,
                                duration=300.0, rng=random.Random(7), rules=rules)
    assert [f.model_dump() for f in a] == [f.model_dump() for f in b]
