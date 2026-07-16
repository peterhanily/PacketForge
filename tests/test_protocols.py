# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Every protocol renderer round-trips clean through real Zeek."""

import pytest

from packetforge.models.flowspec import FlowSet
from packetforge.validation import validators_available

# (flow_id, dict describing the flow) — one minimal flow per protocol.
CASES = {
    "dhcp": {"transport": "udp", "src_ip": "10.0.0.55", "dst_ip": "10.0.0.1",
             "src_port": 68, "dst_port": 67,
             "l7": {"kind": "dhcp", "assigned_ip": "10.0.0.55", "server_ip": "10.0.0.1"}},
    "ntp": {"transport": "udp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1",
            "src_port": 51000, "dst_port": 123, "l7": {"kind": "ntp", "count": 2}},
    "ssh": {"transport": "tcp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51001,
            "dst_port": 22, "conn_state": "SF", "l7": {"kind": "ssh", "payload_bytes": 1500}},
    "ftp": {"transport": "tcp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.20", "src_port": 51002,
            "dst_port": 21, "conn_state": "SF", "l7": {"kind": "ftp", "user": "bob"}},
    "snmp": {"transport": "udp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51003,
             "dst_port": 161, "l7": {"kind": "snmp", "count": 2}},
    "modbus": {"transport": "tcp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51004,
               "dst_port": 502, "conn_state": "SF", "l7": {"kind": "modbus", "count": 3}},
    "radius": {"transport": "udp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51005,
               "dst_port": 1812, "l7": {"kind": "radius", "username": "alice"}},
    "smtp": {"transport": "tcp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.25", "src_port": 51006,
             "dst_port": 25, "conn_state": "SF",
             "l7": {"kind": "smtp", "mail_from": "a@x.example", "rcpt_to": ["b@y.example"],
                    "subject": "hi"}},
    "ldap": {"transport": "tcp", "src_ip": "10.10.0.30", "dst_ip": "10.10.0.10", "src_port": 51007,
             "dst_port": 389, "conn_state": "SF",
             "l7": {"kind": "ldap", "searches": ["DC=corp,DC=local"]}},
    "smb": {"transport": "tcp", "src_ip": "10.10.0.30", "dst_ip": "10.10.0.20", "src_port": 51008,
            "dst_port": 445, "conn_state": "SF", "l7": {"kind": "smb"}},
    "kerberos": {"transport": "tcp", "src_ip": "10.10.0.30", "dst_ip": "10.10.0.10", "src_port": 51013,
                 "dst_port": 88, "conn_state": "SF",
                 "l7": {"kind": "kerberos", "request_type": "TGS",
                        "service": "MSSQLSvc/db.corp.example:1433@CORP.EXAMPLE", "etype": 23}},
    "pop3": {"transport": "tcp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51009,
             "dst_port": 110, "conn_state": "SF", "l7": {"kind": "pop3"}},
    "imap": {"transport": "tcp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51010,
             "dst_port": 143, "conn_state": "SF", "l7": {"kind": "imap"}},
    "irc": {"transport": "tcp", "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "src_port": 51011,
            "dst_port": 6667, "conn_state": "SF", "l7": {"kind": "irc", "channel": "#c2"}},
    "sip": {"transport": "udp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51012,
            "dst_port": 5060, "l7": {"kind": "sip"}},
}


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("name", sorted(CASES))
def test_protocol_roundtrips_clean(name):
    from packetforge.validation import validate_flowset
    spec = dict(CASES[name], flow_id=name, start_time=1700000000.0)
    report = validate_flowset(FlowSet.model_validate({"flows": [spec]}))
    assert report.ok, "\n" + report.summary()
    assert report.zeek_weird == 0 and report.tshark_errors == 0
