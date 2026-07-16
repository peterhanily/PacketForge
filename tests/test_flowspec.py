# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Flow IR validation."""

import pytest
from conftest import EXAMPLE_FLOWS

from packetforge.models.flowspec import FlowSet, load_flowset


def test_example_flowset_loads():
    fs = load_flowset(EXAMPLE_FLOWS)
    assert fs.schema_version == "0.1"
    assert [f.l7.kind for f in fs.flows] == ["dns", "http", "opaque_tcp", "icmp", "tls", "smtp"]


def test_discriminated_union_resolves_types():
    fs = FlowSet.model_validate({"flows": [
        {"flow_id": "d", "transport": "udp", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
         "src_port": 5, "dst_port": 53, "start_time": 0.0,
         "l7": {"kind": "dns", "qname": "x.", "answers": ["3.3.3.3"]}},
    ]})
    assert fs.flows[0].l7.qname == "x."


def test_transport_l7_mismatch_rejected():
    with pytest.raises(Exception):
        FlowSet.model_validate({"flows": [
            {"flow_id": "bad", "transport": "udp", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
             "start_time": 0.0, "l7": {"kind": "http"}},
        ]})


def test_icmp_ports_rejected():
    with pytest.raises(Exception):
        FlowSet.model_validate({"flows": [
            {"flow_id": "i", "transport": "icmp", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
             "src_port": 5, "start_time": 0.0, "l7": {"kind": "icmp"}},
        ]})


def test_incompatible_schema_version_rejected():
    with pytest.raises(Exception):
        FlowSet.model_validate({"schema_version": "9.0", "flows": []})
