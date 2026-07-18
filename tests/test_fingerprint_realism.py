# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Fingerprint realism: a modern TLS 1.3 ClientHello, negotiated TCP timestamps, and
per-OS IP-ID / DF — the packet-level tells a JA3/JA4- or p0f-aware adversary keys on,
and which a real capture shows but earlier synthetic captures did not."""

import random

from scapy.layers.inet import IP, TCP
from scapy.layers.tls.record import TLS

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.compile.timeline import compile_flowset
from packetforge.models.flowspec import Flow, FlowSet, TlsL7
from packetforge.realism import _PKT_FEATURES


def _tls_flow(version, alpn=("h2", "http/1.1")):
    return Flow(flow_id="t", transport="tcp", src_ip="10.10.0.40", dst_ip="140.82.121.4",
                src_port=50000, dst_port=443, start_time=1_700_000_000.0, conn_state="SF",
                src_os="macos", dst_os="linux",
                l7=TlsL7(server_name="example.com", version=version,
                         client_profile="generic_browser", alpn=list(alpn),
                         app_data_resp_bytes=200))


def _client_hello(pkts):
    from scapy.packet import Raw
    for p in pkts:
        if Raw in p and bytes(p[Raw].load)[:1] == b"\x16":   # a TLS handshake record
            for m in getattr(TLS(bytes(p[Raw].load)), "msg", []) or []:
                if m.__class__.__name__ == "TLSClientHello":
                    return m
    return None


def test_tls13_client_hello_is_a_modern_shape():
    ch = _client_hello(compile_flowset(FlowSet(flows=[_tls_flow("TLS1.3")])).packets)
    assert ch is not None
    ext_types = {e.type for e in ch.ext}
    # supported_versions, key_share, psk_key_exchange_modes, ALPN — the set a real client sends
    assert {43, 51, 45, 16} <= ext_types, ext_types
    assert any(c in ch.ciphers for c in (0x1301, 0x1302, 0x1303))  # 1.3 ciphers offered


def test_tls12_hello_omits_the_tls13_extensions():
    ch = _client_hello(compile_flowset(FlowSet(flows=[_tls_flow("TLS1.2", alpn=())])).packets)
    ext_types = {e.type for e in ch.ext}
    assert 43 not in ext_types and 51 not in ext_types  # no 1.3 negotiation without 1.3


def _ep(ip, ipid, ts, ttl=64):
    return Endpoint(ip=ip, port=443, mac="02:00:00:00:00:0" + ip[-1], ttl=ttl, window=64240,
                    timestamps=ts, ip_id_mode=ipid, syn_options=[("MSS", 1460)])


def test_tcp_timestamps_negotiated_and_linux_ipid_zero_with_df():
    orig = _ep("10.10.0.4", "random", ts=True)
    resp = _ep("10.10.0.8", "zero", ts=True)  # a Linux server
    res = build_tcp_flow(orig, resp, [TcpMessage(True, b"hi"), TcpMessage(False, b"yo")],
                         start_time=1_700_000_000.0, rtt=0.02, rng=random.Random(1))
    pkts = res.packets
    assert any(p[TCP].options and any(o[0] == "Timestamp" for o in p[TCP].options) for p in pkts)
    assert all(int(p[IP].flags) & 0x02 for p in pkts)                 # DF set on all IPv4
    assert {p[IP].id for p in pkts if p[IP].src == resp.ip} == {0}    # Linux -> IP-ID 0


def test_windows_ipid_increments_and_no_timestamps_when_unsupported():
    cli = _ep("10.10.0.4", "incremental", ts=False, ttl=128)
    win = _ep("10.10.0.8", "incremental", ts=False, ttl=128)         # a Windows host
    res = build_tcp_flow(cli, win, [TcpMessage(True, b"a"), TcpMessage(False, b"b"),
                                    TcpMessage(False, b"c")],
                         start_time=1_700_000_000.0, rtt=0.02, rng=random.Random(2))
    pkts = res.packets
    win_ids = [p[IP].id for p in pkts if p[IP].src == win.ip]
    assert len(win_ids) >= 2 and all((win_ids[i + 1] - win_ids[i]) & 0xFFFF == 1
                                     for i in range(len(win_ids) - 1))
    # neither end advertises TS, so no segment carries the option
    assert not any(p[TCP].options and any(o[0] == "Timestamp" for o in p[TCP].options) for p in pkts)


def test_c2st_features_include_the_l7_axis():
    # the realism adversary now sees the handshake/fingerprint axis, not just flow stats
    for name in ("has_tcp_ts", "tls13", "ch_n_ciphers", "ch_n_exts", "ch_has_alpn"):
        assert name in _PKT_FEATURES
