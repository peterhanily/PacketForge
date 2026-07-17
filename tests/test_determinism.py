# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Compilation is byte-for-byte deterministic (the EvidenceForge engine contract)."""

from conftest import EXAMPLE_FLOWS

from packetforge.compile.timeline import write_pcap
from packetforge.models.flowspec import load_flowset


def test_identical_bytes_across_runs(tmp_path):
    fs = load_flowset(EXAMPLE_FLOWS)
    a = tmp_path / "a.pcap"
    b = tmp_path / "b.pcap"
    write_pcap(fs, a)
    write_pcap(fs, b)
    assert a.read_bytes() == b.read_bytes()


def test_all_renderers_byte_identical_across_runs():
    """Every renderer must be byte-deterministic (scapy auto-fills some time/GUID
    fields with wall-clock values — this guards against that regressing)."""
    import random

    from packetforge.fingerprints import resolve_endpoint
    from packetforge.models import flowspec as m
    from packetforge.renderers import RENDERERS

    cases = {
        "dns": (m.DnsL7(qname="x.", answers=["1.2.3.4"]), 53, "udp"),
        "http": (m.HttpL7(host="h", response_body_len=50), 80, "tcp"),
        "tls": (m.TlsL7(server_name="s"), 443, "tcp"),
        "smtp": (m.SmtpL7(mail_from="a@x", rcpt_to=["b@y"]), 25, "tcp"),
        "ssh": (m.SshL7(), 22, "tcp"), "ftp": (m.FtpL7(), 21, "tcp"),
        "pop3": (m.Pop3L7(), 110, "tcp"), "imap": (m.ImapL7(), 143, "tcp"),
        "irc": (m.IrcL7(), 6667, "tcp"), "sip": (m.SipL7(), 5060, "udp"),
        "dhcp": (m.DhcpL7(assigned_ip="10.0.0.5", server_ip="10.0.0.9"), 67, "udp"),
        "ntp": (m.NtpL7(), 123, "udp"), "snmp": (m.SnmpL7(), 161, "udp"),
        "radius": (m.RadiusL7(), 1812, "udp"), "modbus": (m.ModbusL7(), 502, "tcp"),
        "ldap": (m.LdapL7(), 389, "tcp"),
        "smb": (m.SmbL7(read_file="report.pdf", file_bytes=3000), 445, "tcp"),
        "dcerpc": (m.DceRpcL7(interface="svcctl", pipe="svcctl", operations=[15, 12, 19, 0]), 445, "tcp"),
        "kerberos": (m.KerberosL7(request_type="TGS", service="HTTP/x@R"), 88, "tcp"),
        "icmp": (m.IcmpL7(), 0, "icmp"),
        "opaque_tcp": (m.OpaqueTcpL7(orig_bytes=50, resp_bytes=50), 9000, "tcp"),
        "opaque_udp": (m.OpaqueUdpL7(orig_bytes=50, resp_bytes=50), 9000, "udp"),
    }
    assert set(cases) == set(RENDERERS), "a renderer is missing a determinism case"
    for kind, (l7, port, tr) in cases.items():
        flow = m.Flow(flow_id="x", transport=tr, src_ip="10.0.0.5", dst_ip="10.0.0.9",
                      src_port=(0 if tr == "icmp" else 50000),
                      dst_port=(0 if tr == "icmp" else port),
                      start_time=1700000000.0, conn_state="SF", l7=l7)
        o = resolve_endpoint("10.0.0.5", 50000, "windows_10")
        r = resolve_endpoint("10.0.0.9", port, "linux")

        def rendered():
            return b"".join(bytes(p) for p in RENDERERS[kind](flow, o, r, random.Random(7)).packets)
        assert rendered() == rendered(), f"{kind} renderer is non-deterministic"


def test_no_renderer_reads_wall_clock(monkeypatch):
    """Output must not depend on the wall clock. scapy fills some ASN.1/time fields
    from ``time.time()`` when left unset (Kerberos rtime/till, NTP, SMB FILETIME);
    at second resolution two back-to-back renders can match by luck, hiding the leak.
    Render each renderer at two clocks years apart and require byte-identity."""
    import random
    import time as _time

    from packetforge.fingerprints import resolve_endpoint
    from packetforge.models import flowspec as m
    from packetforge.renderers import RENDERERS

    cases = {
        "tls": (m.TlsL7(server_name="s"), 443, "tcp"),
        "ntp": (m.NtpL7(), 123, "udp"),
        "smb": (m.SmbL7(read_file="report.pdf", file_bytes=3000), 445, "tcp"),
        "dcerpc": (m.DceRpcL7(interface="svcctl", pipe="svcctl", operations=[15, 12, 19, 0]), 445, "tcp"),
        "kerberos": (m.KerberosL7(request_type="TGS", service="HTTP/x@R"), 88, "tcp"),
        "kerberos_as": (m.KerberosL7(request_type="AS"), 88, "tcp"),
    }
    real_time = _time.time

    def render_at(clock, kind, l7, port, tr):
        monkeypatch.setattr(_time, "time", lambda: float(clock))
        try:
            flow = m.Flow(flow_id="x", transport=tr, src_ip="10.0.0.5", dst_ip="10.0.0.9",
                          src_port=50000, dst_port=port, start_time=1700000000.0,
                          conn_state="SF", l7=l7)
            o = resolve_endpoint("10.0.0.5", 50000, "windows_10")
            r = resolve_endpoint("10.0.0.9", port, "linux")
            return b"".join(bytes(p) for p in RENDERERS[l7.kind](flow, o, r, random.Random(7)).packets)
        finally:
            monkeypatch.setattr(_time, "time", real_time)

    for name, (l7, port, tr) in cases.items():
        a = render_at(1_500_000_000, name, l7, port, tr)  # 2017
        b = render_at(1_900_000_000, name, l7, port, tr)  # 2030
        assert a == b, f"{name} renderer output depends on wall-clock time"


def test_composer_deterministic_at_scale(tmp_path):
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment
    for name in ("office", "home", "cloud", "ot"):
        env = load_environment(name)
        write_pcap(compose_scenario(env, start_time=1700000000.0, noise_flows=200, seed=42),
                   tmp_path / f"{name}-a.pcap")
        write_pcap(compose_scenario(env, start_time=1700000000.0, noise_flows=200, seed=42),
                   tmp_path / f"{name}-b.pcap")
        assert (tmp_path / f"{name}-a.pcap").read_bytes() == (tmp_path / f"{name}-b.pcap").read_bytes(), \
            f"{name} composer non-deterministic"


def test_order_independent_seeding(tmp_path):
    """Reversing flow order changes packet ordering by time, not per-flow content."""
    fs = load_flowset(EXAMPLE_FLOWS)
    r1 = write_pcap(fs, tmp_path / "x.pcap")
    fs.flows.reverse()
    r2 = write_pcap(fs, tmp_path / "y.pcap")
    # same set of flows rendered => same total packet count regardless of input order
    assert len(r1.packets) == len(r2.packets)
