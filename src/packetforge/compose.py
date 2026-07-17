# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Scenario composer: environment-appropriate ambient noise + a storyline.

Generates a FlowSet of benign background traffic sized and shaped by an Environment
(so a hunter must actually hunt), spread across a time window so flows overlap and run
concurrently, then weaves in any malicious storyline flows. Deterministic given a seed
and an explicit start time.

Services with a faithful renderer are rendered for real; the rest (SMB/Kerberos/LDAP/
Modbus/S7/DNP3/...) are rendered as honest structure-only TCP shells on their ports —
clean under Zeek, pending faithful renderers.
"""

from __future__ import annotations

import hashlib
import ipaddress
import random

from packetforge.environments import Environment
from packetforge.models.flowspec import (
    CaptureMeta, DhcpL7, DnsL7, Flow, FlowSet, FtpL7, HttpL7, IcmpL7, ImapL7, IrcL7,
    KerberosL7, LdapL7, ModbusL7, NtpL7, OpaqueTcpL7, Pop3L7, RadiusL7, SipL7, SmbL7,
    SnmpL7, SshL7, TlsL7,
)

_FAITHFUL = {"dns", "tls", "http", "ntp", "dhcp", "ssh", "ftp", "icmp",
             "snmp", "modbus", "radius", "ldap", "smb", "kerberos", "pop3", "imap",
             "irc", "sip"}

# Named traffic volume levels — approximate benign flows per minute a sensor sees.
VOLUME_RATES = {"quiet": 20, "normal": 60, "busy": 200, "saturated": 600}


def flows_for_volume(level: str, duration_s: float) -> int:
    """Convert a named volume level over a window into a benign flow count."""
    if level not in VOLUME_RATES:
        raise ValueError(f"unknown volume {level!r}; choose from {sorted(VOLUME_RATES)}")
    return max(1, round(VOLUME_RATES[level] * duration_s / 60.0))
_TCP_PORTS = {"http": 80, "tls": 443, "ssh": 22, "ftp": 21, "smtp": 25, "smb": 445,
              "kerberos": 88, "ldap": 389, "rdp": 3389, "modbus": 502, "s7": 102,
              "dnp3": 20000, "enip": 44818, "mysql": 3306, "mssql": 1433, "rpc": 135}

_EXTERNAL = [
    ("140.82.121.4", "api.github.com"), ("152.199.19.161", "cdn.example.net"),
    ("104.16.132.229", "updates.example.com"), ("142.250.72.14", "www.example.org"),
    ("13.107.42.14", "portal.example.io"), ("151.101.1.140", "assets.example.co"),
]
_DNS_NAMES = ["www.example.com", "api.example.net", "cdn.example.org", "mail.corp.local",
              "fileserver.corp.local", "dc01.corp.local", "updates.example.io"]


def _seeded(env_name: str, seed: int) -> random.Random:
    h = hashlib.sha256(f"{env_name}:{seed}".encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def _bursty_times(n: int, start: float, duration: float, rng: random.Random) -> list:
    """Self-exciting-ish arrival times: flows cluster into bursts, not uniform noise.

    Uniform-random start times (mean gap ~= stdev) are the classic synthetic tell;
    real user/host activity comes in bursts. We scatter a few burst centers over the
    window and draw each flow tightly around one, so gaps are bursty (mean << stdev).
    """
    if n <= 0:
        return []
    n_bursts = max(1, round(n ** 0.5))
    centers = [rng.uniform(0, duration) for _ in range(n_bursts)]
    spread = max(0.5, duration / (n_bursts * 6.0))  # tight clusters
    out = []
    for _ in range(n):
        t = rng.choice(centers) + rng.gauss(0.0, spread)
        out.append(start + min(duration, max(0.0, t)))
    return sorted(out)


# Real networks are full of failed connections, so a ~100%-SF capture is itself a tell.
# Established service flows still succeed most of the time, but a realistic minority reset
# mid-stream (RSTO/RSTR are "established" — they carry their L7, then abort). Pure
# connection failures (S0/REJ — dead hosts, closed ports, scans) are injected separately
# as connectionless flows, since a failed handshake carries no application layer.
_SERVICE_CONN_STATES = ["SF"] * 88 + ["RSTO"] * 8 + ["RSTR"] * 4
_FAILED_CONN_STATES = ["S0"] * 6 + ["REJ"] * 4   # relative weights; ~15% of ambient volume


def _benign_conn_state(rng: random.Random) -> str:
    return rng.choice(_SERVICE_CONN_STATES)


def _resp_size(rng: random.Random) -> int:
    """A heavy-tailed transfer size: mostly small ("mice"), a heavy tail of bulk
    transfers ("elephants"). Real captures are ~1/3 full-size (MTU) packets because a
    few large flows dominate the bytes; uniform small bodies never produce that mode.
    """
    if rng.random() < 0.14:                              # elephant: a bulk transfer
        return min(700_000, int(rng.paretovariate(0.9) * 22_000))
    return max(0, int(rng.lognormvariate(6.0, 1.3)))     # mouse: small/medium body


def _weighted_choice(rng: random.Random, items: list, weights: list):
    total = sum(weights)
    r = rng.uniform(0, total)
    upto = 0.0
    for item, w in zip(items, weights):
        upto += w
        if r <= upto:
            return item
    return items[-1]


def _internal_hosts(env: Environment, n: int) -> list:
    net = ipaddress.ip_network(env.subnet, strict=False)
    base = int(net.network_address)
    # deterministic host addresses starting at .20, skipping gateway/dns
    reserved = {env.gateway, env.dns_server}
    out, i = [], 20
    while len(out) < n:
        ip = str(ipaddress.ip_address(base + i))
        if ip not in reserved and ipaddress.ip_address(ip) in net:
            out.append(ip)
        i += 1
    return out


def _server(client: str, clients: list, rng: random.Random) -> str:
    """An internal peer distinct from the client (avoid self-connections)."""
    others = [c for c in clients if c != client]
    return rng.choice(others) if others else client


def _host_os_map(env: Environment, clients: list) -> dict:
    """Assign each internal host a stable OS from the environment's client mix.

    The OS is a pure function of (env, host_ip) — independent of flow-generation order —
    so a host keeps one coherent TCP/IP fingerprint and the assignment stays deterministic.
    Empty mix -> every host uses the environment default.
    """
    mix = env.client_os_mix or {env.default_client_os: 1}
    oses = sorted(mix)
    weights = [mix[o] for o in oses]
    out = {}
    for ip in clients:
        h = hashlib.sha256(f"os:{env.name}:{ip}".encode()).digest()
        r = random.Random(int.from_bytes(h[:8], "big"))
        out[ip] = _weighted_choice(r, oses, weights)
    return out


def _ambient_flow(env: Environment, service: str, clients: list, fid: str,
                  start: float, rng: random.Random, sport: int,
                  host_os: dict | None = None) -> Flow | None:
    client = rng.choice(clients)
    cstate = _benign_conn_state(rng)  # most flows succeed (SF); a realistic minority fail
    common = dict(flow_id=fid, src_ip=client, start_time=round(start, 6),
                  src_os=(host_os or {}).get(client, env.default_client_os),
                  dst_os=env.default_server_os)

    if service == "dns":
        return Flow(**common, transport="udp", src_port=sport, dst_port=53,
                    dst_ip=env.dns_server, l7=DnsL7(qname=rng.choice(_DNS_NAMES) + ".",
                    answers=[rng.choice(_EXTERNAL)[0]]))
    if service == "ntp":
        return Flow(**common, transport="udp", src_port=sport, dst_port=123,
                    dst_ip=env.gateway, l7=NtpL7())
    if service == "dhcp":
        return Flow(**common, transport="udp", src_port=68, dst_port=67, dst_ip=env.gateway,
                    l7=DhcpL7(assigned_ip=client, server_ip=env.gateway, gateway=env.gateway,
                              dns_server=env.dns_server))
    if service in ("tls", "http"):
        ip, name = rng.choice(_EXTERNAL)
        port = 443 if service == "tls" else 80
        l7 = (TlsL7(server_name=name, client_profile=rng.choice(["generic_browser", "curl"]),
                    app_data_resp_bytes=_resp_size(rng))
              if service == "tls" else
              HttpL7(host=name, uri=rng.choice(["/", "/api/v1/status", "/index.html"]),
                     status=rng.choice([200, 200, 304, 404]), response_body_len=_resp_size(rng)))
        return Flow(**common, transport="tcp", src_port=sport, dst_port=port, dst_ip=ip,
                    conn_state=cstate, l7=l7)
    if service == "ssh":
        return Flow(**common, transport="tcp", src_port=sport, dst_port=22,
                    dst_ip=_server(client, clients, rng), conn_state=cstate, l7=SshL7())
    if service == "ftp":
        return Flow(**common, transport="tcp", src_port=sport, dst_port=21,
                    dst_ip=_server(client, clients, rng), conn_state=cstate, l7=FtpL7())
    if service == "icmp":
        return Flow(**common, transport="icmp",
                    dst_ip=_server(client, clients, rng), l7=IcmpL7(count=rng.randint(1, 3)))
    if service == "snmp":
        return Flow(**common, transport="udp", src_port=sport, dst_port=161,
                    dst_ip=_server(client, clients, rng), l7=SnmpL7())
    if service == "radius":
        return Flow(**common, transport="udp", src_port=sport, dst_port=1812,
                    dst_ip=_server(client, clients, rng), l7=RadiusL7())
    if service == "modbus":
        return Flow(**common, transport="tcp", src_port=sport, dst_port=502,
                    dst_ip=_server(client, clients, rng), conn_state=cstate,
                    l7=ModbusL7(quantity=rng.choice([5, 10, 20])))
    if service == "kerberos":
        # Benign AD auth to the DC: AES256 with pre-auth — the healthy baseline a
        # Kerberoasting/AS-REP-roasting detection must stay silent on.
        as_or_tgs = rng.choice(["AS", "AS", "TGS"])
        svc = "" if as_or_tgs == "AS" else rng.choice(
            ["cifs/fileserver.corp.example@CORP.EXAMPLE", "host/dc01.corp.example@CORP.EXAMPLE"])
        return Flow(**common, transport="tcp", src_port=sport, dst_port=88,
                    dst_ip=env.dns_server, conn_state=cstate,
                    l7=KerberosL7(request_type=as_or_tgs, client=f"user{sport % 50}",
                                  service=svc, etype=18, request_etypes=[18, 17]))
    if service == "ldap":
        return Flow(**common, transport="tcp", src_port=sport, dst_port=389,
                    dst_ip=env.dns_server, conn_state=cstate, l7=LdapL7())
    if service == "smb":
        return Flow(**common, transport="tcp", src_port=sport, dst_port=445,
                    dst_ip=_server(client, clients, rng), conn_state=cstate, l7=SmbL7())
    if service == "pop3":
        return Flow(**common, transport="tcp", src_port=sport, dst_port=110,
                    dst_ip=_server(client, clients, rng), conn_state=cstate, l7=Pop3L7())
    if service == "imap":
        return Flow(**common, transport="tcp", src_port=sport, dst_port=143,
                    dst_ip=_server(client, clients, rng), conn_state=cstate, l7=ImapL7())
    if service == "irc":
        ip, _ = rng.choice(_EXTERNAL)
        return Flow(**common, transport="tcp", src_port=sport, dst_port=6667,
                    dst_ip=ip, conn_state=cstate, l7=IrcL7(nick=f"n{sport}"))
    if service == "sip":
        return Flow(**common, transport="udp", src_port=sport, dst_port=5060,
                    dst_ip=_server(client, clients, rng), l7=SipL7())

    # no faithful renderer yet -> honest structure-only TCP shell on the service port
    port = _TCP_PORTS.get(service)
    if port is None:
        return None
    # Opaque shells stay byte-less: Zeek binds protocol analyzers to these ports (dnp3,
    # dce_rpc, mysql, rdp...) and would flag filler bytes as weird. Bulk-size realism
    # comes from the faithful http/tls renderers, which Zeek parses cleanly.
    return Flow(**common, transport="tcp", src_port=sport, dst_port=port,
                dst_ip=_server(client, clients, rng), conn_state=cstate,
                l7=OpaqueTcpL7(service_hint=service, orig_bytes=0, resp_bytes=0))


_FAIL_PORTS = [445, 3389, 22, 139, 1433, 5900, 8080, 23, 3306]


def _failed_flow(env: Environment, clients: list, fid: str, start: float,
                 rng: random.Random, sport: int, host_os: dict) -> Flow | None:
    """A benign failed connection — dead host / closed port / scan (S0 or REJ)."""
    if len(clients) < 2:
        return None
    client = rng.choice(clients)
    cstate = rng.choice(_FAILED_CONN_STATES)
    return Flow(flow_id=fid, src_ip=client, dst_ip=_server(client, clients, rng),
                start_time=round(start, 6), transport="tcp", src_port=sport,
                dst_port=rng.choice(_FAIL_PORTS),
                src_os=(host_os or {}).get(client, env.default_client_os),
                dst_os=env.default_server_os, conn_state=cstate,
                l7=OpaqueTcpL7(service_hint="", orig_bytes=0, resp_bytes=0))


# Benign behaviors that trip Emerging Threats INFO/POLICY/DYN_DNS rules — the false-
# positive surface every real network has and a ~0-alert synthetic capture conspicuously
# lacks. Each carries the ET SID(s) it is expected to fire (verified against ET Open), so
# the FP surface is itself labeled ground truth, not incidental noise.
_FP_DNS = [
    ("update.no-ip.org.", [2013743]),
    ("host.duckdns.org.", [2022918, 2042936]),
    ("promo.freefile.top.", [2023883]),
    ("deals.shopnow.biz.", [2027863]),
]
_FP_HTTP = [("api.ipify.org", [2021997]), ("checkip.dyndns.org", [2021378])]
_FP_PER_HOUR = 180.0   # target benign alert rate; real enterprise sensors sit in the hundreds


def _benign_fp_flow(env: Environment, clients: list, fid: str, start: float,
                    rng: random.Random, sport: int, host_os: dict) -> Flow:
    client = rng.choice(clients)
    src_os = (host_os or {}).get(client, env.default_client_os)
    common = dict(flow_id=fid, src_ip=client, start_time=round(start, 6), src_os=src_os,
                  dst_os=env.default_server_os)
    if rng.random() < 0.7:   # DNS noise dominates the real benign-alert surface
        qname, sids = rng.choice(_FP_DNS)
        return Flow(**common, transport="udp", src_port=sport, dst_port=53,
                    dst_ip=env.dns_server, expected_alert=sids,
                    l7=DnsL7(qname=qname, answers=[rng.choice(_EXTERNAL)[0]]))
    host, sids = rng.choice(_FP_HTTP)
    return Flow(**common, transport="tcp", src_port=sport, dst_port=80,
                dst_ip=rng.choice(_EXTERNAL)[0], conn_state="SF", expected_alert=sids,
                l7=HttpL7(host=host, uri="/", status=200, response_body_len=50))


def compose_scenario(env: Environment, *, start_time: float, duration_s: float = 600.0,
                     noise_flows: int = 100, num_hosts: int = 12, seed: int = 0,
                     storyline: list | None = None, texture: str = "clean") -> FlowSet:
    """Compose ambient noise for ``env`` plus an optional storyline into one FlowSet."""
    rng = _seeded(env.name, seed)
    clients = _internal_hosts(env, num_hosts)
    host_os = _host_os_map(env, clients)
    services = [a.service for a in env.ambient]
    weights = [a.weight for a in env.ambient]
    times = _bursty_times(noise_flows, start_time, duration_s, rng)

    flows: list = []
    for i in range(noise_flows):
        service = _weighted_choice(rng, services, weights)
        sport = 1025 + (i % 64000)  # unique per flow -> unique 5-tuple
        flow = _ambient_flow(env, service, clients, f"noise-{i:04d}-{service}", times[i],
                             rng, sport, host_os)
        if flow is not None:
            flows.append(flow)

    # A realistic minority of connection attempts fail outright (dead hosts, closed
    # ports, scans) — the S0/REJ states a ~100%-SF capture never shows.
    n_fail = round(noise_flows * 0.15)
    fail_times = _bursty_times(n_fail, start_time, duration_s, rng)
    for j in range(n_fail):
        ff = _failed_flow(env, clients, f"fail-{j:04d}", fail_times[j], rng,
                          60000 + (j % 5000), host_os)
        if ff is not None:
            flows.append(ff)

    # Weave in the benign false-positive surface at a realistic rate, so the capture
    # trips the ET INFO/DYN_DNS noise a real sensor sees instead of being suspiciously silent.
    n_fp = round(_FP_PER_HOUR * duration_s / 3600.0)
    fp_times = _bursty_times(n_fp, start_time, duration_s, rng)
    for k in range(n_fp):
        flows.append(_benign_fp_flow(env, clients, f"fp-{k:04d}", fp_times[k], rng,
                                     55000 + (k % 4000), host_os))

    if storyline:
        flows.extend(storyline)

    return FlowSet(
        capture=CaptureMeta(description=f"{env.name}: ambient + storyline",
                            link_type=env.link_type, mac_oui=env.mac_oui, texture=texture),
        flows=flows,
    )
