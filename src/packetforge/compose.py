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
import math
import random
from dataclasses import dataclass

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


def _activity_envelope(duration: float, rng: random.Random):
    """A seeded, non-stationary activity envelope over the capture window.

    Real traffic is not stationary across its timespan — there are browsing lulls, busy
    periods, and bulk/backup windows — so the first half of a real capture is measurably
    distinguishable from the second (the within-source ``temporal_split_auc`` baseline sits
    at ~0.7 for real captures, ~0.5 for a stationary generator). The key is *low-frequency*
    structure: an i.i.d. per-phase jitter averages out across the two halves, so we build a
    smooth signal from a strong fundamental (period ~= the whole capture, random phase) plus
    two harmonics. It drives a ``bulk`` bias (transfer volume) and a ``webish`` bias (service
    mix leans web/bulk vs chatty) so *multiple* feature axes drift together across the span.
    Arrivals still get heavy-tailed per-phase activity for burstiness. Fully seeded.
    """
    def _walk(k: int = 16):
        """A seeded, smooth random-walk signal over [0,1], normalized to zero-mean/unit-std.
        A random walk has dominant low-frequency power, so its endpoints reliably drift apart —
        the first half of the capture systematically differs from the second (what a random-phase
        sinusoid fails at, because it averages out across the two halves)."""
        acc, pts = 0.0, []
        for _ in range(k):
            acc += rng.gauss(0.0, 1.0)
            pts.append(acc)
        m = sum(pts) / k
        pts = [p - m for p in pts]
        sd = (sum(p * p for p in pts) / k) ** 0.5 or 1.0
        pts = [p / sd for p in pts]

        def f(pos01: float) -> float:
            x = max(0.0, min(1.0, pos01)) * (k - 1)
            i = int(x)
            j = min(k - 1, i + 1)
            return pts[i] * (1 - (x - i)) + pts[j] * (x - i)
        return f

    def _sig(z: float) -> float:
        return 1.0 / (1.0 + math.exp(-z))

    w_bulk, w_web, w_dir, w_fail = _walk(), _walk(), _walk(), _walk()
    n_phase = max(2, min(10, round(duration / 45.0)))
    activity = [rng.paretovariate(1.5) for _ in range(n_phase)]  # heavy-tailed arrival density

    def envelope(pos01: float) -> dict:
        return {
            "bulk": math.exp(1.1 * w_bulk(pos01)),      # ~[0.3, 3.0] transfer-volume trend
            "web": _sig(1.8 * w_web(pos01)),            # 0..1 web/bulk vs chatty service lean
            "dir": _sig(2.2 * w_dir(pos01)),            # 0..1 resp-heavy (downloads) vs orig-heavy
            "fail": _sig(1.9 * w_fail(pos01)),          # 0..1 connection-failure intensity (scan-ish)
        }

    return envelope, activity


def _bursty_times(n: int, start: float, duration: float, rng: random.Random,
                  activity: list | None = None) -> list:
    """Non-stationary, self-exciting arrival times: flows cluster into bursts *and* the
    burst density varies across the window per the activity envelope.

    Uniform-random start times (mean gap ~= stdev) are the classic synthetic tell, and a
    stationary burst model still leaves the two halves of a capture statistically identical.
    We allot the n flows across phases in proportion to a heavy-tailed activity weight (so
    some periods are far busier than others — non-stationary), then scatter each phase's
    flows into local bursts. Returns exactly n times.
    """
    if n <= 0:
        return []
    n_phase = len(activity) if activity else max(1, round(n ** 0.5))
    if not activity:                                    # flat fallback (no envelope given)
        activity = [1.0] * n_phase
    phase_len = duration / n_phase
    total_w = sum(activity) or 1.0
    # deterministic allotment of exactly n flows across phases, largest-remainder method
    raw = [n * w / total_w for w in activity]
    counts = [int(x) for x in raw]
    rem = n - sum(counts)
    for i in sorted(range(n_phase), key=lambda j: raw[j] - counts[j], reverse=True)[:rem]:
        counts[i] += 1
    out = []
    for i, k in enumerate(counts):
        if k <= 0:
            continue
        base = i * phase_len
        n_bursts = max(1, round(k ** 0.5))
        centers = [base + rng.uniform(0, phase_len) for _ in range(n_bursts)]
        spread = max(0.5, phase_len / (n_bursts * 6.0))  # tight clusters within a phase
        for _ in range(k):
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


def _benign_conn_state(rng: random.Random, fail_bias: float = 0.0) -> str:
    # ``fail_bias`` (from the activity envelope) raises the reset rate in congested phases, so
    # the SF fraction drifts across the capture — a top discriminator of real captures' first vs
    # second half. Service flows use RSTO/RSTR (established-then-reset — the L7 service is still
    # on the wire and Zeek names it); pure never-established S0/REJ stay in the _failed_flow path,
    # so this never orphans an L7 service claim. fail_bias=0 is the old behaviour.
    if fail_bias and rng.random() < 0.4 * fail_bias:
        return rng.choice(("RSTO", "RSTR"))
    return rng.choice(_SERVICE_CONN_STATES)


# Zeek names 13 conn_states; the renderer models five (established flows carry their L7 as
# SF/RSTO/RSTR, pure handshake failures are connectionless S0/REJ). This folds the full
# taxonomy onto that set so a reference's measured mix can be reproduced: half-open and
# reset-before-reply states (SH/RSTOS0/...) are failures, midstream/partial-close states
# (OTH/S1..S3) are normal establishments.
_CSTATE_FOLD = {
    "SF": "SF", "S1": "SF", "S2": "SF", "S3": "SF", "OTH": "SF",
    "RSTO": "RSTO", "RSTR": "RSTR",
    "S0": "S0", "RSTOS0": "S0", "SH": "S0", "SHR": "S0", "RSTRH": "S0",
    "REJ": "REJ",
}


@dataclass
class _ConnPlan:
    fail_frac: float                 # share of connections that never establish (S0/REJ)
    established: tuple               # (states, weights) among SF/RSTO/RSTR
    failed: tuple                    # (states, weights) among S0/REJ


def _conn_state_plan(conn_states: dict) -> _ConnPlan | None:
    """Fold a reference's Zeek conn_state histogram into a renderable establishment plan.

    Returns None if the reference carries no usable conn_state counts, so the caller keeps
    its built-in mix. Otherwise the analog reproduces the reference's SF/RSTO/RSTR split and
    its exact failure rate and S0:REJ ratio — retiring the cs_* C2ST tells.
    """
    folded: dict = {}
    for state, n in conn_states.items():
        tgt = _CSTATE_FOLD.get(state)
        if tgt and n > 0:
            folded[tgt] = folded.get(tgt, 0) + n
    total = sum(folded.values())
    if not total:
        return None
    est = {s: folded.get(s, 0) for s in ("SF", "RSTO", "RSTR") if folded.get(s)}
    fail = {s: folded.get(s, 0) for s in ("S0", "REJ") if folded.get(s)}
    if not est:                      # a reference with only failures still needs a base state
        est = {"SF": 1}
    return _ConnPlan(
        fail_frac=sum(fail.values()) / total,
        established=(list(est), list(est.values())),
        failed=(list(fail), list(fail.values())) if fail else (["S0"], [1]),
    )


def _resp_size(rng: random.Random, bulk: float = 1.0) -> int:
    """A heavy-tailed transfer size: mostly small ("mice"), a heavy tail of bulk
    transfers ("elephants"). Real captures are ~1/3 full-size (MTU) packets because a
    few large flows dominate the bytes; uniform small bodies never produce that mode.
    ``bulk`` (the per-phase activity-envelope bias) makes bulk transfers cluster in
    transfer-heavy phases, so flow sizes vary across the capture's timespan.
    """
    if rng.random() < min(0.5, 0.14 * bulk):             # elephant: a bulk transfer
        return min(700_000, int(rng.paretovariate(0.9) * 22_000 * bulk))
    return max(0, int(rng.lognormvariate(6.0, 1.3)))     # mouse: small/medium body


def _req_size(rng: random.Random, bulk: float = 1.0) -> int:
    """Client-side request volume: mostly small (request headers, cookies — a few hundred
    bytes), a thin tail of uploads (POSTs, form/file submits). Lighter than _resp_size. Real
    ambient has a non-trivial spread of originator bytes; a fixed ~0 makes orig_bytes a tell.
    ``bulk`` (the activity-envelope bias) makes uploads cluster in transfer-heavy phases.
    """
    if rng.random() < min(0.4, 0.06 * bulk):             # an upload
        return min(200_000, int(rng.paretovariate(1.1) * 8_000 * bulk))
    return max(64, int(rng.lognormvariate(6.2, 0.9)))    # ~500-byte median request


# Approximate originator L7 bytes a bare service flow already carries (handshake / request
# line + default headers), measured from the composer's own output. Reference-conditioning
# grows a flow *toward* a drawn target by adding this much less legitimate client content.
_ORIG_BASE = {"tls": 280, "http": 90}
_TOKEN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _size_originator(flow: Flow, target: int, rng: random.Random) -> None:
    """Grow a flow's originator byte volume toward `target` with legitimate protocol content.

    TLS gains client application-data (opaque, already record-fragmented); HTTP gains a
    realistic Cookie (browser GETs carry fat cookies) or, past what fits a header line, a
    request body. Both are counted by Zeek as orig_bytes and neither is filler the parser
    chokes on — so the analog's originator-volume marginal can match the reference's.
    """
    l7 = flow.l7
    if isinstance(l7, TlsL7):
        l7.app_data_orig_bytes = max(l7.app_data_orig_bytes, target - _ORIG_BASE["tls"])
    elif isinstance(l7, HttpL7):
        extra = target - _ORIG_BASE["http"]
        if extra <= 0:
            return
        if extra <= 2048:   # a fat cookie, well within Zeek's header-line bound — stays a GET
            cookie = "s=" + "".join(rng.choice(_TOKEN) for _ in range(extra - 2))
            l7.request_headers = {**l7.request_headers, "Cookie": cookie}
        else:               # a genuine upload; a body is unbounded and always parses clean
            l7.method = "POST"
            l7.request_body_len = extra


# Responder L7 bytes a bare flow already carries before its variable body: a TLS server's
# handshake (ServerHello + certificate chain) and an HTTP response's status line + headers.
_RESP_BASE = {"tls": 2600, "http": 160}


def _size_responder(flow: Flow, target: int, rng: random.Random) -> None:
    """Grow a flow's responder byte volume toward `target` via its variable body — TLS server
    application-data or the HTTP response body. Matches the reference's resp_bytes marginal so
    the orig:resp packet ratio (l_pkt_ratio) tracks it too."""
    l7 = flow.l7
    if isinstance(l7, TlsL7):
        l7.app_data_resp_bytes = max(0, target - _RESP_BASE["tls"])
    elif isinstance(l7, HttpL7):
        l7.response_body_len = max(0, target - _RESP_BASE["http"])


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
                  host_os: dict | None = None, bulk: float = 1.0,
                  direction: float = 0.5, fail_bias: float = 0.0) -> Flow | None:
    client = rng.choice(clients)
    cstate = _benign_conn_state(rng, fail_bias)  # SF fraction drifts with the envelope
    # ``direction`` (0..1) shifts the resp/orig byte balance across the capture: download-heavy
    # phases (dir->1) carry big responses + small requests; interactive/upload phases (dir->0)
    # the reverse. This makes l_byte_ratio/l_pkt_ratio drift — the strongest real within-source tell.
    resp_bulk = bulk * (0.4 + 1.2 * direction)
    orig_bulk = bulk * (0.4 + 1.2 * (1.0 - direction))
    # Internet-facing services (web, IRC) run on Linux, which enables TCP Timestamps;
    # internal AD/file services keep the environment's server OS. So a TS-capable client
    # negotiates timestamps only with the hosts that really would — matching real captures
    # where macOS/Linux egress carries timestamps but a Windows-desktop LAN largely doesn't.
    dst_os = "linux" if service in ("tls", "http", "irc") else env.default_server_os
    common = dict(flow_id=fid, src_ip=client, start_time=round(start, 6),
                  src_os=(host_os or {}).get(client, env.default_client_os),
                  dst_os=dst_os)

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
        # Modern web is overwhelmingly TLS 1.3 with ALPN h2; a minority of endpoints still
        # negotiate 1.2 (which also carries the server certificate in the clear). Two client
        # profiles keep JA3 a real discriminator across the capture.
        _prof = rng.choice(["generic_browser", "generic_browser", "curl"])
        _ver = rng.choices(["TLS1.3", "TLS1.2"], weights=[4, 1])[0]
        # A minority of requests carry an upload body (POST); most are small GETs. Both a
        # TLS client's app-data and an HTTP request body give the originator a realistic,
        # varied byte volume instead of a near-constant ~0 (an easy synthetic tell).
        _post = rng.random() < 0.18
        l7 = (TlsL7(server_name=name, client_profile=_prof, version=_ver,
                    alpn=["h2", "http/1.1"], app_data_orig_bytes=_req_size(rng, orig_bulk),
                    app_data_resp_bytes=_resp_size(rng, resp_bulk))
              if service == "tls" else
              HttpL7(host=name, method="POST" if _post else "GET",
                     uri=rng.choice(["/", "/api/v1/status", "/index.html"]),
                     request_body_len=_req_size(rng, orig_bulk) if _post else 0,
                     status=rng.choice([200, 200, 304, 404]), response_body_len=_resp_size(rng, resp_bulk)))
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
                 rng: random.Random, sport: int, host_os: dict,
                 conn_state: str | None = None) -> Flow | None:
    """A benign failed connection — dead host / closed port / scan (S0 or REJ)."""
    if len(clients) < 2:
        return None
    client = rng.choice(clients)
    cstate = conn_state or rng.choice(_FAILED_CONN_STATES)
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
    # A seeded non-stationary activity envelope makes flow density AND transfer volume vary
    # across the capture's timespan, so the first half is measurably distinct from the second
    # (the within-source heterogeneity real captures show and a stationary generator misses).
    envelope, activity = _activity_envelope(duration_s, rng)
    times = _bursty_times(noise_flows, start_time, duration_s, rng, activity)

    web_services = {"tls", "http"}
    flows: list = []
    for i in range(noise_flows):
        sport = 1025 + (i % 64000)  # unique per flow -> unique 5-tuple
        pos = (times[i] - start_time) / duration_s if duration_s else 0.0
        e = envelope(pos)
        # Service mix drifts with the envelope: web/bulk services up-weighted in transfer-heavy
        # phases, chatty services in quiet phases — so service one-hots, conn shapes, sizes AND
        # the resp/orig balance all shift together across the timespan (not just sizes).
        w = [wt * (1.0 + 1.6 * e["web"] if s in web_services else 1.0 + 1.2 * (1.0 - e["web"]))
             for s, wt in zip(services, weights)]
        service = _weighted_choice(rng, services, w)
        flow = _ambient_flow(env, service, clients, f"noise-{i:04d}-{service}", times[i],
                             rng, sport, host_os, bulk=e["bulk"], direction=e["dir"],
                             fail_bias=e["fail"])
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
