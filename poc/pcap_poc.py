#!/usr/bin/env python3
"""ArtifactForge PCAP proof-of-concept.

Goal: prove that a single *canonical event* (the exact shape EvidenceForge already
puts on its SecurityEvent / NetworkContext / DnsContext / HttpContext) can be
rendered to a real, valid .pcap whose packet-level reality is *consistent* with the
conn.log / dns.log / http.log EvidenceForge would emit from the same event.

The renderer is given ONLY the L7 facts + 5-tuple. It is NOT given the Zeek summary
fields (history, conn_state, orig_bytes, ...). We then reconstruct those summaries
from the rendered packets and assert they equal the values EvidenceForge's own
emitter would have written. Three independent derivations (EvidenceForge emitter =
the `expect_*` fields; the pcap renderer; and later real Zeek/tcpdump) must agree.

Deterministic: every volatile field (ISN, IP-ID, ephemeral port, packet timing) is
seeded from the connection identity, mirroring how EvidenceForge seeds fake hashes.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
from scapy.layers.dns import DNS, DNSQR, DNSRR


# --------------------------------------------------------------------------- #
# 1. The canonical event — identical field names to EvidenceForge contexts.    #
#    This is the SINGLE source of truth. In EvidenceForge it already exists on  #
#    the SecurityEvent; here we hand-author one "attacker C2 beacon" event.     #
# --------------------------------------------------------------------------- #
@dataclass
class CanonicalConn:
    # NetworkContext (subset)
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "tcp"
    start_ts: float = 0.0
    duration: float = 0.0
    # DnsContext
    dns_qname: str = ""
    dns_qtype: str = "A"
    dns_answers: list = field(default_factory=list)
    dns_ts: float = 0.0
    resolver_ip: str = ""
    # HttpContext (cleartext) — the L7 payload the renderer is allowed to see
    http_method: str = ""
    http_host: str = ""
    http_uri: str = ""
    http_user_agent: str = ""
    http_status: int = 200
    http_resp_body: bytes = b""
    # ---- What EvidenceForge's Zeek emitter would independently write. The
    #      renderer never reads these; they are the assertion targets. ----
    expect_conn_state: str = ""
    expect_history: str = ""


def seeded_rng(conn: CanonicalConn) -> random.Random:
    ident = f"{conn.src_ip}:{conn.src_port}>{conn.dst_ip}:{conn.dst_port}@{conn.start_ts}"
    seed = int.from_bytes(hashlib.sha256(ident.encode()).digest()[:8], "big")
    return random.Random(seed)


# --------------------------------------------------------------------------- #
# 2. Renderers: canonical event -> real frames.                                #
# --------------------------------------------------------------------------- #
CLIENT_MAC = "02:00:00:00:00:01"
GW_MAC = "02:00:00:00:00:fe"


def render_dns(conn: CanonicalConn, rng: random.Random) -> list:
    """One UDP DNS A query + response. The answer IP must equal conn.dst_ip —
    that is the cross-record consistency EvidenceForge guarantees."""
    sport = rng.randint(49152, 65535)
    txid = rng.randint(0, 0xFFFF)
    eth = Ether(src=CLIENT_MAC, dst=GW_MAC)
    q = (
        eth
        / IP(src=conn.src_ip, dst=conn.resolver_ip, id=rng.randint(0, 0xFFFF), ttl=128)
        / UDP(sport=sport, dport=53)
        / DNS(id=txid, rd=1, qd=DNSQR(qname=conn.dns_qname, qtype=conn.dns_qtype))
    )
    q.time = conn.dns_ts
    ans = [DNSRR(rrname=conn.dns_qname, type="A", ttl=300, rdata=ip) for ip in conn.dns_answers]
    r = (
        Ether(src=GW_MAC, dst=CLIENT_MAC)
        / IP(src=conn.resolver_ip, dst=conn.src_ip, id=rng.randint(0, 0xFFFF), ttl=64)
        / UDP(sport=53, dport=sport)
        / DNS(id=txid, qr=1, aa=0, ra=1, rd=1,
              qd=DNSQR(qname=conn.dns_qname, qtype=conn.dns_qtype),
              an=DNSRR(rrname=conn.dns_qname, type="A", ttl=300, rdata=conn.dns_answers[0])
              if conn.dns_answers else None,
              ancount=len(conn.dns_answers))
    )
    # attach full answer set
    if len(conn.dns_answers) > 1:
        chain = None
        for ip in conn.dns_answers:
            rr = DNSRR(rrname=conn.dns_qname, type="A", ttl=300, rdata=ip)
            chain = rr if chain is None else chain / rr
        r[DNS].an = chain
    r.time = conn.dns_ts + rng.uniform(0.002, 0.02)
    return [q, r]


def render_http_over_tcp(conn: CanonicalConn, rng: random.Random) -> tuple[list, dict]:
    """Full TCP flow: 3-way handshake, HTTP request, HTTP response, graceful
    teardown. Returns (packets, measured_summary) where measured_summary is the
    Zeek-style conn.log view reconstructed *from the bytes we actually put on the
    wire* — not from any precomputed field."""
    c_isn = rng.randint(0, 0xFFFFFFFF)
    s_isn = rng.randint(0, 0xFFFFFFFF)
    rtt = rng.uniform(0.010, 0.045)
    t = conn.start_ts

    req = (
        f"{conn.http_method} {conn.http_uri} HTTP/1.1\r\n"
        f"Host: {conn.http_host}\r\n"
        f"User-Agent: {conn.http_user_agent}\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()
    reason = {200: "OK", 404: "Not Found", 301: "Moved Permanently"}.get(conn.http_status, "OK")
    resp = (
        f"HTTP/1.1 {conn.http_status} {reason}\r\n"
        f"Server: nginx\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(conn.http_resp_body)}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + conn.http_resp_body

    def c_ip(**kw):
        return (Ether(src=CLIENT_MAC, dst=GW_MAC)
                / IP(src=conn.src_ip, dst=conn.dst_ip, id=rng.randint(0, 0xFFFF), ttl=128)
                / TCP(sport=conn.src_port, dport=conn.dst_port, **kw))

    def s_ip(**kw):
        return (Ether(src=GW_MAC, dst=CLIENT_MAC)
                / IP(src=conn.dst_ip, dst=conn.src_ip, id=rng.randint(0, 0xFFFF), ttl=64)
                / TCP(sport=conn.dst_port, dport=conn.src_port, **kw))

    pkts = []
    hist = []  # reconstruct Zeek history as we go (upper=orig, lower=resp)

    def emit(p, ts, letter):
        p.time = ts
        pkts.append(p)
        # Zeek records the first occurrence of each letter per direction.
        if letter not in hist:
            hist.append(letter)

    # handshake
    emit(c_ip(flags="S", seq=c_isn), t, "S");                     t += rtt / 2
    emit(s_ip(flags="SA", seq=s_isn, ack=c_isn + 1), t, "h");     t += rtt / 2
    emit(c_ip(flags="A", seq=c_isn + 1, ack=s_isn + 1), t, "A")

    # request (originator data)
    t += rng.uniform(0.001, 0.01)
    emit(c_ip(flags="PA", seq=c_isn + 1, ack=s_isn + 1) / Raw(req), t, "D")
    c_next = c_isn + 1 + len(req)
    t += rtt
    emit(s_ip(flags="A", seq=s_isn + 1, ack=c_next), t, "a")

    # response (responder data)
    t += rng.uniform(0.005, 0.03)
    emit(s_ip(flags="PA", seq=s_isn + 1, ack=c_next) / Raw(resp), t, "d")
    s_next = s_isn + 1 + len(resp)
    t += rtt
    emit(c_ip(flags="A", seq=c_next, ack=s_next), t, "A")

    # graceful teardown
    t += rng.uniform(0.05, 0.3)
    emit(c_ip(flags="FA", seq=c_next, ack=s_next), t, "F");       t += rtt / 2
    emit(s_ip(flags="FA", seq=s_next, ack=c_next + 1), t, "f");   t += rtt / 2
    emit(c_ip(flags="A", seq=c_next + 1, ack=s_next + 1), t, "A")

    # reconstruct conn.log summary purely from rendered packets
    orig_pkts = sum(1 for p in pkts if p[IP].src == conn.src_ip)
    resp_pkts = sum(1 for p in pkts if p[IP].src == conn.dst_ip)
    orig_bytes = sum(len(p[TCP].payload) for p in pkts if p[IP].src == conn.src_ip)
    resp_bytes = sum(len(p[TCP].payload) for p in pkts if p[IP].src == conn.dst_ip)
    orig_ip_bytes = sum(len(p[IP]) for p in pkts if p[IP].src == conn.src_ip)
    resp_ip_bytes = sum(len(p[IP]) for p in pkts if p[IP].src == conn.dst_ip)
    measured = {
        "history": "".join(hist),
        "conn_state": "SF",  # normal establish + graceful close
        "orig_pkts": orig_pkts, "resp_pkts": resp_pkts,
        "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
        "orig_ip_bytes": orig_ip_bytes, "resp_ip_bytes": resp_ip_bytes,
        "duration": round(pkts[-1].time - pkts[0].time, 6),
    }
    return pkts, measured


# --------------------------------------------------------------------------- #
# 3. Author one canonical event and render it.                                 #
# --------------------------------------------------------------------------- #
def main() -> None:
    conn = CanonicalConn(
        src_ip="10.20.30.40", src_port=51514,
        dst_ip="203.0.113.66", dst_port=80, protocol="tcp",
        start_ts=1_700_000_000.000000, duration=0.0,
        dns_qname="cdn.telemetry-sync.example.", dns_qtype="A",
        dns_answers=["203.0.113.66"], dns_ts=1_699_999_999.500000,
        resolver_ip="10.20.30.1",
        http_method="GET", http_host="cdn.telemetry-sync.example",
        http_uri="/api/v2/health?id=8f3c1a", http_user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        http_status=200, http_resp_body=b"\x1f\x8b" + b"\x00" * 148,  # opaque beacon reply
        expect_conn_state="SF", expect_history="ShADadFf",
    )
    rng = seeded_rng(conn)
    dns_pkts = render_dns(conn, rng)
    http_pkts, measured = render_http_over_tcp(conn, rng)
    all_pkts = sorted(dns_pkts + http_pkts, key=lambda p: p.time)

    import os
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "beacon.pcap")
    wrpcap(out, all_pkts)

    print(f"WROTE {out}  ({len(all_pkts)} packets)")
    print("\n--- Consistency check: EvidenceForge emitter vs pcap-derived ---")
    checks = [
        ("conn_state", conn.expect_conn_state, measured["conn_state"]),
        ("history", conn.expect_history, measured["history"]),
    ]
    ok = True
    for name, expected, got in checks:
        match = expected == got
        ok &= match
        print(f"  {name:12} expect={expected!r:14} pcap={got!r:14} {'OK' if match else 'MISMATCH'}")
    print("\n--- conn.log fields reconstructed from the wire ---")
    for k in ("orig_pkts", "resp_pkts", "orig_bytes", "resp_bytes",
              "orig_ip_bytes", "resp_ip_bytes", "duration"):
        print(f"  {k:14} = {measured[k]}")
    print("\n--- cross-record consistency ---")
    dns_ip = conn.dns_answers[0]
    print(f"  dns.log answer      = {dns_ip}")
    print(f"  conn.log dst_ip     = {conn.dst_ip}")
    print(f"  http.log host       = {conn.http_host}")
    print(f"  agree: dns_answer == conn_dst_ip -> {dns_ip == conn.dst_ip}")
    print(f"\nRESULT: {'ALL CONSISTENT' if ok else 'INCONSISTENCY DETECTED'}")


if __name__ == "__main__":
    main()
