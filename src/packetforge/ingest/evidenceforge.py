# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Convert EvidenceForge output into the Flow IR.

EvidenceForge emits Zeek logs as NDJSON (conn/dns/http/ssl, correlated by ``uid``)
but no pcap. This reads those logs and builds a FlowSet whose flows carry EF's own
5-tuples, timing, services, and L7 details. Compiling that FlowSet and running real
Zeek over the result checks that PacketForge reproduces EvidenceForge's network story
(see validation/ef_roundtrip.py).

This is the *log-reconstruction* path (Method A in DESIGN.md): it recovers the story
and the IOCs, but not exact payload volumetrics — the gap that motivates emitting the
IR from EvidenceForge's canonical event instead (Method C).

Sensitivity rule: if EvidenceForge's own ``service`` field is set, Zeek has a protocol
analyzer on that port, so opaque random bytes would be flagged malformed. Those flows
are rendered structure-only (TCP: handshake/teardown, no payload) or skipped (UDP)
until faithful protocol renderers exist. Only analyzer-free flows (``service="-"``)
get opaque payload, and those reproduce EF's exact byte counts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from packetforge.models.flowspec import (
    CaptureMeta, DnsL7, Flow, FlowSet, FtpL7, HttpL7, IcmpL7, LdapL7, NtpL7, OpaqueTcpL7,
    OpaqueUdpL7, SmbL7, SshL7, TlsL7,
)
from packetforge.renderers.tls import CIPHER_ID_BY_NAME

_SUPPORTED_CONN_STATES = {"SF", "S0", "REJ", "RSTO", "RSTR"}
_TLS_VERSION = {"TLSv12": "TLS1.2", "TLSv13": "TLS1.3"}  # 1.0/1.1 still downgrade to opaque
_SAFE_HTTP_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}


@dataclass
class IngestStats:
    total_conn: int = 0
    emitted: int = 0
    by_kind: dict = field(default_factory=dict)
    substituted_conn_state: int = 0
    tls_downgraded_to_opaque: int = 0  # non-TLS1.2 ssl we can't render yet
    structure_only: int = 0            # analyzer-port TCP rendered without payload
    skipped_analyzer_udp: int = 0      # analyzer-port UDP skipped (DHCP/NTP/krb/...)

    def bump(self, kind: str) -> None:
        self.by_kind[kind] = self.by_kind.get(kind, 0) + 1


def match_key(rec: dict) -> tuple:
    """Stable key for correlating an EF conn row with our Zeek conn row."""
    return (rec["id.orig_h"], int(rec["id.orig_p"]), rec["id.resp_h"],
            int(rec["id.resp_p"]), rec["proto"])


def _read_ndjson(path: Path) -> list:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _find_zeek_dir(root: Path) -> Path:
    if (root / "conn.json").exists():
        return root
    for p in root.rglob("conn.json"):
        return p.parent
    raise FileNotFoundError(f"no conn.json found under {root}")


def _map_conn_state(ef_state: str, is_l7: bool, orig_bytes: int, resp_bytes: int) -> tuple:
    if ef_state in _SUPPORTED_CONN_STATES:
        return ef_state, False
    if is_l7:
        return "SF", True
    return ("SF" if (orig_bytes and resp_bytes) else "S0"), True


@dataclass
class _Built:
    flow: Flow
    kind: str
    structure_only: bool = False


def _flow_from_conn(rec, dns_i, http_i, ssl_i, stats) -> "_Built | None":
    uid = rec.get("uid", "")
    proto = rec["proto"]
    svc = (rec.get("service") or "").strip()
    if svc == "-":  # Zeek/EF convention for "no service detected"
        svc = ""
    ob, rb = int(rec.get("orig_bytes") or 0), int(rec.get("resp_bytes") or 0)
    common = dict(
        flow_id=uid or f"{match_key(rec)}",
        transport=proto,
        src_ip=rec["id.orig_h"], dst_ip=rec["id.resp_h"],
        src_port=int(rec.get("id.orig_p") or 0), dst_port=int(rec.get("id.resp_p") or 0),
        start_time=float(rec["ts"]),
    )

    if proto == "icmp":
        stats.bump("icmp")
        return _Built(Flow(**{**common, "src_port": 0, "dst_port": 0},
                           l7=IcmpL7(count=max(1, int(rec.get("orig_pkts") or 1)))), "icmp")

    if proto == "udp":
        if svc == "dns" and uid in dns_i:
            d = dns_i[uid]
            stats.bump("dns")
            return _Built(Flow(**common, l7=DnsL7(
                qname=d.get("query", "") or ".", qtype=d.get("qtype_name", "A") or "A",
                answers=[a for a in d.get("answers", []) if isinstance(a, str)],
                rcode=d.get("rcode_name", "NOERROR") or "NOERROR")), "dns")
        if svc == "ntp":
            stats.bump("ntp")
            return _Built(Flow(**common, l7=NtpL7()), "ntp")
        if svc:  # other analyzer-backed UDP (krb/dhcp/...) — defer to real renderers
            stats.skipped_analyzer_udp += 1
            return None
        stats.bump("opaque_udp")
        return _Built(Flow(**common, l7=OpaqueUdpL7(service_hint=svc, orig_bytes=ob, resp_bytes=rb)),
                      "opaque_udp")

    # tcp
    cs, sub = _map_conn_state(rec.get("conn_state", "SF"), is_l7=True, orig_bytes=ob, resp_bytes=rb)
    if svc == "http" and uid in http_i and (http_i[uid].get("method") or "GET") in _SAFE_HTTP_METHODS:
        h = http_i[uid]
        stats.bump("http")
        if sub:
            stats.substituted_conn_state += 1
        return _Built(Flow(**common, conn_state=cs, l7=HttpL7(
            method=h.get("method", "GET") or "GET", uri=h.get("uri", "/") or "/",
            host=h.get("host", "") or "", user_agent=h.get("user_agent", "") or "",
            status=int(h.get("status_code") or 200),
            response_body_len=int(h.get("response_body_len") or 0),
            request_body_len=int(h.get("request_body_len") or 0))), "http")
    if svc == "ssl" and uid in ssl_i:
        s = ssl_i[uid]
        ver = _TLS_VERSION.get(s.get("version", ""))
        if ver is None:
            stats.tls_downgraded_to_opaque += 1  # e.g. TLSv13 — not renderable yet
        else:
            stats.bump("tls")
            if sub:
                stats.substituted_conn_state += 1
            return _Built(Flow(**common, conn_state=cs, l7=TlsL7(
                server_name=s.get("server_name", "") or "unknown.invalid", version=ver,
                server_cipher=CIPHER_ID_BY_NAME.get(s.get("cipher", "")),
                app_data_orig_bytes=0, app_data_resp_bytes=0)), "tls")

    if svc == "ssh":
        stats.bump("ssh")
        return _Built(Flow(**common, conn_state=cs,
                           l7=SshL7(payload_bytes=min(max(rb, 200), 6000))), "ssh")
    if svc == "ftp":
        stats.bump("ftp")
        return _Built(Flow(**common, conn_state=cs, l7=FtpL7()), "ftp")
    if svc == "ldap":
        stats.bump("ldap")
        return _Built(Flow(**common, conn_state=cs, l7=LdapL7()), "ldap")
    if svc == "smb":
        stats.bump("smb")
        return _Built(Flow(**common, conn_state=cs, l7=SmbL7()), "smb")

    # opaque TCP. If EF detected a service, an analyzer lives on this port, so render
    # structure-only to stay clean; otherwise carry EF's exact byte counts.
    structure_only = bool(svc)
    if structure_only:
        ob = rb = 0
        stats.structure_only += 1
    cs2, sub2 = _map_conn_state(rec.get("conn_state", "SF"), is_l7=False, orig_bytes=ob, resp_bytes=rb)
    stats.bump("opaque_tcp")
    if sub2:
        stats.substituted_conn_state += 1
    return _Built(Flow(**common, conn_state=cs2,
                       l7=OpaqueTcpL7(service_hint=svc, orig_bytes=ob, resp_bytes=rb)),
                  "opaque_tcp", structure_only=structure_only)


def flowset_from_evidenceforge(ef_root: str | Path, limit: int | None = None):
    """Return (FlowSet, originals, stats). ``originals`` maps a 5-tuple key to a dict
    of EF records plus the rendered ``kind``/``structure_only`` for that flow.

    Sampling is round-robin across (proto, service) so every traffic type is covered;
    what is sampled/deferred is reported in ``stats`` (no silent truncation).
    """
    zdir = _find_zeek_dir(Path(ef_root))
    conns = _read_ndjson(zdir / "conn.json")
    dns_i = {r["uid"]: r for r in _read_ndjson(zdir / "dns.json") if "uid" in r}
    http_i = {r["uid"]: r for r in _read_ndjson(zdir / "http.json") if "uid" in r}
    ssl_i = {r["uid"]: r for r in _read_ndjson(zdir / "ssl.json") if "uid" in r}

    groups: dict = {}
    for r in conns:
        groups.setdefault((r["proto"], r.get("service") or ""), []).append(r)
    for g in groups.values():
        g.sort(key=lambda r: float(r["ts"]))

    if limit is None:
        selected = list(conns)
    else:
        keys, selected, idx = sorted(groups), [], 0
        while len(selected) < limit and any(idx < len(groups[k]) for k in keys):
            for k in keys:
                if idx < len(groups[k]):
                    selected.append(groups[k][idx])
                    if len(selected) >= limit:
                        break
            idx += 1

    stats = IngestStats(total_conn=len(conns))
    flows, originals = [], {}
    for rec in selected:
        built = _flow_from_conn(rec, dns_i, http_i, ssl_i, stats)
        if built is None:
            continue
        flows.append(built.flow)
        uid = rec.get("uid", "")
        originals[match_key(rec)] = {
            "conn": rec, "dns": dns_i.get(uid), "http": http_i.get(uid), "ssl": ssl_i.get(uid),
            "kind": built.kind, "structure_only": built.structure_only,
        }
    stats.emitted = len(flows)
    fs = FlowSet(capture=CaptureMeta(description=f"ingested from {zdir}"), flows=flows)
    return fs, originals, stats
