# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Real-data round-trip: does our pcap reproduce EvidenceForge's own Zeek logs?

Compile a FlowSet ingested from EvidenceForge, run real Zeek over the resulting pcap,
and compare our Zeek output — field by field — against EvidenceForge's ORIGINAL logs.
Reports agreement per field, honestly separating what reconstructs exactly (5-tuple,
service, conn_state, and the L7 IOC fields) from what a log-only reconstruction cannot
carry (exact payload volumetrics for L7 flows; opaque flows keep EF's byte counts).
"""

from __future__ import annotations

import ipaddress
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from scapy.utils import wrpcap

from packetforge.compile.timeline import compile_flowset
from packetforge.models.flowspec import FlowSet
from packetforge.validation.roundtrip import (
    _clean, _parse_zeek_log, _run_tshark_expert, _run_zeek, _zeek_answers,
    validators_available,
)


def _norm_ip(s: str) -> str:
    """Canonicalize an IP so text-form differences (IPv6 zero-compression) don't read
    as mismatches; non-IPs fall back to lowercase."""
    try:
        return ipaddress.ip_address(s).compressed
    except ValueError:
        return s.lower()


@dataclass
class Tally:
    matched: int = 0
    total: int = 0

    def add(self, ok: bool) -> None:
        self.total += 1
        self.matched += 1 if ok else 0

    def __str__(self) -> str:
        pct = (100.0 * self.matched / self.total) if self.total else 100.0
        return f"{self.matched}/{self.total} ({pct:.1f}%)"


@dataclass
class EfReport:
    flows_ingested: int = 0
    conn_matched: int = 0
    zeek_weird: int = 0
    zeek_reporter: int = 0
    tshark_errors: int = 0
    tshark_warnings: int = 0
    tallies: dict = field(default_factory=dict)
    stats: object = None
    examples: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def _t(self, name: str) -> Tally:
        return self.tallies.setdefault(name, Tally())

    def summary(self) -> str:
        lines = [
            f"EvidenceForge round-trip: {self.flows_ingested} flows ingested, "
            f"{self.conn_matched} matched to our Zeek conn.log",
            f"  our-pcap cleanliness: zeek weird={self.zeek_weird} reporter={self.zeek_reporter} "
            f"tshark errors={self.tshark_errors} warnings={self.tshark_warnings}",
        ]
        if self.stats is not None:
            lines.append(f"  rendered kinds: {dict(sorted(self.stats.by_kind.items()))}")
            if self.stats.tls_downgraded_to_opaque:
                lines.append(f"  note: {self.stats.tls_downgraded_to_opaque} non-TLS1.2 ssl "
                             f"rendered opaque (TLS 1.3 pending)")
            if self.stats.substituted_conn_state:
                lines.append(f"  note: {self.stats.substituted_conn_state} conn_states substituted "
                             f"(unsupported state mapped to nearest)")
            if self.stats.structure_only:
                lines.append(f"  note: {self.stats.structure_only} analyzer-port TCP rendered "
                             f"structure-only (faithful protocol renderers = next phase)")
            if self.stats.skipped_analyzer_udp:
                lines.append(f"  note: {self.stats.skipped_analyzer_udp} analyzer-port UDP skipped "
                             f"(DHCP/NTP/Kerberos/... = next phase)")
        lines.append("  field agreement (our Zeek vs EvidenceForge's originals):")
        for name in sorted(self.tallies):
            lines.append(f"    {name:28} {self.tallies[name]}")
        for note in self.notes:
            lines.append(f"  finding: {note}")
        for ex in self.examples[:6]:
            lines.append(f"  e.g. {ex}")
        return "\n".join(lines)


def _index_by_5tuple(rows: list) -> dict:
    idx: dict = {}
    for r in rows:
        key = (r.get("id.orig_h"), r.get("id.resp_h"), _clean(str(r.get("id.resp_p", ""))), r.get("proto"))
        idx.setdefault(key, []).append(r)
    return idx


def _index_l7(rows: list) -> dict:
    """Index dns/http/ssl rows by (orig_h, resp_h, resp_p) — these logs have no
    ``proto`` field, so proto must be left out of the key."""
    idx: dict = {}
    for r in rows:
        key = (r.get("id.orig_h"), r.get("id.resp_h"), _clean(str(r.get("id.resp_p", ""))))
        idx.setdefault(key, []).append(r)
    return idx


def _nearest(rows: list, ts: float) -> dict | None:
    if not rows:
        return None
    return min(rows, key=lambda r: abs(float(r.get("ts", 0.0)) - ts))


def compare_against_ef(fs: FlowSet, originals: dict, stats, keep_dir: str | None = None) -> EfReport:
    if not validators_available():
        raise RuntimeError("EF round-trip requires zeek + tshark on PATH")

    report = EfReport(flows_ingested=len(fs.flows), stats=stats)
    compiled = compile_flowset(fs)
    workdir = Path(keep_dir) if keep_dir else Path(tempfile.mkdtemp(prefix="pf_ef_"))
    workdir.mkdir(parents=True, exist_ok=True)
    pcap = workdir / "capture.pcap"
    wrpcap(str(pcap), compiled.packets)

    _run_zeek(pcap, workdir)
    report.zeek_weird = len(_parse_zeek_log(workdir / "weird.log"))
    report.zeek_reporter = len(_parse_zeek_log(workdir / "reporter.log"))
    report.tshark_errors, report.tshark_warnings = _run_tshark_expert(pcap)

    my_conn = _index_by_5tuple(_parse_zeek_log(workdir / "conn.log"))
    my_dns = _index_l7(_parse_zeek_log(workdir / "dns.log"))
    my_http = _index_l7(_parse_zeek_log(workdir / "http.log"))
    my_ssl = _index_l7(_parse_zeek_log(workdir / "ssl.log"))

    for key5, orig in originals.items():
        ef_conn = orig["conn"]
        ts = float(ef_conn["ts"])
        kind = orig["kind"]
        ckey = (key5[0], key5[2], str(key5[3]), key5[4])  # orig_h, resp_h, resp_p, proto
        dkey = (key5[0], key5[2], str(key5[3]))  # L7 logs have no proto field
        row = _nearest(my_conn.get(ckey, []), ts)
        if row is None:
            report.examples.append(f"no conn match for {key5}")
            continue
        report.conn_matched += 1

        report._t("conn.proto").add(_clean(row.get("proto", "")) == ef_conn.get("proto"))
        if kind == "icmp":
            # EF synthesizes conn_state 'SF' for ICMP; real Zeek marks ICMP 'OTH'.
            if _clean(row.get("conn_state", "")) != ef_conn.get("conn_state"):
                report._icmp_cs_diff = getattr(report, "_icmp_cs_diff", 0) + 1
        else:
            report._t("conn.conn_state").add(_clean(row.get("conn_state", "")) == ef_conn.get("conn_state"))
        if kind in ("dns", "http", "tls", "ssh", "ftp", "ntp"):
            report._t("conn.service").add(_clean(row.get("service", "")) == (ef_conn.get("service") or ""))

        # exact byte counts only where we rendered payload (analyzer-free opaque)
        if kind in ("opaque_tcp", "opaque_udp") and not orig["structure_only"]:
            report._t("opaque.orig_bytes").add(
                int(_clean(row.get("orig_bytes", "")) or 0) == int(ef_conn.get("orig_bytes") or 0))
            report._t("opaque.resp_bytes").add(
                int(_clean(row.get("resp_bytes", "")) or 0) == int(ef_conn.get("resp_bytes") or 0))

        if kind == "dns" and orig["dns"]:
            d, ed = _nearest(my_dns.get(dkey, []), ts), orig["dns"]
            if d is not None:
                report._t("dns.query").add(  # DNS names are case-insensitive (RFC 4343)
                    _clean(d.get("query", "")).lower() == (ed.get("query") or "").lower())
                report._t("dns.qtype").add(_clean(d.get("qtype_name", "")) == (ed.get("qtype_name") or ""))
                if (ed.get("qtype_name") in ("A", "AAAA")) and ed.get("answers"):
                    mine = {_norm_ip(a) for a in _zeek_answers(d.get("answers", ""))}
                    theirs = {_norm_ip(a) for a in ed.get("answers", [])}
                    report._t("dns.answers[A/AAAA]").add(mine == theirs)
        elif kind == "http" and orig["http"]:
            h, eh = _nearest(my_http.get(dkey, []), ts), orig["http"]
            if h is not None:
                for f in ("method", "host"):
                    report._t(f"http.{f}").add(_clean(h.get(f, "")) == (eh.get(f) or ""))
                # Zeek percent-decodes the URI; EF preserves the raw form — decode both
                report._t("http.uri").add(unquote(_clean(h.get("uri", ""))) == unquote(eh.get("uri") or ""))
                report._t("http.status_code").add(
                    _clean(h.get("status_code", "")) == str(eh.get("status_code", "")))
        elif kind == "tls" and orig["ssl"]:
            s, es = _nearest(my_ssl.get(dkey, []), ts), orig["ssl"]
            if s is not None:
                for f in ("version", "cipher", "server_name"):
                    report._t(f"ssl.{f}").add(_clean(s.get(f, "")) == (es.get(f) or ""))

    icmp_diff = getattr(report, "_icmp_cs_diff", 0)
    if icmp_diff:
        report.notes.append(
            f"{icmp_diff} ICMP flows: real Zeek marks conn_state 'OTH', but EvidenceForge "
            f"synthesizes 'SF' — the round-trip caught EF's synthetic value diverging from real Zeek")
    return report
