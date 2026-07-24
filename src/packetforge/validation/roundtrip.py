# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The round-trip validation gate.

Compile a FlowSet, run **real Zeek** and **tshark** over the resulting pcap, and
assert that:

1. Zeek produced no ``weird.log`` / ``reporter.log`` (a clean reassembly),
2. tshark's expert analysis reports zero Errors/Warnings/Malformed,
3. Zeek's ``conn/dns/http/ssl`` logs match, field-for-field, what each renderer said
   it emitted (and any author-declared ``expect`` block in the IR).

If all three hold, the synthetic packets are valid *and* the log layer Zeek derives
from them agrees with PacketForge's own view — which is the consistency guarantee,
tested rather than asserted.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from packetforge.compile.timeline import CompiledFlow, compile_flowset
from packetforge.models.flowspec import FlowSet
from scapy.utils import wrpcap

# Zeek conn.log fields we hold the packets accountable for (duration is excluded —
# Zeek derives it its own way; see docs/feasibility-evidence.md).
_CONN_FIELDS = ("service", "conn_state", "history", "orig_bytes", "resp_bytes",
                "orig_pkts", "resp_pkts")
_INT_CONN_FIELDS = {"orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"}


@dataclass
class Mismatch:
    flow_id: str
    log: str
    field: str
    expected: object
    actual: object

    def __str__(self) -> str:
        return f"[{self.flow_id}] {self.log}.{self.field}: expected {self.expected!r}, got {self.actual!r}"


@dataclass
class ValidationReport:
    ok: bool = False
    pcap: str = ""
    packet_count: int = 0
    total_flows: int = 0
    matched_flows: int = 0
    zeek_weird: int = 0
    zeek_reporter: int = 0
    tshark_errors: int = 0
    tshark_warnings: int = 0
    mismatches: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def summary(self) -> str:
        head = "PASS" if self.ok else "FAIL"
        lines = [
            f"{head}  ({self.packet_count} packets, {self.matched_flows}/{self.total_flows} flows matched)",
            f"  zeek weird={self.zeek_weird} reporter={self.zeek_reporter}  "
            f"tshark errors={self.tshark_errors} warnings={self.tshark_warnings}",
        ]
        for m in self.mismatches:
            lines.append(f"  MISMATCH {m}")
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)


def validators_available() -> bool:
    return bool(shutil.which("zeek") and shutil.which("tshark"))


# --------------------------------------------------------------------------- #
# Zeek TSV log parsing                                                          #
# --------------------------------------------------------------------------- #
def _parse_zeek_log(path: Path) -> list:
    """Parse a Zeek TSV log into a list of {field: value} dicts."""
    if not path.exists():
        return []
    fields: list = []
    rows: list = []
    sep = "\t"
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#separator"):
            token = line.split(" ", 1)[1].strip()
            sep = token.encode().decode("unicode_escape") if token.startswith("\\x") else token
        elif line.startswith("#fields"):
            fields = line.split(sep)[1:]
        elif line.startswith("#") or not line:
            continue
        else:
            values = line.split(sep)
            rows.append(dict(zip(fields, values)))
    return rows


def _clean(v: str) -> str:
    return "" if v == "-" else v


def _zeek_answers(v: str) -> set:
    v = _clean(v)
    return set(x for x in v.split(",") if x) if v else set()


# --------------------------------------------------------------------------- #
# External tool runners                                                         #
# --------------------------------------------------------------------------- #
def _run_zeek(pcap: Path, workdir: Path) -> None:
    # detect_filtered_trace=F silences Zeek's "looks pre-filtered" heuristic, which fires on
    # small synthetic traces and is not a packet defect. Read the pcap by absolute path: Zeek
    # runs with cwd=workdir (where its logs land), and the pcap may live outside workdir (the
    # evaluator) or be given via a relative dir (bundles) — an absolute path resolves in all cases.
    subprocess.run(
        ["zeek", "-r", str(pcap.resolve()), "detect_filtered_trace=F"],
        cwd=str(workdir), capture_output=True, text=True, check=False,
    )


# tshark's expert summary header is "Errors (N)" / "Warns (N)" — some builds print the
# long "Warnings". Match every spelling (the old regex only matched "Warnings", so on a
# tshark that emits "Warns" the warning count silently read as zero). Section headers are
# "Word (N)"; the per-message breakdown rows are "<freq> <group> <proto> <summary>".
_EXPERT_SECTION = re.compile(r"^([A-Za-z]+)\s*\((\d+)\)\s*$")
_EXPERT_ROW = re.compile(r"^\s*(\d+)\s+\S+\s+\S+\s+(.+?)\s*$")
# Warnings that any real capture also carries and that are not malformations, so they are
# excluded from the gate. It fails only on genuine problems (bad checksums, impossible
# sequences, dissector Malformed exceptions). Errors are never excluded.
#   - TCP RST: a realistic capture has a minority of reset connections.
#   - TCP window full: normal flow control — a bulk transfer fills the receiver's advertised
#     window before an ACK opens it; ubiquitous in real captures, not a malformation.
#   - Kerberos decrypt notices: tshark can't decrypt tickets without the keys — universal in
#     any Kerberos capture (real or synthetic), not a defect in the bytes on the wire.
_BENIGN_WARN_PATTERNS = (
    re.compile(r"^Connection reset \(RST\)$"),
    re.compile(r"^TCP window specified by the receiver is now completely full$"),
    re.compile(r"^Missing keytype \d+ usage "),
    re.compile(r"^Used keymap=\(null\)"),
)


def _benign_warn(summary: str) -> bool:
    return any(p.match(summary) for p in _BENIGN_WARN_PATTERNS)


def _run_tshark_expert(pcap: Path) -> tuple:
    """Count tshark expert Errors and non-benign Warnings, reading the message breakdown."""
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-q", "-z", "expert"],
        capture_output=True, text=True, check=False,
    ).stdout
    errors = warnings = 0
    section = None  # "errors" | "warnings" | None (Notes/Chats are informational)
    for line in out.splitlines():
        header = _EXPERT_SECTION.match(line)
        if header:
            name = header.group(1)
            section = ("errors" if name == "Errors"
                       else "warnings" if name in ("Warnings", "Warns")
                       else None)
            continue
        if section is None:
            continue
        row = _EXPERT_ROW.match(line)
        if not row:
            continue
        freq, summary = int(row.group(1)), row.group(2)
        if section == "errors":
            errors += freq
        elif not _benign_warn(summary):
            warnings += freq
    return errors, warnings


def gate_pcap(pcap) -> dict:
    """Run the zeek+tshark validation gate against a finished capture (no flowspec needed).

    Returns the counts the gate is built on; ``ok`` is True iff all are zero — Zeek produced
    no weird/reporter and tshark's expert flagged no errors or non-benign warnings. Used to
    enforce the contract on generated sample pcaps (the build sweep and the regression test).
    """
    import tempfile

    pcap = Path(pcap)
    with tempfile.TemporaryDirectory() as d:
        _run_zeek(pcap, Path(d))
        weird = len(_parse_zeek_log(Path(d) / "weird.log"))
        reporter = len(_parse_zeek_log(Path(d) / "reporter.log"))
    errors, warnings = _run_tshark_expert(pcap)
    return {
        "zeek_weird": weird, "zeek_reporter": reporter,
        "tshark_errors": errors, "tshark_warnings": warnings,
        "ok": weird == 0 and reporter == 0 and errors == 0 and warnings == 0,
    }


# --------------------------------------------------------------------------- #
# Matching + diffing                                                            #
# --------------------------------------------------------------------------- #
def _find_conn(conn_rows: list, key: dict) -> dict | None:
    for r in conn_rows:
        if (r.get("id.orig_h") == key["orig_h"]
                and r.get("id.resp_h") == key["resp_h"]
                and _clean(r.get("proto", "")) == key["proto"]
                and (key["proto"] == "icmp"
                     or (str(r.get("id.resp_p")) == str(key["resp_p"])
                         and str(r.get("id.orig_p")) == str(key["orig_p"])))):
            return r
    return None


def _diff_conn(cf: CompiledFlow, row: dict, expected: dict) -> list:
    out = []
    for f in _CONN_FIELDS:
        if f not in expected:
            continue
        exp = expected[f]
        act = _clean(row.get(f, ""))
        if f in _INT_CONN_FIELDS:
            act_cmp = int(act) if act else 0
            if int(exp) != act_cmp:
                out.append(Mismatch(cf.flow_id, "conn", f, int(exp), act_cmp))
        else:
            if str(exp) != act:
                out.append(Mismatch(cf.flow_id, "conn", f, exp, act))
    return out


def _diff_dns(cf: CompiledFlow, rows: list, expected: dict) -> list:
    # Match by connection (5-tuple), not by query — many flows share a qname.
    match = _l7_row_for(cf, rows)
    if match is None:
        return [Mismatch(cf.flow_id, "dns", "query", expected["query"], "<no dns.log row>")]
    out = []
    if _clean(match.get("qtype_name", "")) != expected["qtype_name"]:
        out.append(Mismatch(cf.flow_id, "dns", "qtype_name", expected["qtype_name"], match.get("qtype_name")))
    if _clean(match.get("rcode_name", "")) != expected["rcode_name"]:
        out.append(Mismatch(cf.flow_id, "dns", "rcode_name", expected["rcode_name"], match.get("rcode_name")))
    if _zeek_answers(match.get("answers", "")) != set(expected["answers"]):
        out.append(Mismatch(cf.flow_id, "dns", "answers", set(expected["answers"]), _zeek_answers(match.get("answers", ""))))
    return out


def _l7_row_for(cf: CompiledFlow, rows: list) -> dict | None:
    """Find the L7 row (http/ssl) for this flow by its connection 5-tuple.

    Matching on a content field (e.g. SNI) is ambiguous when several flows share it;
    the 5-tuple is unique per connection.
    """
    k = cf.key
    return next(
        (r for r in rows
         if r.get("id.orig_h") == k["orig_h"] and r.get("id.resp_h") == k["resp_h"]
         and str(r.get("id.resp_p")) == str(k["resp_p"])
         and str(r.get("id.orig_p")) == str(k["orig_p"])),
        None,
    )


def _diff_ssl(cf: CompiledFlow, rows: list, expected: dict) -> list:
    match = _l7_row_for(cf, rows)
    if match is None:
        return [Mismatch(cf.flow_id, "ssl", "server_name", expected["server_name"], "<no ssl.log row>")]
    out = []
    for f in ("version", "cipher", "server_name"):
        exp = expected[f]
        if not exp:  # unmapped/blank expectations are not asserted
            continue
        act = _clean(match.get(f, ""))
        if str(exp) != act:
            out.append(Mismatch(cf.flow_id, "ssl", f, exp, act))
    return out


def _diff_smtp(cf: CompiledFlow, rows: list, expected: dict) -> list:
    match = next((r for r in rows if _clean(r.get("mailfrom", "")) == expected["mailfrom"]), None)
    if match is None:
        return [Mismatch(cf.flow_id, "smtp", "mailfrom", expected["mailfrom"], "<no smtp.log row>")]
    out = []
    if _clean(match.get("subject", "")) != expected["subject"]:
        out.append(Mismatch(cf.flow_id, "smtp", "subject", expected["subject"], match.get("subject")))
    actual_rcpts = set(x for x in _clean(match.get("rcptto", "")).split(",") if x)
    if actual_rcpts != expected["rcptto"]:
        out.append(Mismatch(cf.flow_id, "smtp", "rcptto", expected["rcptto"], actual_rcpts))
    return out


def _diff_http(cf: CompiledFlow, rows: list, key: dict, expected: dict) -> list:
    match = _l7_row_for(cf, rows)
    if match is None:
        return [Mismatch(cf.flow_id, "http", "*", "an http.log row", "<none>")]
    checks = {
        "method": expected["method"], "host": expected["host"], "uri": expected["uri"],
        "user_agent": expected["user_agent"], "status_code": str(expected["status_code"]),
        "response_body_len": str(expected["response_body_len"]),
    }
    out = []
    for f, exp in checks.items():
        act = _clean(match.get(f, ""))
        if str(exp) != act:
            out.append(Mismatch(cf.flow_id, "http", f, exp, act))
    return out


# --------------------------------------------------------------------------- #
# Public entry point                                                           #
# --------------------------------------------------------------------------- #
def validate_flowset(fs: FlowSet, salt: str = "", keep_dir: str | None = None) -> ValidationReport:
    if not validators_available():
        raise RuntimeError("validation requires 'zeek' and 'tshark' on PATH")

    report = ValidationReport(total_flows=len(fs.flows))
    compiled = compile_flowset(fs, salt=salt)
    report.packet_count = len(compiled.packets)

    workdir = Path(keep_dir) if keep_dir else Path(tempfile.mkdtemp(prefix="pf_val_"))
    workdir.mkdir(parents=True, exist_ok=True)
    pcap = workdir / "capture.pcap"
    wrpcap(str(pcap), compiled.packets)
    report.pcap = str(pcap)

    _run_zeek(pcap, workdir)
    report.zeek_weird = len(_parse_zeek_log(workdir / "weird.log"))
    report.zeek_reporter = len(_parse_zeek_log(workdir / "reporter.log"))
    report.tshark_errors, report.tshark_warnings = _run_tshark_expert(pcap)

    conn_rows = _parse_zeek_log(workdir / "conn.log")
    dns_rows = _parse_zeek_log(workdir / "dns.log")
    http_rows = _parse_zeek_log(workdir / "http.log")
    ssl_rows = _parse_zeek_log(workdir / "ssl.log")
    smtp_rows = _parse_zeek_log(workdir / "smtp.log")
    _log_cache: dict = {}

    def rows_for(name: str) -> list:
        if name not in _log_cache:
            _log_cache[name] = _parse_zeek_log(workdir / f"{name}.log")
        return _log_cache[name]

    for cf in compiled.flows:
        exp = cf.expected
        if exp.get("skip_conn"):
            # e.g. DHCP: broadcast conns don't match the flow 5-tuple; verify via its log
            report.matched_flows += 1
        else:
            row = _find_conn(conn_rows, cf.key)
            if row is None:
                report.mismatches.append(Mismatch(cf.flow_id, "conn", "*", "a conn.log row", "<none>"))
                continue
            report.matched_flows += 1
            if "conn" in exp:
                report.mismatches.extend(_diff_conn(cf, row, exp["conn"]))
            if cf.ir_expect:
                report.mismatches.extend(_diff_conn(cf, row, cf.ir_expect))
            if cf.kind == "dns" and "dns" in exp:
                report.mismatches.extend(_diff_dns(cf, dns_rows, exp["dns"]))
            if cf.kind == "http" and "http" in exp:
                report.mismatches.extend(_diff_http(cf, http_rows, cf.key, exp["http"]))
            if cf.kind == "tls" and "ssl" in exp:
                report.mismatches.extend(_diff_ssl(cf, ssl_rows, exp["ssl"]))
            if cf.kind == "smtp" and "smtp" in exp:
                report.mismatches.extend(_diff_smtp(cf, smtp_rows, exp["smtp"]))
        # protocols verified by "this Zeek analyzer log must appear"
        produces = exp.get("produces")
        if produces and not rows_for(produces):
            report.mismatches.append(
                Mismatch(cf.flow_id, produces, "*", f"a {produces}.log row", "<none>"))

    report.ok = (
        report.zeek_weird == 0
        and report.zeek_reporter == 0
        and report.tshark_errors == 0
        and report.tshark_warnings == 0
        and report.matched_flows == report.total_flows
        and not report.mismatches
    )
    if not keep_dir:
        report.notes.append(f"zeek workdir: {workdir}")
    return report
