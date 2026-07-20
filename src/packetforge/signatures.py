# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Signature-conditioned rendering — invert open IDS rules into inert trigger flows.

A real network's benign false-positive surface is not a *rate*, it is a *distribution*
over specific signatures (this network trips ``ET CHAT Skype User-Agent``, that one trips
``ET POLICY curl User-Agent``). A synthetic capture that fires the right *volume* of
alerts on the *wrong* signatures still scores an alert-distribution divergence of ~1.0 —
disjoint support. This module closes that gap by **inverting the rules themselves**:
given a target ``signature -> count`` histogram (measured from a real reference with
:func:`packetforge.realism_detection._alert_histogram`), it renders inert flows that trip
*exactly those* signatures, in proportion.

Because Emerging Threats / Suricata rules are open, deterministic pattern-matchers, they
can be read and satisfied by construction — no ML, fully reproducible. The engine only
inverts **benign-prone** categories (POLICY / INFO / CHAT / FILE_SHARING / DNS / TLS and a
reputation-IP fallback); it refuses to synthesise a trigger for a MALWARE/CNC/EXPLOIT rule,
which would poison the ground truth. Every rendered flow carries the SID it is expected to
fire, so the FP surface stays labeled by construction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, Optional

from packetforge.environments import Environment
from packetforge.models.flowspec import DnsL7, Flow, HttpL7, OpaqueTcpL7, OpaqueUdpL7


class Content(NamedTuple):
    """One ``content`` match from a rule, with the modifiers we act on.

    ``pos`` is the anchor: ``any`` (substring), ``start`` (startswith), ``end``
    (endswith), or ``exact`` (both anchors on the same content). ``negated`` is a
    ``content:!"..."`` term — a value the trigger must *avoid*.
    """

    buffer: str
    data: bytes
    pos: str = "any"
    negated: bool = False

# Rule categories we will NEVER invert — synthesising these would fabricate an attack the
# ground truth doesn't contain. Matched against classtype and the msg prefix.
_FORBIDDEN_CLASSTYPES = {
    "trojan-activity", "command-and-control", "targeted-activity",
    "attempted-admin", "attempted-user", "shellcode-detect", "exploit-kit",
    "coin-mining", "credential-theft", "social-engineering",
}
_FORBIDDEN_MSG = re.compile(r"\bET (MALWARE|CNC|EXPLOIT|TROJAN|ATTACK_RESPONSE|WORM|MOBILE_MALWARE)\b", re.I)

# Sticky buffers we know how to satisfy; a content following one of these applies to it.
_HTTP_UA = {"http.user_agent", "http_user_agent"}
_HTTP_URI = {"http.uri", "http.uri.raw", "http_uri", "uricontent"}
_HTTP_HOST = {"http.host", "http_host"}
_DNS_QUERY = {"dns.query", "dns_query"}


def _decode_content(s: str) -> bytes:
    """Decode an ET/Suricata content string (ASCII with ``|hh hh|`` hex escapes) to bytes."""
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "|":
            j = s.find("|", i + 1)
            if j == -1:
                break
            try:  # a |..| block is hex bytes, space-separated or not
                out += bytes.fromhex(s[i + 1:j].replace(" ", ""))
            except ValueError:
                pass  # malformed hex block -> skip it (partial content still useful)
            i = j + 1
        else:
            out.append(ord(s[i]) & 0xFF)
            i += 1
    return bytes(out)


@dataclass
class RuleSpec:
    sid: int
    msg: str
    proto: str                       # http/tcp/udp/ip
    dst_port: str = "any"            # header dst port token
    src_port: str = "any"
    classtype: str = ""
    src_iplist: list = field(default_factory=list)   # for `alert ip [cidr,...] -> $HOME_NET`
    contents: list = field(default_factory=list)      # list of (buffer, bytes)

    @property
    def renderable(self) -> bool:
        return not (self.classtype in _FORBIDDEN_CLASSTYPES or _FORBIDDEN_MSG.search(self.msg))


_HEADER = re.compile(
    r"^\s*alert\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\(", re.I)
_OPT = re.compile(r'([a-z0-9_.]+)(?::\s*("(?:[^"\\]|\\.)*"|[^;]*))?;', re.I)


def _parse_rule(line: str) -> Optional[RuleSpec]:
    h = _HEADER.match(line)
    if not h:
        return None
    proto, src, sport, dst, dport = (g.lower() for g in h.groups())
    opts = line[line.index("(") + 1: line.rindex(")")]
    sid = msg = classtype = None
    contents: list = []
    buffer = "raw"
    for m in _OPT.finditer(opts):
        key = m.group(1).lower()
        val = (m.group(2) or "").strip()
        negated = val.startswith("!")
        if negated:
            val = val[1:].strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        if key == "sid":
            sid = int(val)
        elif key == "msg":
            msg = val
        elif key == "classtype":
            classtype = val
        elif key in _HTTP_UA:
            buffer = "http.user_agent"
        elif key in _HTTP_URI:
            buffer = "http.uri"
            if val:  # uricontent:"..." carries its content inline
                contents.append(Content("http.uri", _decode_content(val), negated=negated))
        elif key in _HTTP_HOST:
            buffer = "http.host"
        elif key in _DNS_QUERY:
            buffer = "dns.query"
        elif key == "content":
            contents.append(Content(buffer, _decode_content(val), negated=negated))
        elif key in ("endswith", "startswith") and contents:
            anchor = "end" if key == "endswith" else "start"
            prev = contents[-1].pos
            contents[-1] = contents[-1]._replace(
                pos="exact" if prev in ("start", "end") and prev != anchor else anchor)
    if sid is None or msg is None:
        return None
    src_iplist: list = []
    if proto == "ip" and src.startswith("[") and dst.upper() in ("$HOME_NET", "any"):
        src_iplist = [c for c in src.strip("[]").split(",") if c]
    return RuleSpec(sid=sid, msg=msg, proto=proto, dst_port=dport, src_port=sport,
                    classtype=classtype or "", src_iplist=src_iplist, contents=contents)


def parse_rules(paths) -> dict:
    """Parse ET/Suricata ``.rules`` files into ``{msg: RuleSpec}`` (first wins per msg)."""
    if isinstance(paths, (str, Path)):
        p = Path(paths)
        paths = sorted(p.glob("*.rules")) if p.is_dir() else [p]
    out: dict = {}
    for f in paths:
        for line in Path(f).read_text(errors="ignore").splitlines():
            if not line.lstrip().lower().startswith("alert "):
                continue
            r = _parse_rule(line)
            if r and r.msg not in out:
                out[r.msg] = r
    return out


def _first(contents, buffer):
    """Positive (non-negated) content bytes for a buffer, in rule order."""
    return [c.data for c in contents if c.buffer == buffer and not c.negated]


def _dns_qname(rule: RuleSpec) -> str:
    """A qname satisfying the rule's dns.query content anchors, avoiding negated terms."""
    pos = [c for c in rule.contents if c.buffer == "dns.query" and not c.negated]
    negated = {c.data.decode("latin-1").strip(".") for c in rule.contents
               if c.buffer == "dns.query" and c.negated}

    def txt(c):
        return c.data.decode("latin-1").strip(".")
    exact = [txt(c) for c in pos if c.pos == "exact"]
    if exact:
        name = exact[0]
    else:
        core = next((txt(c) for c in pos if c.pos in ("start", "any")), "shop7")
        suffix = next((txt(c) for c in pos if c.pos == "end"), "")
        if suffix:
            name = core if core.endswith(suffix) else f"{core}.{suffix}"
        else:
            name = core if "." in core else f"{core}.example"
    while name in negated or not name:
        name = "a" + name
    return name.rstrip(".") + "."


def invert(rule: RuleSpec, env: Environment, *, client: str, dst_ip: str, sport: int,
           start: float, flow_id: str) -> Optional[Flow]:
    """Render one inert flow expected to trip ``rule``, or ``None`` if unsupported/forbidden."""
    if not rule.renderable:
        return None
    common = dict(flow_id=flow_id, src_ip=client, start_time=round(start, 6),
                  src_os=env.default_client_os, dst_os=env.default_server_os,
                  expected_alert=[rule.sid])

    ua = _first(rule.contents, "http.user_agent")
    uri_parts = _first(rule.contents, "http.uri")
    host_parts = _first(rule.contents, "http.host")
    dns_parts = _first(rule.contents, "dns.query")
    raw = _first(rule.contents, "raw")

    # 1. HTTP User-Agent policy rules -> an HTTP request whose UA contains the content.
    if rule.proto == "http" and ua:
        agent = ua[0].decode("latin-1")
        return Flow(**common, transport="tcp", src_port=sport, dst_port=80, dst_ip=dst_ip,
                    conn_state="SF", l7=HttpL7(host="cdn.example.net", uri="/",
                                               user_agent=agent, status=200, response_body_len=64))
    # 2. HTTP URI content rules -> a GET whose path contains all the content fragments.
    if rule.proto == "http" and uri_parts:
        uri = "/" + "".join(p.decode("latin-1").lstrip("/") for p in uri_parts)
        host = host_parts[0].decode("latin-1") if host_parts else "app.example.net"
        return Flow(**common, transport="tcp", src_port=sport, dst_port=80, dst_ip=dst_ip,
                    conn_state="SF", l7=HttpL7(host=host, uri=uri, status=200, response_body_len=64))
    # 3. DNS query content rules -> a lookup whose qname satisfies the content anchors.
    if dns_parts:
        return Flow(**common, transport="udp", src_port=sport, dst_port=53,
                    dst_ip=env.dns_server, l7=DnsL7(qname=_dns_qname(rule), answers=[dst_ip]))
    # 4. Raw content on a fixed TCP/UDP port -> an opaque flow carrying the literal prefix.
    # Concatenate all raw contents in order: multi-content rules chain with distance:0
    # (contiguous), and placing them back-to-back satisfies depth+distance for that common
    # shape. Rules with non-zero distance/within are approximated (honest partial coverage).
    port = _port_int(rule.dst_port) or _port_int(rule.src_port)
    if raw and port:
        blob = b"".join(raw)
        lit = blob.hex()
        if rule.proto == "udp":
            sp = _port_int(rule.src_port) or sport
            bcast = _broadcast_for(client)
            return Flow(**common, transport="udp", src_port=sp, dst_port=port,
                        dst_ip=bcast, l7=OpaqueUdpL7(orig_bytes=max(len(blob), 40),
                                                     orig_literal_hex=lit))
        return Flow(**common, transport="tcp", src_port=sport, dst_port=port, dst_ip=dst_ip,
                    conn_state="SF", l7=OpaqueTcpL7(orig_bytes=max(len(blob), 24),
                                                    resp_bytes=48, orig_literal_hex=lit))
    # 5. Reputation IP-list rules -> an inbound touch from a listed source address.
    if rule.src_iplist:
        listed = _first_host(rule.src_iplist[0])
        return Flow(flow_id=flow_id, src_ip=listed, dst_ip=client, start_time=round(start, 6),
                    src_os=env.default_server_os, dst_os=env.default_client_os,
                    transport="tcp", src_port=40000 + (sport % 20000), dst_port=443,
                    conn_state="S0", expected_alert=[rule.sid],
                    l7=OpaqueTcpL7(orig_bytes=0, resp_bytes=0))
    return None


def _port_int(tok: str):
    try:
        return int(tok)
    except (ValueError, TypeError):
        return None


def _broadcast_for(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3] + ["255"]) if len(parts) == 4 else "255.255.255.255"


def _first_host(cidr: str) -> str:
    """A concrete host address inside a CIDR (network + 5), for a reputation touch."""
    net = cidr.split("/")[0].strip()
    o = net.split(".")
    if len(o) == 4:
        o[3] = str((int(o[3]) + 5) % 254 + 1)
        return ".".join(o)
    return net


def conditioned_fp_flows(target: dict, env: Environment, clients: list, *, start_time: float,
                         duration: float, rng, rules: dict, id_prefix: str = "fp",
                         max_flows: int = 400) -> tuple:
    """Render inert flows reproducing a reference ``{signature: count}`` alert histogram.

    Returns ``(flows, unmatched)`` where ``unmatched`` is the ``{signature: count}`` the
    engine could not invert (honest partial coverage — surfaced, never silently dropped).
    """
    flows: list = []
    unmatched: dict = {}
    i = 0
    # Deterministic order: by descending count then signature name.
    for msg, count in sorted(target.items(), key=lambda kv: (-kv[1], kv[0])):
        rule = rules.get(msg)
        made = 0
        for _ in range(count):
            if len(flows) >= max_flows:
                break
            client = clients[i % len(clients)]
            dst = _EXTERNAL[i % len(_EXTERNAL)]
            t = start_time + (rng.random() * duration if duration else 0.0)
            f = None
            if rule is not None:
                f = invert(rule, env, client=client, dst_ip=dst, sport=1025 + (i % 60000),
                           start=t, flow_id=f"{id_prefix}-{i:04d}")
            if f is not None:
                flows.append(f)
                made += 1
            i += 1
        if made < count:
            unmatched[msg] = count - made
    flows.sort(key=lambda f: f.start_time)
    return flows, unmatched


# A small pool of external destinations for the trigger flows (documentation ranges).
_EXTERNAL = ["203.0.113.10", "198.51.100.20", "203.0.113.55", "198.51.100.77"]
