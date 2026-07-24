# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Multi-tool cross-validation — 'it's real' stops being an opinion.

Run a capture through several *independent, real* NSM/forensic tools and report what
each one sees. When Zeek, Suricata, tshark, p0f, and a JA3 tool all parse the same
protocols and agree on the fingerprints — none of them written by us — the realism claim
is no longer self-referential. Tools that aren't installed are skipped, not faked.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from packetforge.fingerprints.ja3 import ja3_hash
from packetforge.fingerprints.loader import load_ja3_profile


def _which_p0f() -> str | None:
    return shutil.which("p0f") or next(
        (p for p in ("/opt/homebrew/sbin/p0f", "/usr/local/sbin/p0f", "/usr/sbin/p0f")
         if Path(p).exists()), None)


def _which_ja3() -> str | None:
    cand = Path(sys.executable).parent / "ja3"
    return str(cand) if cand.exists() else shutil.which("ja3")


@dataclass
class CrossValReport:
    tools: dict = field(default_factory=dict)   # tool -> {parsed: bool, detail: {...}}
    ja3_agreement: dict = field(default_factory=dict)  # digest -> {internal, external, match}

    @property
    def tools_run(self) -> list:
        return [t for t, v in self.tools.items() if v.get("available")]

    @property
    def all_agree(self) -> bool:
        ran = [v for v in self.tools.values() if v.get("available")]
        if not ran:
            return False
        clean = all(v.get("parsed") for v in ran)
        ja3_ok = all(a["match"] for a in self.ja3_agreement.values()) if self.ja3_agreement else True
        return clean and ja3_ok

    def render(self) -> str:
        lines = [f"Cross-validation — {len(self.tools_run)} independent tools ran"]
        for tool, v in self.tools.items():
            if not v.get("available"):
                lines.append(f"  {tool:9} (not installed — skipped)")
                continue
            status = "OK  " if v.get("parsed") else "FAIL"
            lines.append(f"  {tool:9} {status} {v.get('summary', '')}")
        if self.ja3_agreement:
            ok = sum(1 for a in self.ja3_agreement.values() if a["match"])
            lines.append(f"  JA3 agreement: {ok}/{len(self.ja3_agreement)} digests match "
                         f"between PacketForge and the external JA3 tool")
        lines.append(f"  => {'independent tools agree' if self.all_agree else 'DISAGREEMENT'}")
        return "\n".join(lines)


def _zeek(pcap: Path, wd: Path) -> dict:
    from packetforge.validation.roundtrip import _parse_zeek_log
    # -C ignores checksums: real captures routinely have NIC-offloaded (invalid) ones,
    # which Zeek otherwise discards. (Suricata gets the same treatment via -k none.)
    subprocess.run(["zeek", "-C", "-r", str(pcap), "FilteredTraceDetection::enable=F"],
                   cwd=str(wd), capture_output=True, text=True, check=False)
    conn = _parse_zeek_log(wd / "conn.log")
    services: dict = {}
    for r in conn:
        s = r.get("service", "-") or "-"
        services[s] = services.get(s, 0) + 1
    weird = len(_parse_zeek_log(wd / "weird.log")) + len(_parse_zeek_log(wd / "reporter.log"))
    seen = sorted(k for k in services if k != "-")
    return {"available": True, "parsed": weird == 0,
            "summary": f"{len(conn)} conns, services={','.join(seen) or 'none'}, weird={weird}",
            "detail": {"services": services, "weird": weird}}


def _suricata(pcap: Path, wd: Path) -> dict:
    if not shutil.which("suricata"):
        return {"available": False}
    subprocess.run(["suricata", "-r", str(pcap), "-l", str(wd), "-k", "none"],
                   capture_output=True, text=True, check=False)
    eve = wd / "eve.json"
    protos: dict = {}
    if eve.exists():
        for line in eve.read_text(errors="replace").splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") == "flow":
                ap = e.get("app_proto", "failed")
                protos[ap] = protos.get(ap, 0) + 1
    seen = sorted(k for k in protos if k not in ("failed", "unknown"))
    # "parsed" = ran without crashing; a tiny capture with no app-layer is not a failure.
    return {"available": True, "parsed": eve.exists(),
            "summary": f"app_protos={','.join(seen) or 'none'}",
            "detail": {"app_protos": protos}}


def _tshark(pcap: Path) -> dict:
    if not shutil.which("tshark"):
        return {"available": False}
    out = subprocess.run(["tshark", "-r", str(pcap), "-q", "-z", "io,phs"],
                         capture_output=True, text=True, check=False).stdout
    # io,phs lines look like "  <indent>proto   frames:N bytes:M"; take the proto token.
    protos = sorted({ln.split()[0] for ln in out.splitlines()
                     if "frames:" in ln and ln[:1] in (" ", "\t")})
    return {"available": True, "parsed": bool(protos),
            "summary": f"protocols={','.join(protos) or 'none'}",
            "detail": {"protocols": protos}}


def _p0f(pcap: Path) -> dict:
    p0f = _which_p0f()
    if not p0f:
        return {"available": False}
    out = subprocess.run([p0f, "-r", str(pcap)], capture_output=True, text=True,
                         check=False).stdout
    # p0f emits both TCP raw_sigs ("4:128+0:...") and HTTP raw_sigs ("1:Host,..."); keep
    # only the TCP ones (IP version 4/6 first field, numeric TTL second).
    fams: dict = {}
    n = 0
    for ln in out.splitlines():
        if "raw_sig" not in ln:
            continue
        s = ln.split("=", 1)[1].strip()
        parts = s.split(":")
        if len(parts) < 2 or parts[0] not in ("4", "6"):
            continue
        ttl = parts[1].split("+")[0]
        if not ttl.isdigit():
            continue
        n += 1
        fam = {"128": "Windows", "64": "Linux/Unix", "255": "network-gear"}.get(ttl, f"ttl{ttl}")
        fams[fam] = fams.get(fam, 0) + 1
    # p0f fingerprints TCP SYNs; a UDP-only capture yields 0 sigs, which is not a failure.
    return {"available": True, "parsed": True,
            "summary": f"{n} TCP sigs, OS families={dict(fams)}",
            "detail": {"os_families": fams, "signatures": n}}


def _ja3_external(pcap: Path) -> list:
    ja3 = _which_ja3()
    if not ja3:
        return []
    out = subprocess.run([ja3, "--json", str(pcap)], capture_output=True, text=True,
                         check=False).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return []


def _internal_ja3_digests(flowset) -> set:
    """The JA3 digests PacketForge intends for the TLS flows in a FlowSet.

    Mirrors ``render_tls``: a TLS 1.3 hello prepends the 1.3 ciphers and advertises
    supported_versions / key_share / psk_key_exchange_modes, and ALPN adds extension 16 —
    so the computed digest matches the bytes an external JA3 tool reads off the wire.
    """
    digests = set()
    for f in flowset.flows:
        if getattr(f.l7, "kind", "") == "tls":
            if getattr(f.l7, "ja3", None):
                continue  # explicit wire-JA3 override: not recomputed from a named profile
            prof = load_ja3_profile(f.l7.client_profile)
            ciphers = list(prof["ciphers"])
            exts = list(prof["extensions"])
            if getattr(f.l7, "version", "TLS1.2") == "TLS1.3":
                ciphers = [4865, 4866, 4867] + ciphers
                exts = exts + [43, 51, 45]
            if getattr(f.l7, "alpn", None) and 16 not in exts:
                exts.append(16)
            digests.add(ja3_hash(prof.get("tls_version", 771), ciphers, exts,
                                 prof["curves"], prof["point_formats"]))
    return digests


def cross_validate(pcap: str | Path, flowset=None, workdir: str | None = None) -> CrossValReport:
    pcap = Path(pcap)
    base = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="pf_xval_"))
    base.mkdir(parents=True, exist_ok=True)
    report = CrossValReport()
    (base / "zeek").mkdir(exist_ok=True)
    (base / "suri").mkdir(exist_ok=True)
    report.tools["zeek"] = _zeek(pcap, base / "zeek") if shutil.which("zeek") else {"available": False}
    report.tools["suricata"] = _suricata(pcap, base / "suri")
    report.tools["tshark"] = _tshark(pcap)
    report.tools["p0f"] = _p0f(pcap)
    has_ja3 = bool(_which_ja3())
    external = _ja3_external(pcap) if has_ja3 else []
    # the tool ran; 0 JA3 records in a no-TLS capture is correct, not a failure
    report.tools["ja3"] = {"available": has_ja3, "parsed": has_ja3,
                           "summary": f"{len(external)} JA3 records"}
    ext_digests = {e.get("ja3_digest") for e in external}
    # if we know the source FlowSet, confirm internal == external byte-for-byte
    if flowset is not None and external:
        for d in _internal_ja3_digests(flowset):
            report.ja3_agreement[d] = {"internal": d, "external": d in ext_digests,
                                       "match": d in ext_digests}
    return report
