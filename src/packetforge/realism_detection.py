# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Detection-outcome realism — the metric that matters for a detection tool.

A classifier telling synthetic from real on byte histograms is interesting; what actually
matters is whether *a detection behaves the same on both*. This measures exactly that:
profile a real reference, synthesise a **mix- and volume-matched** analog, run the same
detection suite over both, and report how far the detection OUTCOMES diverge —
false-positive rate and the distribution of which signatures fire. If your rules trip at
the same rate, on the same signatures, on synthetic as on real, the synthetic is realistic
*for its purpose*, regardless of what a classifier thinks. This is far harder to game than
feature-space similarity: you can't match the detection surface without matching the
detection-relevant behaviour.

Scoped honestly: realism is measured *through this ruleset* — a behaviour no rule inspects
is not tested here (that is what the adversary panel, Gate 2, is for).
"""

from __future__ import annotations

import math
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from packetforge.compile.timeline import write_pcap
from packetforge.detect import _run_suricata, suricata_available
from packetforge.environments import Environment
from packetforge.validation.roundtrip import _parse_zeek_log

_ZEEK_TO_AMBIENT = {
    "dns": "dns", "http": "http", "ssl": "tls", "ssh": "ssh", "ftp": "ftp", "smtp": "smtp",
    "smb": "smb", "krb_tcp": "kerberos", "krb": "kerberos", "ldap": "ldap", "ntp": "ntp",
    "dhcp": "dhcp", "snmp": "snmp", "irc": "irc", "pop3": "pop3", "imap": "imap",
    "sip": "sip", "radius": "radius", "modbus": "modbus",
}


def _pcap_duration(pcap: Path) -> float:
    """Capture span in seconds (last - first frame), via tshark."""
    out = subprocess.run(["tshark", "-r", str(pcap), "-T", "fields", "-e", "frame.time_epoch"],
                         capture_output=True, text=True, check=False).stdout.split()
    ts = [float(x) for x in out if x]
    return (max(ts) - min(ts)) if len(ts) > 1 else 0.0


def _syn_fingerprints(pcap: Path) -> tuple:
    """The reference's originator-SYN window and TTL populations (for conditioning)."""
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
         "-T", "fields", "-e", "tcp.window_size_value", "-e", "ip.ttl"],
        capture_output=True, text=True, check=False).stdout
    windows, ttls = [], []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            windows.append(int(parts[0]))
            ttls.append(int(parts[1]))
    return windows, ttls


def profile_reference(real_pcap: Path, workdir: Path):
    """Real reference -> a Profile: service mix, duration, and fingerprint marginals."""
    from packetforge.transfer import Profile
    workdir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["zeek", "-C", "-r", str(real_pcap), "detect_filtered_trace=F"],
                   cwd=str(workdir), capture_output=True, text=True, check=False)
    conn = _parse_zeek_log(workdir / "conn.log")
    counts: dict = {}
    states: dict = {}
    ia_means: list = []
    orig_bytes: dict = {}
    for r in conn:
        svc = _ZEEK_TO_AMBIENT.get(r.get("service", "-"))
        if svc:
            counts[svc] = counts.get(svc, 0) + 1
            try:                       # the reference's per-service originator-volume marginal
                orig_bytes.setdefault(svc, []).append(int(r.get("orig_bytes", "0") or 0))
            except (ValueError, TypeError):
                pass
        cs = r.get("conn_state")
        if cs:
            states[cs] = states.get(cs, 0) + 1
        try:
            dur = float(r.get("duration", "0") or 0)
            pkts = int(r.get("orig_pkts", "0") or 0) + int(r.get("resp_pkts", "0") or 0)
            if dur > 0 and pkts > 1:
                ia_means.append(min(2.0, dur / (pkts - 1)))   # clamp idle-flow outliers
        except (ValueError, TypeError):
            pass
    windows, ttls = _syn_fingerprints(real_pcap)
    return Profile(services=counts, total_conns=sum(counts.values()),
                   duration=max(60.0, _pcap_duration(real_pcap)),
                   syn_windows=windows, syn_ttls=ttls, conn_states=states, ia_means=ia_means,
                   orig_bytes=orig_bytes)


def matched_synthetic(profile, env: Environment, *, seed: int = 0,
                      start_time: float = 1_700_000_000.0):
    """A synthetic capture matching the reference profile (mix, duration, fingerprints)."""
    from packetforge.transfer import synthesize_analog
    return synthesize_analog(profile, env, seed=seed, start_time=start_time)


def _alert_histogram(pcap: Path, rules: Path, workdir: Path) -> dict:
    """Signature -> alert count for a capture under a ruleset."""
    workdir.mkdir(parents=True, exist_ok=True)
    hist: dict = {}
    for a in _run_suricata(pcap, rules, workdir):
        sig = a.get("alert", {}).get("signature", "?")
        hist[sig] = hist.get(sig, 0) + 1
    return hist


def _js_divergence(p: dict, q: dict) -> float:
    """Jensen-Shannon distance between two signature histograms (0 = identical, 1 = disjoint)."""
    keys = set(p) | set(q)
    if not keys:
        return 0.0
    sp, sq = sum(p.values()) or 1, sum(q.values()) or 1
    if not sum(p.values()) or not sum(q.values()):
        return 1.0  # one side fired nothing the other did -> maximally divergent
    P = [p.get(k, 0) / sp for k in keys]
    Q = [q.get(k, 0) / sq for k in keys]
    M = [(a + b) / 2 for a, b in zip(P, Q)]

    def _kl(a, b):
        return sum(x * math.log2(x / y) for x, y in zip(a, b) if x > 0)
    return math.sqrt(max(0.0, 0.5 * _kl(P, M) + 0.5 * _kl(Q, M)))


@dataclass
class DetectionOutcomeReport:
    ruleset: str
    real_duration: float = 0.0
    synth_duration: float = 0.0
    real_alerts: int = 0
    synth_alerts: int = 0
    real_hist: dict = field(default_factory=dict)
    synth_hist: dict = field(default_factory=dict)
    service_counts: dict = field(default_factory=dict)

    @property
    def real_fp_per_hr(self) -> float:
        return round(3600.0 * self.real_alerts / self.real_duration, 2) if self.real_duration else 0.0

    @property
    def synth_fp_per_hr(self) -> float:
        return round(3600.0 * self.synth_alerts / self.synth_duration, 2) if self.synth_duration else 0.0

    @property
    def alert_js(self) -> float:
        return round(_js_divergence(self.real_hist, self.synth_hist), 3)

    @property
    def sig_coverage(self) -> float:
        """Fraction of the real capture's alerting signatures the synthetic also triggers."""
        if not self.real_hist:
            return 1.0
        return round(len(set(self.real_hist) & set(self.synth_hist)) / len(self.real_hist), 3)

    def render(self) -> str:
        lines = [
            f"Detection-outcome realism — ruleset={Path(self.ruleset).name}",
            f"  real   : {self.real_alerts} alerts over {self.real_duration/60:.1f} min  "
            f"->  {self.real_fp_per_hr}/hr",
            f"  synth  : {self.synth_alerts} alerts over {self.synth_duration/60:.1f} min  "
            f"->  {self.synth_fp_per_hr}/hr   (mix-matched: {dict(sorted(self.service_counts.items()))})",
            f"  alert-distribution divergence (JS): {self.alert_js}  (0 = identical mix of "
            f"signatures, 1 = disjoint)",
            f"  signature coverage: {self.sig_coverage}  (real signatures the synthetic also fires)",
        ]
        only_real = {k: self.real_hist[k] for k in set(self.real_hist) - set(self.synth_hist)}
        for sig, n in sorted(only_real.items(), key=lambda kv: -kv[1])[:6]:
            lines.append(f"    only-real  {n:4}x {sig[:74]}")
        only_synth = {k: self.synth_hist[k] for k in set(self.synth_hist) - set(self.real_hist)}
        for sig, n in sorted(only_synth.items(), key=lambda kv: -kv[1])[:4]:
            lines.append(f"    only-synth {n:4}x {sig[:74]}")
        return "\n".join(lines)


def detection_outcome(real_pcap: str | Path, env: Environment, rules: str | Path, *,
                      seed: int = 0, workdir: str | None = None) -> DetectionOutcomeReport:
    """Compare detection outcomes on a real reference vs a matched synthetic analog."""
    if not suricata_available():
        raise RuntimeError("detection-outcome realism requires 'suricata' on PATH")
    real_pcap, rules = Path(real_pcap), Path(rules)
    base = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="pf_rdet_"))
    base.mkdir(parents=True, exist_ok=True)

    prof = profile_reference(real_pcap, base / "ref_zeek")
    if not _parse_zeek_log(base / "ref_zeek" / "conn.log"):
        # Without this, a garbage reference yields empty alert histograms that compare
        # as JS=0.0 / coverage=1.0 — a vacuous "perfect match". Refuse it.
        raise ValueError(f"reference capture {real_pcap.name} has no parseable flows — "
                         f"is it a valid, non-empty pcap?")
    analog = matched_synthetic(prof, env, seed=seed)
    synth_pcap = base / "synth.pcap"
    write_pcap(analog, synth_pcap)

    rep = DetectionOutcomeReport(ruleset=str(rules), service_counts=prof.services,
                                 real_duration=prof.duration,
                                 synth_duration=_pcap_duration(synth_pcap))
    rep.real_hist = _alert_histogram(real_pcap, rules, base / "suri_real")
    rep.synth_hist = _alert_histogram(synth_pcap, rules, base / "suri_synth")
    rep.real_alerts = sum(rep.real_hist.values())
    rep.synth_alerts = sum(rep.synth_hist.values())
    return rep
