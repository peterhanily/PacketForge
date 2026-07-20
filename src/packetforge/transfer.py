# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Transfer proof — does the synthetic hold up against a real capture?

Profile a real pcap (what protocols/services/fingerprints independent tools see in it),
synthesize an analog with the same shape, then cross-validate both. If the same real
tools reach the same conclusions on the analog as on the original, the synthetic
"transfers": a detection tuned on one behaves the same on the other. This is the direct
answer to the skeptic's "sure, but does it work on real traffic?"
"""

from __future__ import annotations

import random
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from packetforge.compile.timeline import write_pcap
from packetforge.compose import (
    _CSTATE_FOLD,
    _FP_PER_HOUR,
    _ambient_flow,
    _benign_fp_flow,
    _conn_state_plan,
    _failed_flow,
    _host_os_map,
    _internal_hosts,
    _size_originator,
    _size_responder,
    _weighted_choice,
)
from packetforge.crossval import cross_validate
from packetforge.environments import Environment
from packetforge.models.flowspec import CaptureMeta, FlowSet

# tshark dissector name -> the ambient service our composer can render. tshark's
# content-based dissection is robust to non-standard ports (unlike port heuristics).
_PROTO_TO_AMBIENT = {
    "dns": "dns", "http": "http", "tls": "tls", "ssl": "tls", "ssh": "ssh", "ftp": "ftp",
    "smtp": "smtp", "smb": "smb", "smb2": "smb", "kerberos": "kerberos", "ldap": "ldap",
    "ntp": "ntp", "dhcp": "dhcp", "bootp": "dhcp", "snmp": "snmp", "irc": "irc",
    "pop": "pop3", "imap": "imap", "sip": "sip", "radius": "radius", "modbus": "modbus",
}


@dataclass
class Profile:
    services: dict = field(default_factory=dict)   # ambient-service -> flow count
    total_conns: int = 0
    duration: float = 0.0
    # Fingerprint marginals measured from the reference, for reference-conditioning: the
    # empirical SYN-window and TTL populations, and the conn_state histogram. Empty ->
    # the generator falls back to its OS-profile defaults and its own conn_state mix.
    syn_windows: list = field(default_factory=list)
    syn_ttls: list = field(default_factory=list)
    conn_states: dict = field(default_factory=dict)
    ia_means: list = field(default_factory=list)   # per-flow mean packet inter-arrival (s)
    orig_bytes: dict = field(default_factory=dict)  # ambient-service -> [per-flow orig L7 bytes]
    flow_vectors: list = field(default_factory=list)  # per-flow joint vectors (bytes/pkts/dur/cs)

    def render(self) -> str:
        svc = ", ".join(f"{k}:{v}" for k, v in sorted(self.services.items(), key=lambda kv: -kv[1]))
        return f"{self.total_conns} conns over {self.duration:.0f}s — services: {svc or 'none'}"


def profile_pcap(pcap: str | Path, workdir: str | None = None) -> Profile:
    """Extract a structural profile from a (real) capture via tshark dissection.

    Services are derived from tshark's protocol hierarchy (frame counts per protocol),
    which recognises protocols by content and so survives non-standard ports.
    """
    phs = subprocess.run(["tshark", "-r", str(pcap), "-q", "-z", "io,phs"],
                         capture_output=True, text=True, check=False).stdout
    frames: dict = {}
    total = 0
    for ln in phs.splitlines():
        if "frames:" not in ln:
            continue
        proto = ln.split()[0]
        try:
            n = int(ln.split("frames:")[1].split()[0])
        except (IndexError, ValueError):
            continue
        if proto == "frame":  # the (unindented) root line carries the total frame count
            total = n
        svc = _PROTO_TO_AMBIENT.get(proto)
        if svc:
            frames[svc] = frames.get(svc, 0) + n
    # a modest number of analog flows per detected service, proportional to frame share
    services = {svc: max(1, min(40, round(n / 4))) for svc, n in frames.items()}
    return Profile(services=services, total_conns=total, duration=0.0)


def synthesize_analog(profile: Profile, env: Environment, *, seed: int = 0,
                      start_time: float = 1_700_000_000.0,
                      fp_per_hour: float | None = None,
                      target_alerts: dict | None = None,
                      rules: dict | None = None) -> FlowSet:
    """Build a FlowSet reproducing the profile's service mix in the given environment.

    ``fp_per_hour`` sets the benign false-positive surface rate (dyndns/IP-lookup flows that
    trip ET INFO rules). None uses the default enterprise rate; pass the *reference's own*
    measured alert rate for a detection-matched analog — a clean reference that trips no rules
    then gets no fabricated FP surface (otherwise the analog over-alerts, JS -> 1.0)."""
    rng = random.Random(seed)
    clients = _internal_hosts(env, 12)
    host_os = _host_os_map(env, clients)
    duration = max(60.0, profile.duration)
    flows: list = []

    if profile.flow_vectors:
        # Joint cloning: one analog flow per reference flow, reproducing its bytes, packet
        # counts, duration and conn_state *together*. A flow's ia_mean is then consistent with
        # its packet count, so the joint feature distribution matches — not just each marginal,
        # which decorrelates ia_mean from pkts and balloons a few flows' durations.
        for idx, v in enumerate(profile.flow_vectors):
            start = start_time + rng.uniform(0, duration)
            cs = _CSTATE_FOLD.get(v["conn_state"], "SF")
            if cs in ("S0", "REJ"):
                f = _failed_flow(env, clients, f"analog-{idx:05d}", start, rng,
                                 60000 + (idx % 5000), host_os, conn_state=cs)
            elif v["service"]:
                f = _ambient_flow(env, v["service"], clients, f"analog-{idx:05d}-{v['service']}",
                                  start, rng, 1025 + (idx % 64000), host_os)
                if f is not None:
                    if f.transport == "tcp":
                        f.conn_state = cs
                    _size_originator(f, v["orig_bytes"], rng)
                    _size_responder(f, v["resp_bytes"], rng)
                    pk = v["orig_pkts"] + v["resp_pkts"]
                    if pk > 1 and v["duration"] > 0:    # per-flow ia_mean, consistent with pkts
                        f.rtt = min(2.0, max(0.002, v["duration"] / (pk - 1)))
                    # Effective segment size so the responder's packet count matches (real
                    # captures coalesce via offload); fixes over-segmentation -> l_orig_pkts,
                    # resp_bpp, and the ia_* dilution that too many small gaps caused.
                    if v["resp_bytes"] > 1460 and v["resp_pkts"] > 2:
                        f.seg_bytes = int(min(64000, max(1460,
                                          v["resp_bytes"] / (v["resp_pkts"] - 2))))
            else:
                f = None
            if f is not None:
                flows.append(f)
    else:
        # Marginal path — used when only a tshark protocol profile is available (no conn.log,
        # so no per-flow vectors). Reproduces the service mix and each marginal independently.
        i = 0
        for service, count in profile.services.items():
            for _ in range(count):
                start = start_time + rng.uniform(0, duration)
                flow = _ambient_flow(env, service, clients, f"analog-{i:04d}-{service}",
                                     start, rng, 1025 + (i % 64000), host_os)
                if flow is not None:
                    if profile.orig_bytes.get(service):
                        _size_originator(flow, rng.choice(profile.orig_bytes[service]), rng)
                    flows.append(flow)
                i += 1
        plan = _conn_state_plan(profile.conn_states)
        if plan:
            for f in flows:
                if f.transport == "tcp" and f.conn_state in ("SF", "RSTO", "RSTR"):
                    f.conn_state = _weighted_choice(rng, *plan.established)
            n_fail = min(round(len(flows) * plan.fail_frac / (1 - plan.fail_frac)), 4 * len(flows))
        else:
            n_fail = round(i * 0.15)
        for j in range(n_fail):
            csf = _weighted_choice(rng, *plan.failed) if plan else None
            ff = _failed_flow(env, clients, f"analog-fail-{j:04d}",
                              start_time + rng.uniform(0, duration), rng, 60000 + (j % 5000),
                              host_os, conn_state=csf)
            if ff is not None:
                flows.append(ff)
        if profile.ia_means:   # marginal timing (the cloning path sets rtt per-vector instead)
            for f in flows:
                if f.transport == "tcp":
                    f.rtt = max(0.002, rng.choice(profile.ia_means))

    # Benign false-positive surface (both paths): specific dyndns / noisy-TLD / IP-lookup flows
    # that trip ET INFO/DYN_DNS rules, giving the analog the benign alert surface real networks
    # have (the generic cloned flows carry no rule-tripping content of their own).
    if target_alerts and rules:
        # Signature-conditioned FP surface: reproduce the reference's *specific* alert
        # signatures (not just their rate) by inverting the rules it actually trips, so the
        # alert distributions share support and the JS divergence can fall toward 0.
        from packetforge.signatures import conditioned_fp_flows
        fp, _unmatched = conditioned_fp_flows(target_alerts, env, clients, start_time=start_time,
                                              duration=duration, rng=rng, rules=rules,
                                              id_prefix="analog-fp")
        flows.extend(fp)
    else:
        _fp_rate = _FP_PER_HOUR if fp_per_hour is None else fp_per_hour
        for k in range(round(_fp_rate * duration / 3600.0)):
            flows.append(_benign_fp_flow(env, clients, f"analog-fp-{k:04d}",
                         start_time + rng.uniform(0, duration), rng, 55000 + (k % 4000), host_os))
    # SYN window/TTL are per-SYN fingerprints; a marginal draw matches them well (both paths).
    if profile.syn_windows:
        for f in flows:
            if f.transport == "tcp":
                f.syn_window = rng.choice(profile.syn_windows)
                if profile.syn_ttls:
                    f.syn_ttl = rng.choice(profile.syn_ttls)
    flows.sort(key=lambda f: f.start_time)
    # Render with reference-matching timing so within-flow inter-arrivals get the bursty
    # spread (ia_std/ia_burst) a real reference shows instead of near-constant spacing. The
    # "conditioned" texture is retransmit-free, so packet counts — and thus validity — are
    # byte-exact.
    return FlowSet(capture=CaptureMeta(description="transfer analog", link_type=env.link_type,
                                       mac_oui=env.mac_oui, texture="conditioned"), flows=flows)


@dataclass
class TransferReport:
    profile: Profile
    real_protocols: set = field(default_factory=set)
    analog_protocols: set = field(default_factory=set)
    real_agree: bool = False
    analog_agree: bool = False

    @property
    def shared(self) -> set:
        return self.real_protocols & self.analog_protocols

    @property
    def transferred(self) -> float:
        if not self.real_protocols:
            return 0.0
        return round(100.0 * len(self.shared) / len(self.real_protocols), 1)

    def render(self) -> str:
        return "\n".join([
            "Transfer proof — real capture vs synthetic analog",
            f"  real profile: {self.profile.render()}",
            f"  real tools agree:   {self.real_agree}   protocols: {','.join(sorted(self.real_protocols)) or 'none'}",
            f"  analog tools agree: {self.analog_agree}   protocols: {','.join(sorted(self.analog_protocols)) or 'none'}",
            f"  shared protocols: {','.join(sorted(self.shared)) or 'none'}",
            f"  => {self.transferred}% of the real capture's protocols reproduced and "
            f"independently confirmed in the analog",
        ])


def _tshark_protocols(report) -> set:
    return set(report.tools.get("tshark", {}).get("detail", {}).get("protocols", []))


def transfer_proof(real_pcap: str | Path, env: Environment, *, seed: int = 0,
                   workdir: str | None = None) -> TransferReport:
    base = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="pf_xfer_"))
    base.mkdir(parents=True, exist_ok=True)
    profile = profile_pcap(real_pcap, workdir=str(base / "profile"))
    analog = synthesize_analog(profile, env, seed=seed)
    analog_pcap = base / "analog.pcap"
    write_pcap(analog, analog_pcap)

    real_xv = cross_validate(real_pcap, workdir=str(base / "xv_real"))
    analog_xv = cross_validate(analog_pcap, flowset=analog, workdir=str(base / "xv_analog"))
    return TransferReport(
        profile=profile,
        real_protocols=_tshark_protocols(real_xv),
        analog_protocols=_tshark_protocols(analog_xv),
        real_agree=real_xv.all_agree,
        analog_agree=analog_xv.all_agree,
    )
