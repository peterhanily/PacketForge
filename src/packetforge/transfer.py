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
    _FP_PER_HOUR,
    _ambient_flow,
    _benign_fp_flow,
    _conn_state_plan,
    _failed_flow,
    _host_os_map,
    _internal_hosts,
    _size_originator,
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
                      start_time: float = 1_700_000_000.0) -> FlowSet:
    """Build a FlowSet reproducing the profile's service mix in the given environment."""
    rng = random.Random(seed)
    clients = _internal_hosts(env, 12)
    host_os = _host_os_map(env, clients)
    duration = max(60.0, profile.duration)
    flows = []
    i = 0
    for service, count in profile.services.items():
        for _ in range(count):
            start = start_time + rng.uniform(0, duration)
            flow = _ambient_flow(env, service, clients, f"analog-{i:04d}-{service}",
                                 start, rng, 1025 + (i % 64000), host_os)
            if flow is not None:
                # Reference-conditioning: size the originator payload to the reference's
                # per-service orig_bytes marginal — the dominant remaining C2ST tell.
                if profile.orig_bytes.get(service):
                    _size_originator(flow, rng.choice(profile.orig_bytes[service]), rng)
                flows.append(flow)
            i += 1
    # A realistic analog also fails a minority of connections and trips the benign
    # false-positive surface — the same texture compose_scenario adds, so the scorecard
    # measures the generator as it actually renders. When the reference's conn_state mix is
    # known, condition on it: reproduce its SF/RSTO/RSTR split among established flows and
    # its exact failure rate and S0:REJ ratio, retiring the cs_* C2ST tells.
    plan = _conn_state_plan(profile.conn_states)
    if plan:
        for f in flows:
            if f.transport == "tcp" and f.conn_state in ("SF", "RSTO", "RSTR"):
                f.conn_state = _weighted_choice(rng, *plan.established)
        # fail_frac is a share of *all* connections; convert to a count relative to the
        # established flows, capped so a degenerate reference can't explode the flow list.
        n_fail = min(round(len(flows) * plan.fail_frac / (1 - plan.fail_frac)), 4 * len(flows))
    else:
        n_fail = round(i * 0.15)
    for j in range(n_fail):
        cs = _weighted_choice(rng, *plan.failed) if plan else None
        ff = _failed_flow(env, clients, f"analog-fail-{j:04d}",
                          start_time + rng.uniform(0, duration), rng, 60000 + (j % 5000),
                          host_os, conn_state=cs)
        if ff is not None:
            flows.append(ff)
    for k in range(round(_FP_PER_HOUR * duration / 3600.0)):
        flows.append(_benign_fp_flow(env, clients, f"analog-fp-{k:04d}",
                     start_time + rng.uniform(0, duration), rng, 55000 + (k % 4000), host_os))
    # Reference-conditioning: draw each flow's SYN window/TTL from the reference's measured
    # populations, so the synthetic matches those fingerprint marginals (the dominant C2ST
    # tell) rather than the OS-profile defaults. Window/TTL are orthogonal to the labels.
    if profile.syn_windows:
        for f in flows:
            if f.transport == "tcp":
                f.syn_window = rng.choice(profile.syn_windows)
                if profile.syn_ttls:
                    f.syn_ttl = rng.choice(profile.syn_ttls)
                if profile.ia_means:   # match the reference's packet-timing spread
                    f.rtt = max(0.002, rng.choice(profile.ia_means))
    flows.sort(key=lambda f: f.start_time)
    return FlowSet(capture=CaptureMeta(description="transfer analog", link_type=env.link_type,
                                       mac_oui=env.mac_oui), flows=flows)


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
