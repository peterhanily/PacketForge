# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Detection-CI surface — deterministic PCAP fixtures for Detection-as-Code pipelines.

Detection engineering has converged on Detection-as-Code: rules as version-controlled
software, gated in CI. The load-bearing dependency that model can't cleanly satisfy is
*trustworthy, regenerable test data*. PacketForge is a unit-test fixture source for network
detections — a byte-identical capture + the exact Zeek logs it produces + a ground-truth
answer key, so a rule test is deterministic and can gate a merge.

Two entry points:

- ``packetforge_fixture(attack)`` — render an attack fixture for use inside a team's own
  pytest: assert a rule *fires* on the attack capture and stays *quiet* on the benign one.
- ``write_suricata_verify(fixture, out_dir, rules)`` — export the fixture as a standard
  ``suricata-verify`` test directory (``test.pcap`` + ``test.yaml``), so a PacketForge
  capture drops straight into a Suricata rule-regression suite.
"""

from __future__ import annotations

import random
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Fixture:
    """A rendered, deterministic detection fixture (one attack + its benign-only twin)."""

    attack: str
    env: str
    seed: int
    pcap: Path
    ground_truth: Path
    _benign_pcap: Path
    zeek_dir: Path = None
    expected_sids: dict = field(default_factory=dict)   # SID -> count (frozen golden, if rules given)

    def suricata_alerts(self, rules) -> dict:
        """Signature-id -> count when ``rules`` run over the attack capture."""
        return _sid_histogram(self.pcap, Path(rules))

    def benign_alerts(self, rules) -> dict:
        """Signature-id -> count on the benign-only twin (the false-positive check)."""
        return _sid_histogram(self._benign_pcap, Path(rules))

    def fires(self, rules, sid: int | None = None) -> bool:
        """Does ``rules`` fire on the attack capture (optionally a specific SID)?"""
        h = self.suricata_alerts(rules)
        return (sid in h) if sid is not None else bool(h)

    def quiet_on_benign(self, rules, sid: int | None = None) -> bool:
        """Does ``rules`` stay silent on the benign twin (no false positive)?"""
        h = self.benign_alerts(rules)
        return (sid not in h) if sid is not None else not h


def _sid_histogram(pcap: Path, rules: Path) -> dict:
    from packetforge.detect import _run_suricata
    wd = Path(tempfile.mkdtemp(prefix="pf_dci_"))
    hist: dict = {}
    for a in _run_suricata(Path(pcap).resolve(), rules, wd):
        sid = a.get("alert", {}).get("signature_id")
        if sid is not None:
            hist[sid] = hist.get(sid, 0) + 1
    return hist


def _render(attack: str | None, env_name: str, seed: int, flows: int, out: Path):
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment
    env = load_environment(env_name)
    intrusion, storyline = None, None
    if attack:
        from packetforge.scenarios import build_attack
        intrusion = build_attack(attack, env, 1_700_000_100.0, random.Random(seed))
        storyline = intrusion.flows
    fs = compose_scenario(env, start_time=1_700_000_000.0, noise_flows=flows, seed=seed,
                          storyline=storyline)
    from packetforge.bundle import write_bundle
    write_bundle(fs, out, intrusion=intrusion)
    return intrusion


def packetforge_fixture(attack: str, *, env: str = "office", seed: int = 0, flows: int = 80,
                        rules=None, out_dir=None) -> Fixture:
    """Render a deterministic fixture for ``attack`` (+ a benign-only twin) for detection CI.

    If ``rules`` is given, the fixture also freezes the SID histogram those rules produce on
    the attack capture as ``expected_sids`` — a golden set for regression (export it with
    :func:`write_suricata_verify`).
    """
    base = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="pf_fixture_"))
    atk_dir, ben_dir = base / attack, base / f"{attack}-benign"
    _render(attack, env, seed, flows, atk_dir)
    _render(None, env, seed, flows, ben_dir)   # same env/seed, no attack -> the benign twin
    fx = Fixture(attack=attack, env=env, seed=seed, pcap=atk_dir / "capture.pcap",
                 ground_truth=atk_dir / "GROUND_TRUTH.json", _benign_pcap=ben_dir / "capture.pcap",
                 zeek_dir=atk_dir)
    if rules is not None:
        fx.expected_sids = fx.suricata_alerts(rules)
    return fx


def write_suricata_verify(fixture: Fixture, out_dir, rules) -> Path:
    """Export ``fixture`` as a ``suricata-verify`` test: ``test.pcap`` + ``test.yaml``.

    The expected checks are the golden SID histogram ``rules`` produce on the capture now —
    so the test asserts those signatures keep firing (a rule-regression guard).
    """
    import shutil
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy(fixture.pcap, out / "test.pcap")
    hist = fixture.expected_sids or fixture.suricata_alerts(rules)
    checks = "\n".join(
        f"- filter:\n    count: {n}\n    match:\n      alert.signature_id: {sid}"
        for sid, n in sorted(hist.items()))
    (out / "test.yaml").write_text(
        "# Generated by PacketForge — deterministic detection fixture.\n"
        f"# attack={fixture.attack} env={fixture.env} seed={fixture.seed}\n"
        "requires:\n  min-version: 6.0.0\n\n"
        "args:\n- -k none\n\n"
        "checks:\n" + (checks + "\n" if checks else "[]\n"))
    return out
