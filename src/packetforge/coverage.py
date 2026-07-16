# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Detection lab v2 — coverage matrices and a false-positive benchmark.

Two numbers a detection engineer actually reports, produced against a real ruleset:

- **Coverage**: for each attack, which ATT&CK techniques a ruleset catches vs misses
  (a technique x attack matrix). Run it against your own rules AND against a large real
  ruleset (ET Open) to see the Pyramid-of-Pain reality — IOC feeds miss fictional-IOC
  synthetic attacks; behavioral/TTP rules are what synthetic captures actually exercise.
- **FP benchmark**: run a ruleset over a benign capture of known duration and report
  false positives extrapolated to *alerts per hour at a realistic base rate*.

Everything reuses the same Suricata runner and ground-truth mapping as ``detect``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path

from packetforge.compile.timeline import write_pcap
from packetforge.compose import compose_scenario
from packetforge.detect import DetectionReport, run_detection, suricata_available
from packetforge.environments import Environment
from packetforge.scenarios import build_attack, list_attacks, write_ground_truth


@dataclass
class AttackCoverage:
    attack: str
    caught: dict          # technique -> alert count
    missed: list          # techniques
    false_positives: int


@dataclass
class CoverageMatrix:
    ruleset: str
    env: str
    rows: list = field(default_factory=list)   # list[AttackCoverage]

    @property
    def technique_totals(self) -> tuple:
        caught = sum(len(r.caught) for r in self.rows)
        total = caught + sum(len(r.missed) for r in self.rows)
        return caught, total

    def render(self) -> str:
        caught, total = self.technique_totals
        fp = sum(r.false_positives for r in self.rows)
        lines = [
            f"ATT&CK coverage — ruleset={self.ruleset}  env={self.env}",
            f"  techniques caught: {caught}/{total}   false positives (benign): {fp}",
            "",
            f"  {'ATTACK':22} {'CAUGHT':>6} {'MISSED':>6}  TECHNIQUES",
        ]
        for r in self.rows:
            techs = ", ".join(sorted(t.split()[0] for t in r.caught)) or "-"
            miss = ", ".join(sorted(t.split()[0] for t in r.missed)) or "-"
            lines.append(f"  {r.attack:22} {len(r.caught):>6} {len(r.missed):>6}  "
                         f"caught[{techs}] missed[{miss}]")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        caught, total = self.technique_totals
        fp = sum(r.false_positives for r in self.rows)
        out = [f"# ATT&CK coverage — `{self.ruleset}` on `{self.env}`", "",
               f"- Techniques caught: **{caught}/{total}**",
               f"- False positives on benign traffic: **{fp}**", "",
               "| Attack | Caught | Missed | Techniques caught | Techniques missed |",
               "|---|--:|--:|---|---|"]
        for r in self.rows:
            c = ", ".join(sorted(t.split()[0] for t in r.caught)) or "—"
            m = ", ".join(sorted(t.split()[0] for t in r.missed)) or "—"
            out.append(f"| {r.attack} | {len(r.caught)} | {len(r.missed)} | {c} | {m} |")
        return "\n".join(out) + "\n"


def build_coverage_matrix(env: Environment, rules: str | Path, *, attacks=None,
                          noise_flows: int = 80, seed: int = 0,
                          start_time: float = 1_700_000_000.0,
                          workdir: str | Path | None = None) -> CoverageMatrix:
    """Run ``rules`` over every attack woven into benign noise; tabulate caught/missed."""
    if not suricata_available():
        raise RuntimeError("coverage requires 'suricata' on PATH")
    attacks = attacks or list_attacks()
    out = Path(workdir) if workdir else Path(__import__("tempfile").mkdtemp(prefix="pf_cov_"))
    out.mkdir(parents=True, exist_ok=True)
    matrix = CoverageMatrix(ruleset=str(rules), env=env.name)
    for name in attacks:
        intr = build_attack(name, env, start_time + 100.0, random.Random(seed))
        fs = compose_scenario(env, start_time=start_time, noise_flows=noise_flows,
                              seed=seed, storyline=intr.flows)
        pcap = out / f"{name}.pcap"
        write_pcap(fs, pcap)
        gt = out / f"{name}.json"
        write_ground_truth(intr, out / f"{name}.md", gt)
        rep: DetectionReport = run_detection(pcap, rules, gt)
        matrix.rows.append(AttackCoverage(name, rep.techniques_caught, rep.techniques_missed,
                                          rep.false_positives))
    return matrix


@dataclass
class FpBenchmark:
    ruleset: str
    env: str
    duration_s: float
    benign_flows: int
    false_positives: int
    signatures: dict = field(default_factory=dict)   # signature -> count

    @property
    def fp_per_hour(self) -> float:
        return round(3600.0 * self.false_positives / self.duration_s, 2) if self.duration_s else 0.0

    def render(self) -> str:
        lines = [
            f"FP benchmark — ruleset={self.ruleset}  env={self.env}",
            f"  benign capture: {self.benign_flows} flows over {self.duration_s/60:.0f} min",
            f"  false positives: {self.false_positives}  ->  {self.fp_per_hour} alerts/hour "
            f"at this base rate",
        ]
        for sig, n in sorted(self.signatures.items(), key=lambda kv: -kv[1])[:8]:
            lines.append(f"    {n:4} {sig[:80]}")
        if not self.signatures:
            lines.append("    (clean: no benign traffic tripped this ruleset)")
        return "\n".join(lines)


def fp_benchmark(env: Environment, rules: str | Path, *, duration_s: float = 3600.0,
                 volume: str = "normal", seed: int = 0, texture: str = "realistic",
                 start_time: float = 1_700_000_000.0,
                 workdir: str | Path | None = None) -> FpBenchmark:
    """Run ``rules`` over a benign capture; every alert is a false positive."""
    from packetforge.compose import flows_for_volume

    if not suricata_available():
        raise RuntimeError("fp-benchmark requires 'suricata' on PATH")
    out = Path(workdir) if workdir else Path(__import__("tempfile").mkdtemp(prefix="pf_fp_"))
    out.mkdir(parents=True, exist_ok=True)
    n = flows_for_volume(volume, duration_s)
    fs = compose_scenario(env, start_time=start_time, duration_s=duration_s,
                          noise_flows=n, seed=seed, texture=texture)
    pcap = out / "benign.pcap"
    write_pcap(fs, pcap)
    # a benign capture has no malicious flows -> every alert is a false positive
    gt = out / "benign.json"
    gt.write_text('{"title": "benign", "iocs": {}, "malicious_flows": []}\n')
    rep = run_detection(pcap, rules, gt)
    sigs: dict = {}
    for ex in rep.examples:
        sig = ex.split("[", 1)[-1].rstrip("]") if "[" in ex else ex
        sigs[sig] = sigs.get(sig, 0) + 1
    return FpBenchmark(ruleset=str(rules), env=env.name, duration_s=duration_s,
                       benign_flows=len(fs.flows), false_positives=rep.false_positives,
                       signatures=sigs)
