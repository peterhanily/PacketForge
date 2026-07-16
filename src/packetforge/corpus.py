# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Detection-CI corpus — a versioned, labeled capture set for rule regression testing.

A team points its detection ruleset at this corpus on every change and gets a
regression answer against a known key: the ground truth ships with the corpus, and
because generation is byte-deterministic, the corpus is content-addressable (each
capture carries its sha256). ``build`` emits the corpus + manifest; ``verify`` scores a
ruleset against it and, given a baseline scorecard, flags regressions (a technique that
used to be caught and now is missed, or a new false positive) with a non-zero exit.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path

from packetforge.compile.timeline import write_pcap
from packetforge.compose import compose_scenario
from packetforge.detect import run_detection, suricata_available
from packetforge.environments import load_environment
from packetforge.scenarios import build_attack, list_attacks, write_ground_truth

CORPUS_VERSION = "1.0"
# The corpus is a fixed, labeled matrix — pinned env/seed/volume so it is reproducible.
_SPECS = [
    {"env": "office", "attack": a, "seed": 1000 + i, "flows": 80, "texture": "realistic"}
    for i, a in enumerate(list_attacks())
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_corpus(out_dir: str | Path, *, start_time: float = 1_700_000_000.0) -> dict:
    """Generate the labeled corpus (captures + ground truth) and a manifest.json."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    for spec in _SPECS:
        env = load_environment(spec["env"])
        name = f"{spec['env']}-{spec['attack']}"
        intr = build_attack(spec["attack"], env, start_time + 100.0, random.Random(spec["seed"]))
        fs = compose_scenario(env, start_time=start_time, noise_flows=spec["flows"],
                              seed=spec["seed"], storyline=intr.flows, texture=spec["texture"])
        pcap = out / f"{name}.pcap"
        write_pcap(fs, pcap)
        gt_json = out / f"{name}.GROUND_TRUTH.json"
        write_ground_truth(intr, out / f"{name}.GROUND_TRUTH.md", gt_json)
        techniques = sorted({e.technique for e in intr.ground_truth})
        entries.append({
            "name": name, "pcap": pcap.name, "sha256": _sha256(pcap),
            "env": spec["env"], "attack": spec["attack"],
            "ground_truth": gt_json.name, "techniques": techniques,
            "flows": len(fs.flows), "malicious_flows": len(intr.flows),
        })
    manifest = {"corpus_version": CORPUS_VERSION, "captures": entries}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


@dataclass
class CorpusScore:
    name: str
    techniques_total: int
    techniques_caught: list
    techniques_missed: list
    false_positives: int


def verify_corpus(corpus_dir: str | Path, rules: str | Path) -> dict:
    """Run ``rules`` over every capture; return a scorecard (per-capture caught/missed/FP)."""
    if not suricata_available():
        raise RuntimeError("verify requires 'suricata' on PATH")
    corpus = Path(corpus_dir)
    manifest = json.loads((corpus / "manifest.json").read_text())
    scores = []
    for cap in manifest["captures"]:
        pcap = corpus / cap["pcap"]
        # integrity: the corpus is content-addressed, so a changed capture is a red flag
        if _sha256(pcap) != cap["sha256"]:
            raise RuntimeError(f"corpus integrity: {cap['pcap']} sha256 mismatch")
        rep = run_detection(pcap, rules, corpus / cap["ground_truth"])
        scores.append(CorpusScore(
            name=cap["name"], techniques_total=len(cap["techniques"]),
            techniques_caught=sorted(rep.techniques_caught), techniques_missed=rep.techniques_missed,
            false_positives=rep.false_positives).__dict__)
    caught = sum(len(s["techniques_caught"]) for s in scores)
    total = sum(s["techniques_total"] for s in scores)
    fp = sum(s["false_positives"] for s in scores)
    return {"corpus_version": manifest["corpus_version"], "rules": str(rules),
            "techniques_caught": caught, "techniques_total": total,
            "false_positives": fp, "scores": scores}


def diff_scorecards(baseline: dict, current: dict) -> dict:
    """Regressions: techniques caught in baseline but missed now, and new false positives."""
    base = {s["name"]: set(s["techniques_caught"]) for s in baseline["scores"]}
    base_fp = {s["name"]: s["false_positives"] for s in baseline["scores"]}
    regressions, new_fps, gains = [], [], []
    for s in current["scores"]:
        now = set(s["techniques_caught"])
        was = base.get(s["name"], set())
        for t in sorted(was - now):
            regressions.append({"capture": s["name"], "technique": t})
        for t in sorted(now - was):
            gains.append({"capture": s["name"], "technique": t})
        if s["false_positives"] > base_fp.get(s["name"], 0):
            new_fps.append({"capture": s["name"],
                            "was": base_fp.get(s["name"], 0), "now": s["false_positives"]})
    return {"regressions": regressions, "new_false_positives": new_fps, "gains": gains,
            "ok": not regressions and not new_fps}
