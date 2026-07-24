# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Human blind panel — EvidenceForge's own realism bar, applied to packets.

EvidenceForge measures log realism with blind analyst panels. This does the same for
captures: render each flow as an analyst-readable "card" (the conn summary + its L7
detail), interleave real and synthetic flows into a shuffled quiz with a hidden key, and
score a human's guesses. Analyst accuracy ~0.5 means an experienced eye can't tell them
apart; high accuracy names *which* flows gave it away.

Decoupled on purpose: `generate` writes the quiz + a hidden answer key; a human fills in
guesses at their own pace; `score` reads them back. No live prompt, and reproducible.
"""

from __future__ import annotations

import json
import random
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from packetforge.validation.roundtrip import _parse_zeek_log


def _index(rows: list) -> dict:
    return {r.get("uid"): r for r in rows if r.get("uid")}


def _flow_cards(zeek_workdir: Path) -> dict:
    """uid -> a human-readable analyst card for each connection."""
    conn = _parse_zeek_log(zeek_workdir / "conn.log")
    http, dns, ssl = (_index(_parse_zeek_log(zeek_workdir / f"{n}.log"))
                      for n in ("http", "dns", "ssl"))
    cards: dict = {}
    for c in conn:
        uid = c.get("uid")
        svc = c.get("service", "-") or "-"
        line = (f"{c.get('proto')}/{svc}  dur={c.get('duration', '-')}s  "
                f"orig={c.get('orig_bytes', '-')}B/{c.get('orig_pkts', '-')}p  "
                f"resp={c.get('resp_bytes', '-')}B/{c.get('resp_pkts', '-')}p  "
                f"state={c.get('conn_state', '-')}  hist={c.get('history', '-')}")
        detail = ""
        if uid in http:
            h = http[uid]
            detail = (f"\n    HTTP {h.get('method')} {h.get('host', '')}{h.get('uri', '')}  "
                      f"UA=\"{h.get('user_agent', '')}\"  -> {h.get('status_code', '')} "
                      f"{h.get('resp_mime_types', '')} {h.get('response_body_len', '')}B")
        elif uid in ssl:
            s = ssl[uid]
            detail = (f"\n    TLS {s.get('version', '')} {s.get('cipher', '')}  "
                      f"SNI={s.get('server_name', '')}  ja3={s.get('ja3', '')}")
        elif uid in dns:
            d = dns[uid]
            detail = (f"\n    DNS {d.get('qtype_name', '')} {d.get('query', '')}  "
                      f"-> {d.get('answers', '')}")
        cards[uid] = line + detail
    return cards


def _run_zeek(pcap: Path, wd: Path):
    wd.mkdir(parents=True, exist_ok=True)
    subprocess.run(["zeek", "-C", "-r", str(pcap), "FilteredTraceDetection::enable=F"],
                   cwd=str(wd), capture_output=True, text=True, check=False)


def generate_quiz(real_pcap, synth_pcap, outdir, *, n: int = 12, seed: int = 0) -> Path:
    """Write a blind quiz (n real + n synthetic flow cards, shuffled) + a hidden key."""
    rng = random.Random(seed)
    base = Path(tempfile.mkdtemp(prefix="pf_panel_"))
    _run_zeek(Path(real_pcap), base / "real")
    _run_zeek(Path(synth_pcap), base / "synth")
    real = list(_flow_cards(base / "real").values())
    synth = list(_flow_cards(base / "synth").values())
    rng.shuffle(real)
    rng.shuffle(synth)
    items = [("real", c) for c in real[:n]] + [("synth", c) for c in synth[:n]]
    rng.shuffle(items)

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    lines = ["# Blind realism panel", "",
             "Each card below is one network flow — some real, some PacketForge-synthetic.",
             "For each, write `real` or `synth` in `guesses.txt` (one per line, `N: guess`).",
             "You cannot tell? That's the point. Guess anyway.", ""]
    key = {}
    for i, (label, card) in enumerate(items, 1):
        key[str(i)] = label
        lines.append(f"## {i}\n```\n{card}\n```\n")
    (outdir / "quiz.md").write_text("\n".join(lines), encoding="utf-8")
    (outdir / "answers.json").write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
    tmpl = "\n".join(f"{i}: " for i in range(1, len(items) + 1)) + "\n"
    (outdir / "guesses.txt").write_text(tmpl, encoding="utf-8")
    return outdir / "quiz.md"


@dataclass
class PanelResult:
    n: int
    correct: int
    real_as_synth: int
    synth_as_real: int

    @property
    def accuracy(self) -> float:
        return round(self.correct / self.n, 3) if self.n else 0.0

    def render(self) -> str:
        v = ("~chance: an analyst can't tell them apart" if self.accuracy < 0.6
             else "distinguishable: an analyst can spot the synthetic")
        return (f"Blind panel — {self.correct}/{self.n} correct  ->  accuracy {self.accuracy}\n"
                f"  {v}\n"
                f"  real mistaken for synthetic: {self.real_as_synth}   "
                f"synthetic mistaken for real: {self.synth_as_real}")


def score_quiz(answers_path, guesses_path) -> PanelResult:
    key = json.loads(Path(answers_path).read_text())
    correct = ras = sar = n = 0
    for line in Path(guesses_path).read_text().splitlines():
        if ":" not in line:
            continue
        idx, guess = line.split(":", 1)
        idx, guess = idx.strip(), guess.strip().lower()
        if idx not in key or guess not in ("real", "synth"):
            continue
        n += 1
        truth = key[idx]
        if guess == truth:
            correct += 1
        elif truth == "real":
            ras += 1
        else:
            sar += 1
    return PanelResult(n=n, correct=correct, real_as_synth=ras, synth_as_real=sar)
