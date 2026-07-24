# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The validation trinity — fidelity, utility, non-leakage — mapped to synthetic packets.

The wider synthetic-data field judges synthetic data on three axes, never one:

- **Fidelity** — is it statistically like real? Here: protocol conformance (the Zeek/tshark
  round-trip) *plus* a C2ST against a real-vs-real floor (already measured by
  ``realism-audit`` / the scorecard). A hard constraint tabular vendors don't even have.
- **Utility** — does a model *trained on synthetic* work on real? The field's hardest-won
  lesson: statistical similarity is necessary but not sufficient — a capture that matches
  every marginal yet trains no useful model is a failure. Measured by **TSTR** (train on
  synthetic, test on real) on a flow→service classifier: if a model learned on our flows
  classifies *real* flows nearly as well as one trained on real, the features transfer.
- **Non-leakage** — is it *generated*, not replayed? For each synthetic flow, the distance to
  the closest real flow (**DCR**). A synthetic flow that is a near-copy of a real one is
  memorisation, not generation — the privacy leg. Judged against the real-vs-real internal
  DCR, so "as novel as two real flows are from each other" is the bar.

This module leads with utility, reports all three, and never collapses them to one scalar.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


def _zeek_rows(pcap: Path, workdir: Path):
    """(rows, services) of per-flow feature vectors from a capture, via Zeek + realism.py."""
    from packetforge.realism import flow_feature_rows
    workdir.mkdir(parents=True, exist_ok=True)
    pcap = Path(pcap).resolve()  # cwd changes for zeek; resolve first (past bug)
    subprocess.run(["zeek", "-C", "-r", str(pcap), "FilteredTraceDetection::enable=F"],
                   cwd=workdir, capture_output=True, check=False)
    rows, _names, services = flow_feature_rows(workdir, pcap)
    return rows, services


@dataclass
class TSTRReport:
    tstr_accuracy: float = 0.0        # trained on synthetic, tested on real
    trtr_accuracy: float = 0.0        # trained on real, tested on real (baseline)
    gap: float = 0.0                  # trtr - tstr (0 = fully transfers)
    classes: list = field(default_factory=list)
    n_synth: int = 0
    n_real: int = 0
    inconclusive: bool = False


def tstr(synth_pcap, real_pcap, workdir: Path) -> TSTRReport:
    """Train a flow→service classifier on synthetic, test on real (TSTR). The utility leg."""
    from collections import Counter

    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score

    s_rows, s_svc = _zeek_rows(synth_pcap, workdir / "tstr_s")
    r_rows, r_svc = _zeek_rows(real_pcap, workdir / "tstr_r")
    sc, rc = Counter(s_svc), Counter(r_svc)
    # Common label space: services present in both sides with enough support.
    common = sorted(s for s in set(s_svc) & set(r_svc)
                    if s != "-" and sc[s] >= 5 and rc[s] >= 5)
    if len(common) < 2:
        return TSTRReport(classes=common, n_synth=len(s_rows), n_real=len(r_rows),
                          inconclusive=True)

    def filt(rows, svc):
        keep = [(row, s) for row, s in zip(rows, svc) if s in common]
        return np.array([r for r, _ in keep], dtype=float), [s for _, s in keep]

    Xs, ys = filt(s_rows, s_svc)
    Xr, yr = filt(r_rows, r_svc)
    clf = RandomForestClassifier(n_estimators=120, max_depth=8, random_state=0)
    clf.fit(Xs, ys)
    tstr_acc = float(clf.score(Xr, yr))                    # train synth → test real
    cv = min(3, min(Counter(yr).values()))
    trtr = float(cross_val_score(RandomForestClassifier(n_estimators=120, max_depth=8,
                 random_state=0), Xr, yr, cv=max(2, cv)).mean()) if len(Xr) >= 10 else tstr_acc
    return TSTRReport(tstr_accuracy=round(tstr_acc, 3), trtr_accuracy=round(trtr, 3),
                      gap=round(trtr - tstr_acc, 3), classes=common,
                      n_synth=len(Xs), n_real=len(Xr))


@dataclass
class LeakageReport:
    dcr_median: float = 0.0           # median synth→nearest-real distance
    dcr_p05: float = 0.0              # 5th percentile (the closest matches)
    real_internal_median: float = 0.0  # real→nearest-other-real (the novelty floor)
    near_replay_frac: float = 0.0     # fraction of synth flows suspiciously close to a real one
    n_synth: int = 0
    n_real: int = 0
    inconclusive: bool = False

    @property
    def verdict(self) -> str:
        if self.inconclusive:
            return "INCONCLUSIVE"
        # Generation, not replay, when synth flows are ~as far from real as real flows are
        # from each other, and few are near-replays.
        return "generated" if (self.dcr_median >= 0.5 * self.real_internal_median
                               and self.near_replay_frac <= 0.02) else "replay-risk"


def nonleakage(synth_pcap, real_pcap, workdir: Path) -> LeakageReport:
    """Distance-to-closest-record of each synthetic flow vs the real reference. Non-leakage leg."""
    import numpy as np
    from sklearn.neighbors import NearestNeighbors
    from sklearn.preprocessing import StandardScaler

    s_rows, _ = _zeek_rows(synth_pcap, workdir / "dcr_s")
    r_rows, _ = _zeek_rows(real_pcap, workdir / "dcr_r")
    if len(s_rows) < 10 or len(r_rows) < 10:
        return LeakageReport(n_synth=len(s_rows), n_real=len(r_rows), inconclusive=True)
    scaler = StandardScaler().fit(np.array(r_rows, dtype=float))
    S = scaler.transform(np.array(s_rows, dtype=float))
    R = scaler.transform(np.array(r_rows, dtype=float))
    d_synth = NearestNeighbors(n_neighbors=1).fit(R).kneighbors(S)[0][:, 0]
    d_real = NearestNeighbors(n_neighbors=2).fit(R).kneighbors(R)[0][:, 1]  # skip self
    real_med = float(np.median(d_real))
    thresh = 0.5 * real_med
    return LeakageReport(
        dcr_median=round(float(np.median(d_synth)), 3),
        dcr_p05=round(float(np.percentile(d_synth, 5)), 3),
        real_internal_median=round(real_med, 3),
        near_replay_frac=round(float(np.mean(d_synth < thresh)), 3),
        n_synth=len(s_rows), n_real=len(r_rows))


@dataclass
class TrinityReport:
    fidelity_c2st: float = 0.0
    fidelity_conformant: bool = False
    utility: TSTRReport = field(default_factory=TSTRReport)
    nonleakage: LeakageReport = field(default_factory=LeakageReport)

    def render(self) -> str:
        u, n = self.utility, self.nonleakage
        lines = [
            "Validation trinity — fidelity · utility · non-leakage",
            f"  fidelity   : C2ST {self.fidelity_c2st:.3f} vs real  |  protocol-conformant "
            f"{self.fidelity_conformant}",
            f"  utility    : TSTR {u.tstr_accuracy:.3f}  (train-on-real baseline {u.trtr_accuracy:.3f}, "
            f"gap {u.gap:+.3f}) over {len(u.classes)} services"
            + ("  [INCONCLUSIVE]" if u.inconclusive else ""),
            f"  non-leakage: DCR median {n.dcr_median:.3f} vs real-internal {n.real_internal_median:.3f}"
            f"  near-replays {n.near_replay_frac:.1%}  -> {n.verdict}",
        ]
        return "\n".join(lines)


def validation_trinity(synth_pcap, real_pcap, *, workdir: str | None = None) -> TrinityReport:
    """Score a synthetic capture against a real reference on all three axes."""
    base = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="pf_trinity_"))
    base.mkdir(parents=True, exist_ok=True)
    from packetforge.realism import c2st_auc_between

    s_rows, _ = _zeek_rows(synth_pcap, base / "fid_s")
    r_rows, _ = _zeek_rows(real_pcap, base / "fid_r")
    c2st = c2st_auc_between(s_rows, r_rows)
    conformant = not (base / "fid_s" / "weird.log").exists()
    return TrinityReport(
        fidelity_c2st=round(c2st, 3), fidelity_conformant=conformant,
        utility=tstr(synth_pcap, real_pcap, base),
        nonleakage=nonleakage(synth_pcap, real_pcap, base))
