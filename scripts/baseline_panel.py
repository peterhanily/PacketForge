#!/usr/bin/env python3
"""Baseline PacketForge synthetic captures against a PANEL of real pcaps.

A single real-vs-synth AUC is uninterpretable: even two *real* captures score high
(different network, time, mix). The honest question is whether synth-vs-real is worse
than the real-vs-real FLOOR. This computes the full pairwise C2ST AUC matrix over a set
of captures, then reports:

  * real-vs-real floor  — the AUC distribution among distinct real captures (the bar a
                          generator of novel traffic can realistically reach)
  * synth-vs-real       — each synthetic against each real, and vs that floor
  * within-source       — first-half vs second-half of each capture (a per-capture sanity floor)

Usage (labels are basenames):
    .venv/bin/python baseline_panel.py --real a.pcap b.pcap c.pcap --synth office.pcap home.pcap

Only aggregate AUCs are printed; pcaps are read locally and never transmitted. Captures
with < 20 flows are skipped (too few to train the adversary).
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")
from packetforge.realism import (  # noqa: E402
    c2st_auc_between, flow_feature_rows, temporal_split_auc,
)

_MIN = 20


def _rows(pcap):
    wd = Path(tempfile.mkdtemp(prefix="pf_panel_"))
    subprocess.run(["zeek", "-C", "-r", str(Path(pcap).resolve()), "detect_filtered_trace=F"],
                   cwd=str(wd), capture_output=True, text=True, check=False)
    rows, _, _ = flow_feature_rows(wd, pcap)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--real", nargs="+", required=True, help="real reference pcaps")
    ap.add_argument("--synth", nargs="+", required=True, help="synthetic pcaps to score")
    args = ap.parse_args()

    caps = []  # (label, kind, rows)
    for kind, paths in (("real", args.real), ("synth", args.synth)):
        for p in paths:
            if not Path(p).is_file():
                print(f"ERROR: missing {p}", file=sys.stderr)
                return 2
            r = _rows(p)
            tag = f"{Path(p).name}"
            if len(r) < _MIN:
                print(f"  skip {tag}: only {len(r)} flows (< {_MIN})")
                continue
            caps.append((tag, kind, r))

    if sum(1 for _, k, _ in caps if k == "real") < 1 or sum(1 for _, k, _ in caps if k == "synth") < 1:
        print("ERROR: need at least one real and one synthetic capture with >= 20 flows", file=sys.stderr)
        return 2

    labels = [c[0] for c in caps]
    w = max(len(x) for x in labels)

    # --- pairwise AUC matrix -------------------------------------------------
    print("\nPairwise C2ST AUC (0.5 = same distribution, 1.0 = trivially separable):")
    print(" " * (w + 2) + "  ".join(f"{i:>5}" for i in range(len(caps))))
    mat = [[0.0] * len(caps) for _ in caps]
    for i, (_, _, ri) in enumerate(caps):
        for j, (_, _, rj) in enumerate(caps):
            mat[i][j] = 0.5 if i == j else c2st_auc_between(ri, rj)
        row = "  ".join(f"{mat[i][j]:.3f}" if j != i else "  -  " for j in range(len(caps)))
        print(f"{labels[i]:<{w}} {i:>2} {row}")

    # --- floors and synth deltas --------------------------------------------
    real_idx = [i for i, c in enumerate(caps) if c[1] == "real"]
    synth_idx = [i for i, c in enumerate(caps) if c[1] == "synth"]

    rr = [mat[i][j] for a, i in enumerate(real_idx) for j in real_idx[a + 1:]]
    if rr:
        rr.sort()
        floor = rr[len(rr) // 2]
        print(f"\nreal-vs-real floor: median {floor:.3f}  (range {rr[0]:.3f}–{rr[-1]:.3f}, "
              f"{len(rr)} pairs)")
    else:
        floor = None
        print("\nreal-vs-real floor: n/a (need >= 2 real captures for a floor)")

    print("\nsynth-vs-real (lower is better; compare to the floor, not to 0.5):")
    for si in synth_idx:
        aucs = [mat[si][ri] for ri in real_idx]
        aucs_sorted = sorted(aucs)
        med = aucs_sorted[len(aucs_sorted) // 2]
        delta = f"  (floor+{med - floor:+.3f})" if floor is not None else ""
        print(f"  {labels[si]:<{w}}  median {med:.3f}  min {aucs_sorted[0]:.3f} "
              f"max {aucs_sorted[-1]:.3f}{delta}")

    print("\nwithin-source floor (each capture, 1st half vs 2nd — a per-capture sanity check):")
    for lab, _, r in caps:
        print(f"  {lab:<{w}}  {temporal_split_auc(r):.3f}")

    print("\nRead it as: a synth whose synth-vs-real median sits NEAR the real-vs-real floor is")
    print("as hard to tell from real as two real captures are from each other. Far ABOVE the")
    print("floor = a genuine fidelity gap beyond mere population difference.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
