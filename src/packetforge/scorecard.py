# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Versioned realism scorecard — one honest artifact across all three gates.

Every gate we build answers a different question:
  * validity   (Gate 1) — does real Zeek/tshark reproduce what we rendered?
  * realism    (Gate 2) — can an adversary tell synthetic flows from real ones (C2ST)?
  * detection  (Phase 1) — do detections *behave* the same (FP rate, alert mix) on both?

`build_scorecard` folds their report objects into a single plain dict with per-gate
verdicts and an explicit `honest_gaps` list — no gap is smoothed over. `compare_scorecards`
diffs a fresh run against a committed baseline within per-metric tolerances so CI can flag a
*regression* (realism got worse) without tripping on the run-to-run noise floor. The point is
a durable, checked-in number that goes up when the work gets better and can't quietly rot.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

SCHEMA_VERSION = "1.0"

# Target bars a gate must clear to read "pass".
_TARGET_C2ST = 0.65   # absolute AUC bar — used only when no real-vs-real baseline is available
_C2ST_BASELINE_TOL = 0.03   # synth may sit this far above the real-vs-real floor and still pass
_TARGET_JS = 0.30     # alert-distribution JS <= this => detections behave alike

# Metrics tracked for CI regression. (dotted path, direction, tolerance, label)
# tolerance is the run-to-run noise we forgive; worse-than-baseline beyond it is a regression.
_METRICS = [
    ("gates.validity.matched_ratio", "higher_better", 0.02, "validity: flows matched"),
    ("gates.realism.c2st_auc", "lower_better", 0.05, "realism: C2ST AUC"),
    ("gates.realism.held_out_auc", "lower_better", 0.05, "realism: held-out AUC"),
    ("gates.detection.alert_js", "lower_better", 0.05, "detection: alert-JS divergence"),
    ("gates.detection.sig_coverage", "higher_better", 0.05, "detection: signature coverage"),
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _get(d: dict, dotted: str):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _validity_gate(v) -> dict:
    ratio = round(v.matched_flows / v.total_flows, 3) if v.total_flows else 0.0
    return {
        "verdict": "pass" if v.ok else "fail",
        "ok": bool(v.ok),
        "matched_flows": v.matched_flows,
        "total_flows": v.total_flows,
        "matched_ratio": ratio,
        "packet_count": v.packet_count,
        "zeek_weird": v.zeek_weird,
        "tshark_errors": v.tshark_errors,
    }


def _realism_gate(r) -> dict:
    # The C2ST vs a single reference measures distance to *that capture*, not realism in the
    # abstract: two distinct real captures score ~0.95, so an absolute 0.5/0.65 target is
    # unreachable for a generator of novel traffic. When a real-vs-real baseline is measured,
    # the synth passes if it is no more separable than a distinct real capture is (within a
    # noise tolerance); otherwise we fall back to the absolute target and flag it honestly.
    baseline = getattr(r, "real_baseline_auc", 0.0) or 0.0
    if baseline > 0.5:
        verdict = "pass" if r.c2st_auc <= baseline + _C2ST_BASELINE_TOL else "gap"
    else:
        verdict = "pass" if r.c2st_auc <= _TARGET_C2ST else "gap"
    return {
        "verdict": verdict,
        "c2st_auc": round(r.c2st_auc, 3),
        "held_out_auc": round(r.held_out_auc, 3),
        "mmd": round(r.mmd, 3),
        "real_baseline_auc": round(baseline, 3),
        "n_real": r.n_real,
        "n_synth": r.n_synth,
        "target_auc": _TARGET_C2ST,
        "top_tells": [name for name, _ks, _imp in r.tells[:5]],
    }


def _detection_gate(d) -> dict:
    return {
        "verdict": "pass" if d.alert_js <= _TARGET_JS else "gap",
        "real_fp_per_hr": d.real_fp_per_hr,
        "synth_fp_per_hr": d.synth_fp_per_hr,
        "alert_js": d.alert_js,
        "sig_coverage": d.sig_coverage,
        "ruleset": Path(d.ruleset).name,   # basename only — never leak local paths
        "target_js": _TARGET_JS,
    }


def _honest_gaps(gates: dict) -> list:
    """Name every gap in plain language — the scorecard must not flatter the generator."""
    gaps = []
    rz = gates.get("realism")
    if rz and rz["verdict"] != "pass":
        tells = ", ".join(rz["top_tells"]) or "(none surfaced)"
        base = rz.get("real_baseline_auc", 0.0)
        if base and base > 0.5:
            bar = f"a distinct real capture scores {base} against this reference; synthetic is " \
                  f"still {round(rz['c2st_auc'] - base, 3)} more separable"
        else:
            bar = f"target <= {rz['target_auc']}"
        gaps.append(
            f"Realism: a C2ST adversary separates synthetic from real at AUC {rz['c2st_auc']} "
            f"({bar}). Strongest tells: {tells}."
        )
    dt = gates.get("detection")
    if dt and dt["verdict"] != "pass":
        if dt["synth_fp_per_hr"] < 0.25 * dt["real_fp_per_hr"]:
            surface = (f"synthetic fires {dt['synth_fp_per_hr']}/hr false positives vs the "
                       f"reference's {dt['real_fp_per_hr']}/hr — too clean, missing the benign FP surface")
        else:
            surface = (f"synthetic fires a realistic {dt['synth_fp_per_hr']}/hr of benign alerts "
                       f"(reference {dt['real_fp_per_hr']}/hr) but on a different signature set; "
                       f"matching the reference's specific benign SIDs needs reference-conditioning")
        gaps.append(
            f"Detection: alert-distribution JS is {dt['alert_js']} (target <= {dt['target_js']}); "
            f"{surface}."
        )
    vz = gates.get("validity")
    if vz and vz["verdict"] != "pass":
        gaps.append(
            f"Validity: only {vz['matched_flows']}/{vz['total_flows']} flows reproduce under "
            f"real Zeek/tshark — the capture is not yet fully faithful."
        )
    return gaps


def build_scorecard(*, meta: dict, validity=None, realism=None, detection=None) -> dict:
    """Fold the gate reports into one versioned dict. Any gate may be None (not run)."""
    gates: dict = {}
    if validity is not None:
        gates["validity"] = _validity_gate(validity)
    if realism is not None:
        gates["realism"] = _realism_gate(realism)
    if detection is not None:
        gates["detection"] = _detection_gate(detection)

    verdicts = {name: g["verdict"] for name, g in gates.items()}
    if not gates:
        overall = "not-run"
    elif all(v == "pass" for v in verdicts.values()):
        overall = "pass"
    elif any(v == "fail" for v in verdicts.values()):
        overall = "fail"
    else:
        overall = "gap"

    card = {
        "schema_version": SCHEMA_VERSION,
        "reference": meta.get("reference", {}),
        "generator": meta.get("generator", {}),
        "gates": gates,
        "honest_gaps": _honest_gaps(gates),
        "verdict": overall,
    }
    if meta.get("calibration"):   # the second real capture the realism C2ST was scored against
        card["calibration"] = meta["calibration"]
    return card


def compare_scorecards(baseline: dict, current: dict) -> list:
    """Per-metric diff vs baseline. status: ok | improved | regressed | missing."""
    out = []
    for path, direction, tol, label in _METRICS:
        b, c = _get(baseline, path), _get(current, path)
        if b is None or c is None:
            out.append({"metric": label, "path": path, "baseline": b, "current": c,
                        "delta": None, "status": "missing"})
            continue
        delta = round(c - b, 4)
        worse = delta > tol if direction == "lower_better" else delta < -tol
        better = delta < -tol if direction == "lower_better" else delta > tol
        status = "regressed" if worse else "improved" if better else "ok"
        out.append({"metric": label, "path": path, "baseline": b, "current": c,
                    "delta": delta, "tolerance": tol, "direction": direction, "status": status})
    return out


def regressions(comparison: list) -> list:
    return [c for c in comparison if c["status"] == "regressed"]


def render_comparison(comparison: list) -> str:
    lines = ["Realism scorecard — regression check vs baseline"]
    for c in comparison:
        if c["status"] == "missing":
            lines.append(f"  ?  {c['metric']}: missing (baseline={c['baseline']} current={c['current']})")
            continue
        mark = {"ok": " ", "improved": "+", "regressed": "!"}[c["status"]]
        lines.append(f"  {mark}  {c['metric']}: {c['baseline']} -> {c['current']} "
                     f"(Δ {c['delta']:+}, tol {c['tolerance']}) {c['status']}")
    regs = regressions(comparison)
    lines.append(f"  => {'REGRESSED: ' + str(len(regs)) + ' metric(s)' if regs else 'no regressions'}")
    return "\n".join(lines)


def run_scorecard(real_pcap, env, *, rules=None, baseline_pcap=None, seed: int = 1337,
                  workdir=None, git_commit: str | None = None) -> dict:
    """Run every available gate against a real reference and assemble the scorecard.

    Needs zeek + tshark (validity, realism) and — if `rules` is given — suricata (detection).
    The synthetic is mix/volume-matched to the reference so the comparison is apples-to-apples.
    `baseline_pcap` (a *second, distinct real* capture) calibrates the C2ST: it is the
    real-vs-real floor the synth is scored against, since 0.5 is unreachable vs one reference.
    """
    import subprocess
    import tempfile

    from packetforge.compile.timeline import write_pcap
    from packetforge.realism import audit, c2st_auc_between, flow_feature_rows
    from packetforge.realism_detection import (
        detection_outcome,
        matched_synthetic,
        profile_reference,
    )
    from packetforge.validation import validate_flowset
    from packetforge.validation.roundtrip import _parse_zeek_log

    real_pcap = Path(real_pcap)
    base = Path(workdir or tempfile.mkdtemp(prefix="pf_scorecard_"))
    base.mkdir(parents=True, exist_ok=True)

    # Profile the reference, then build a matched synthetic capture.
    prof_dir = base / "profile"
    prof = profile_reference(real_pcap, prof_dir)
    # A reference with no parseable flows can't anchor a realism comparison: two empty
    # captures are trivially "indistinguishable", so an unguarded run would emit a
    # vacuous verdict=pass on a non-pcap. Refuse it instead.
    if not _parse_zeek_log(prof_dir / "conn.log"):
        raise ValueError(f"reference capture {real_pcap.name} has no parseable flows — "
                         f"is it a valid, non-empty pcap?")
    fs = matched_synthetic(prof, env, seed=seed)
    synth_pcap = base / "synth.pcap"
    write_pcap(fs, synth_pcap)

    # Gate 1 — validity of the synthetic under real tooling.
    validity = validate_flowset(fs)

    # Gate 2 — realism C2ST: real vs matched-synthetic, in feature space.
    wds = {}
    for label, pcap in (("real", real_pcap), ("synth", synth_pcap)):
        wd = base / f"zeek_{label}"
        wd.mkdir(exist_ok=True)
        subprocess.run(["zeek", "-C", "-r", str(pcap), "detect_filtered_trace=F"],
                       cwd=str(wd), capture_output=True, text=True, check=False)
        wds[label] = wd
    realism = audit(wds["real"], wds["synth"], real_pcap=real_pcap, synth_pcap=synth_pcap)

    # Calibrate the C2ST against a real-vs-real baseline: run the identical adversary between the
    # reference and a *second distinct real* capture. Two real captures are not one distribution,
    # so this lands well above 0.5 — it is the floor a generator of novel traffic can reach, and
    # the only fair thing to score the synth's AUC against.
    if baseline_pcap is not None:
        bwd = base / "zeek_baseline"
        bwd.mkdir(exist_ok=True)
        subprocess.run(["zeek", "-C", "-r", str(baseline_pcap), "detect_filtered_trace=F"],
                       cwd=str(bwd), capture_output=True, text=True, check=False)
        ref_rows, _, _ = flow_feature_rows(wds["real"], real_pcap)
        base_rows, _, _ = flow_feature_rows(bwd, Path(baseline_pcap))
        realism.real_baseline_auc = c2st_auc_between(ref_rows, base_rows)

    # Phase 1 — detection-outcome equivalence (only if a ruleset is available).
    detection = None
    if rules is not None:
        detection = detection_outcome(real_pcap, env, rules, seed=seed, workdir=base / "detect")

    ref_flows = len([r for r in _parse_zeek_log(wds["real"] / "conn.log") if r.get("uid")])
    meta = {
        "reference": {"name": real_pcap.name, "sha256": _sha256(real_pcap),
                      "flows": ref_flows, "duration_s": round(prof.duration, 1)},
        "generator": {"packetforge_version": _pf_version(), "git_commit": git_commit,
                      "environment": getattr(env, "name", str(env)), "seed": seed},
    }
    if baseline_pcap is not None:   # the second real capture the C2ST is calibrated against
        baseline_pcap = Path(baseline_pcap)
        meta["calibration"] = {"name": baseline_pcap.name, "sha256": _sha256(baseline_pcap)}
    return build_scorecard(meta=meta, validity=validity, realism=realism, detection=detection)


def _pf_version() -> str:
    from packetforge import __version__
    return __version__
