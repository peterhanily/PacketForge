# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""PacketForge command-line interface."""

from __future__ import annotations

import argparse
import sys

from packetforge import __version__
from packetforge.compile.timeline import write_pcap
from packetforge.models.flowspec import load_flowset
from packetforge.validation import validate_flowset, validators_available


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packetforge",
        description="Deterministic, validated synthetic PCAPs from a Flow IR.",
    )
    parser.add_argument("--version", action="version", version=f"packetforge {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("compile", help="compile a FlowSpec (YAML/JSON) to a .pcap")
    c.add_argument("flowspec")
    c.add_argument("-o", "--out", required=True, help="output .pcap path")
    c.add_argument("--salt", default="", help="determinism salt (default: empty)")

    v = sub.add_parser("validate", help="compile and check against real Zeek/tshark")
    v.add_argument("flowspec")
    v.add_argument("--keep-dir", default=None, help="keep the Zeek working dir here")
    v.add_argument("--salt", default="")

    e = sub.add_parser(
        "ef-roundtrip",
        help="ingest EvidenceForge output, render a pcap, and compare our Zeek to EF's own logs")
    e.add_argument("ef_output", help="an EvidenceForge output directory")
    e.add_argument("--limit", type=int, default=None, help="sample at most N flows (round-robin)")
    e.add_argument("-o", "--out", default=None, help="also write the compiled pcap here")
    e.add_argument("--keep-dir", default=None)

    s = sub.add_parser("scenario", help="compose environment ambient noise (+ storyline) to a pcap")
    s.add_argument("--env", required=True, help="environment name (see --list-envs)")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--flows", type=int, default=150, help="number of ambient noise flows")
    s.add_argument("--volume", choices=["quiet", "normal", "busy", "saturated"], default=None,
                   help="named traffic volume (overrides --flows: rate x duration)")
    s.add_argument("--duration", type=float, default=600.0, help="time window in seconds")
    s.add_argument("--start", type=float, default=1_700_000_000.0, help="epoch start time")
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--storyline", default=None, help="a FlowSpec YAML whose flows are woven in")
    s.add_argument("--attack", nargs="?", const="phishing-intrusion", default=None,
                   help="weave in an attack (name from list-attacks; bare --attack = phishing-intrusion)")
    s.add_argument("--intensity", type=float, default=1.0, help="attack volume multiplier (default 1.0)")
    s.add_argument("--texture", choices=["clean", "realistic"], default="clean",
                   help="capture texture: 'realistic' adds RTT jitter, retransmits, dup-ACKs")
    s.add_argument("--evasion", action="append", default=None, dest="evasions",
                   help="apply an evasion modifier (repeatable; see list-evasions)")
    s.add_argument("--validate", action="store_true", help="also run the Zeek round-trip")

    ev = sub.add_parser("eval", help="score a .pcap for realism (blind-panel heuristics)")
    ev.add_argument("pcap")
    ev.add_argument("--min-score", type=int, default=None, help="exit non-zero below this score")

    rp = sub.add_parser("report", help="write a self-contained forensic HTML report for a .pcap")
    rp.add_argument("pcap")
    rp.add_argument("-o", "--out", required=True, help="output .html path")
    rp.add_argument("--ground-truth", default=None,
                    help="GROUND_TRUTH.json (default: <pcap-base>.GROUND_TRUTH.json if present)")

    dt = sub.add_parser("detect", help="run Suricata rules over a capture, score vs ground truth")
    dt.add_argument("pcap")
    dt.add_argument("--rules", default="detection/example.rules", help="Suricata rules file")
    dt.add_argument("--ground-truth", default=None,
                    help="GROUND_TRUTH.json (default: <pcap-base>.GROUND_TRUTH.json)")

    rb = sub.add_parser(
        "robustness",
        help="measure rule robustness: run rules on the clean vs evasive attack, report the delta")
    rb.add_argument("--env", required=True)
    rb.add_argument("--attack", default="phishing-intrusion")
    rb.add_argument("--evasion", action="append", default=None, dest="evasions", required=True,
                    help="evasion modifier(s) to apply to the evasive variant (repeatable)")
    rb.add_argument("--rules", default="detection/example.rules")
    rb.add_argument("--flows", type=int, default=120, help="ambient noise flows")
    rb.add_argument("--seed", type=int, default=0)
    rb.add_argument("--keep", default=None, help="keep generated pcaps/ground-truth in this dir")

    cov = sub.add_parser("coverage",
                         help="ATT&CK coverage matrix: run a ruleset over every attack")
    cov.add_argument("--env", required=True)
    cov.add_argument("--rules", default="detection/example.rules")
    cov.add_argument("--attacks", default=None, help="comma-separated subset (default: all)")
    cov.add_argument("--flows", type=int, default=80, help="ambient noise flows per attack")
    cov.add_argument("--seed", type=int, default=0)
    cov.add_argument("--md", default=None, help="also write the matrix as markdown here")

    fp = sub.add_parser("fp-benchmark",
                        help="false-positive rate of a ruleset over benign traffic (alerts/hour)")
    fp.add_argument("--env", required=True)
    fp.add_argument("--rules", required=True, help="ruleset to benchmark (e.g. ET Open)")
    fp.add_argument("--volume", default="normal", choices=["quiet", "normal", "busy", "saturated"])
    fp.add_argument("--duration", type=float, default=3600.0, help="benign window seconds")
    fp.add_argument("--seed", type=int, default=0)

    xv = sub.add_parser("crossval",
                        help="cross-validate a capture with independent tools (zeek/suricata/tshark/p0f/ja3)")
    xv.add_argument("pcap")
    xv.add_argument("--flowspec", default=None, help="source FlowSet YAML (enables JA3 agreement check)")

    tp = sub.add_parser("transfer-proof",
                        help="profile a real capture, synthesize an analog, confirm both parse the same")
    tp.add_argument("real_pcap")
    tp.add_argument("--env", default="office")
    tp.add_argument("--seed", type=int, default=0)

    mt = sub.add_parser("malware-transfer",
                        help="does a JA3 detection transfer from a (real-fake) malware capture to its analog?")
    mt.add_argument("--family", default="shadowbeacon", help="inert malware family (see list-families)")
    mt.add_argument("--env", default="office")
    mt.add_argument("--rules", default="detection/malware-ja3.rules")
    mt.add_argument("--reference", default=None, help="use a real capture instead of the built-in reference")
    mt.add_argument("--seed", type=int, default=0)
    sub.add_parser("list-families", help="list the inert malware-shaped families")

    sg = sub.add_parser("sigma",
                        help="evaluate Sigma rules over the Zeek logs a capture produces")
    sg.add_argument("pcap")
    sg.add_argument("--rules-dir", default="detection/sigma", help="dir of Sigma .yml rules")

    cb = sub.add_parser("corpus-build",
                        help="generate the versioned, labeled detection-CI corpus + manifest")
    cb.add_argument("--out", required=True, help="output directory for the corpus")

    cv = sub.add_parser("corpus-verify",
                        help="score a ruleset against the corpus; flag regressions vs a baseline")
    cv.add_argument("--corpus", required=True, help="corpus directory (with manifest.json)")
    cv.add_argument("--rules", default="detection/example.rules")
    cv.add_argument("--baseline", default=None, help="a prior scorecard JSON to diff against")
    cv.add_argument("--save", default=None, help="write this run's scorecard JSON here")

    sub.add_parser("list-envs", help="list available network environments")
    sub.add_parser("list-attacks", help="list available attack scenarios")
    sub.add_parser("list-evasions", help="list available evasion modifiers")
    return parser


def _robustness(args) -> int:
    """Compose the same attack clean vs evasive into identical noise, detect both, diff."""
    import random
    import tempfile
    from pathlib import Path

    from packetforge.compose import compose_scenario
    from packetforge.detect import run_detection, suricata_available
    from packetforge.environments import load_environment
    from packetforge.scenarios import build_attack, write_ground_truth

    if not suricata_available():
        print("ERROR: need 'suricata' on PATH", file=sys.stderr)
        return 2
    env = load_environment(args.env)
    outdir = Path(args.keep) if args.keep else Path(tempfile.mkdtemp(prefix="pf_robust_"))
    outdir.mkdir(parents=True, exist_ok=True)
    start = 1_700_000_000.0

    def run(label: str, evasions: tuple):
        intr = build_attack(args.attack, env, start + 100.0, random.Random(args.seed),
                            evasions=evasions)
        fs = compose_scenario(env, start_time=start, noise_flows=args.flows, seed=args.seed,
                              storyline=intr.flows)
        pcap = outdir / f"{label}.pcap"
        write_pcap(fs, pcap)
        gt = outdir / f"{label}.GROUND_TRUTH.json"
        write_ground_truth(intr, outdir / f"{label}.GROUND_TRUTH.md", gt)
        return run_detection(pcap, args.rules, gt)

    clean = run("clean", ())
    evasive = run("evasive", tuple(args.evasions))

    print(f"Rule-robustness: {args.attack} in {args.env}  |  evasions: {', '.join(args.evasions)}")
    print(f"  rules: {args.rules}")
    print(f"  CLEAN     {clean.summary().splitlines()[0]}")
    print(f"  EVASIVE   {evasive.summary().splitlines()[0]}")
    lost = sorted(set(clean.techniques_caught) - set(evasive.techniques_caught))
    kept = sorted(set(clean.techniques_caught) & set(evasive.techniques_caught))
    for t in kept:
        print(f"  ROBUST   {t}  (still caught under evasion)")
    for t in lost:
        print(f"  EVADED   {t}  (caught clean, MISSED under {', '.join(args.evasions)})")
    if not lost:
        print("  -> rules are robust to these evasions (no technique lost)")
    else:
        print(f"  -> {len(lost)}/{len(clean.techniques_caught)} caught techniques evaded; "
              f"tighten beyond the defeated IOCs")
    if args.keep:
        print(f"  artifacts in {outdir}")
    return 0


def main(argv: list | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "compile":
        fs = load_flowset(args.flowspec)
        result = write_pcap(fs, args.out, salt=args.salt)
        print(f"wrote {args.out}: {len(result.packets)} packets across {len(result.flows)} flows")
        return 0

    if args.cmd == "validate":
        fs = load_flowset(args.flowspec)
        if not validators_available():
            print("ERROR: 'zeek' and 'tshark' must be on PATH to validate", file=sys.stderr)
            return 2
        report = validate_flowset(fs, salt=args.salt, keep_dir=args.keep_dir)
        print(report.summary())
        return 0 if report.ok else 1

    if args.cmd == "ef-roundtrip":
        from packetforge.ingest.evidenceforge import flowset_from_evidenceforge
        from packetforge.validation.ef_roundtrip import compare_against_ef

        if not validators_available():
            print("ERROR: 'zeek' and 'tshark' must be on PATH", file=sys.stderr)
            return 2
        fs, originals, stats = flowset_from_evidenceforge(args.ef_output, limit=args.limit)
        if args.out:
            write_pcap(fs, args.out)
        print(compare_against_ef(fs, originals, stats, keep_dir=args.keep_dir).summary())
        return 0

    if args.cmd == "eval":
        from packetforge.evaluate import evaluate_pcap
        if not validators_available():
            print("ERROR: need zeek + tshark on PATH", file=sys.stderr)
            return 2
        report = evaluate_pcap(args.pcap)
        print(report.summary())
        if args.min_score is not None and report.score < args.min_score:
            return 1
        return 0

    if args.cmd == "report":
        from pathlib import Path

        from packetforge.report import render_report
        if not validators_available():
            print("ERROR: need zeek + tshark on PATH", file=sys.stderr)
            return 2
        gt = args.ground_truth
        if gt is None:
            cand = Path(args.pcap).with_suffix("").as_posix() + ".GROUND_TRUTH.json"
            gt = cand if Path(cand).exists() else None
        Path(args.out).write_text(render_report(args.pcap, gt), encoding="utf-8")
        print(f"wrote {args.out}")
        return 0

    if args.cmd == "detect":
        from pathlib import Path

        from packetforge.detect import run_detection, suricata_available
        if not suricata_available():
            print("ERROR: need 'suricata' on PATH", file=sys.stderr)
            return 2
        gt = args.ground_truth
        if gt is None:
            cand = Path(args.pcap).with_suffix("").as_posix() + ".GROUND_TRUTH.json"
            gt = cand if Path(cand).exists() else None
        if gt is None:
            print("ERROR: no GROUND_TRUTH.json found; pass --ground-truth", file=sys.stderr)
            return 2
        print(run_detection(args.pcap, args.rules, gt).summary())
        return 0

    if args.cmd == "corpus-build":
        from packetforge.corpus import build_corpus
        manifest = build_corpus(args.out)
        print(f"built corpus v{manifest['corpus_version']}: {len(manifest['captures'])} "
              f"labeled captures in {args.out}")
        for c in manifest["captures"]:
            print(f"  {c['name']:32} {len(c['techniques'])} techniques  {c['sha256'][:12]}")
        return 0

    if args.cmd == "corpus-verify":
        import json as _json
        from pathlib import Path

        from packetforge.corpus import diff_scorecards, verify_corpus
        from packetforge.detect import suricata_available
        if not suricata_available():
            print("ERROR: need 'suricata' on PATH", file=sys.stderr)
            return 2
        card = verify_corpus(args.corpus, args.rules)
        print(f"corpus v{card['corpus_version']} vs {args.rules}: "
              f"{card['techniques_caught']}/{card['techniques_total']} techniques caught, "
              f"{card['false_positives']} false positives")
        for s in card["scores"]:
            print(f"  {s['name']:32} caught {len(s['techniques_caught'])}/{s['techniques_total']}"
                  f"  fp={s['false_positives']}")
        if args.save:
            Path(args.save).write_text(_json.dumps(card, indent=2) + "\n", encoding="utf-8")
            print(f"wrote scorecard {args.save}")
        if args.baseline:
            base = _json.loads(Path(args.baseline).read_text())
            d = diff_scorecards(base, card)
            for r in d["regressions"]:
                print(f"  REGRESSION  {r['capture']}: lost {r['technique']}")
            for f in d["new_false_positives"]:
                print(f"  NEW FP      {f['capture']}: {f['was']} -> {f['now']}")
            for g in d["gains"]:
                print(f"  GAIN        {g['capture']}: now catches {g['technique']}")
            if d["ok"]:
                print("  -> no regressions vs baseline")
                return 0
            print("  -> REGRESSIONS DETECTED")
            return 1
        return 0

    if args.cmd == "crossval":
        from packetforge.crossval import cross_validate
        fs = load_flowset(args.flowspec) if args.flowspec else None
        print(cross_validate(args.pcap, flowset=fs).render())
        return 0

    if args.cmd == "transfer-proof":
        from packetforge.environments import load_environment
        from packetforge.transfer import transfer_proof
        if not validators_available():
            print("ERROR: need zeek + tshark on PATH", file=sys.stderr)
            return 2
        print(transfer_proof(args.real_pcap, load_environment(args.env), seed=args.seed).render())
        return 0

    if args.cmd == "list-families":
        from packetforge.malware_transfer import MALWARE_FAMILIES, list_families
        for name in list_families():
            print(f"{name:14} {MALWARE_FAMILIES[name]['label']}")
        return 0

    if args.cmd == "malware-transfer":
        from packetforge.detect import suricata_available
        from packetforge.environments import load_environment
        from packetforge.malware_transfer import malware_transfer_proof
        if not suricata_available() or not validators_available():
            print("ERROR: need suricata + tshark on PATH", file=sys.stderr)
            return 2
        rep = malware_transfer_proof(load_environment(args.env), args.family, args.rules,
                                     reference_pcap=args.reference, seed=args.seed)
        print(rep.render())
        return 0 if rep.same_verdict else 1

    if args.cmd == "sigma":
        from packetforge.sigma import evaluate_pcap_with_sigma
        if not validators_available():
            print("ERROR: need zeek + tshark on PATH", file=sys.stderr)
            return 2
        results = evaluate_pcap_with_sigma(args.pcap, args.rules_dir)
        if not results:
            print(f"no Sigma rules found in {args.rules_dir}")
            return 2
        fired = [r for r in results if r.fired]
        print(f"Sigma over Zeek: {len(fired)}/{len(results)} rules fired  ({args.pcap})")
        for r in results:
            mark = "FIRED " if r.fired else "silent"
            detail = ""
            if r.groups:
                hot = sorted(((k, v) for k, v in r.groups.items()), key=lambda kv: -kv[1])[:2]
                detail = "  " + ", ".join(f"{k}:{v}" for k, v in hot)
            elif r.matched_records:
                detail = f"  ({len(r.matched_records)} records)"
            tech = f" [{r.rule.technique}]" if r.rule.technique else ""
            print(f"  {mark} {r.rule.title}{tech}{detail}")
        return 0

    if args.cmd == "list-envs":
        from packetforge.environments import list_environments, load_environment
        for name in list_environments():
            env = load_environment(name)
            print(f"{name:8} link={env.link_type:10} {env.subnet:16} {env.description}")
        return 0

    if args.cmd == "list-attacks":
        from packetforge.scenarios import ATTACKS, list_attacks
        for name in list_attacks():
            doc = (ATTACKS[name].__doc__ or "").strip().split("\n")[0]
            print(f"{name:18} {doc}")
        return 0

    if args.cmd == "list-evasions":
        from packetforge.scenarios import EVASIONS, list_evasions
        for name in list_evasions():
            doc = (EVASIONS[name].__doc__ or "").strip().split("\n")[0]
            print(f"{name:18} {doc}")
        return 0

    if args.cmd == "robustness":
        return _robustness(args)

    if args.cmd == "coverage":
        from pathlib import Path

        from packetforge.coverage import build_coverage_matrix
        from packetforge.detect import suricata_available
        from packetforge.environments import load_environment
        if not suricata_available():
            print("ERROR: need 'suricata' on PATH", file=sys.stderr)
            return 2
        attacks = args.attacks.split(",") if args.attacks else None
        matrix = build_coverage_matrix(load_environment(args.env), args.rules,
                                       attacks=attacks, noise_flows=args.flows, seed=args.seed)
        print(matrix.render())
        if args.md:
            Path(args.md).write_text(matrix.to_markdown(), encoding="utf-8")
            print(f"\nwrote {args.md}")
        return 0

    if args.cmd == "fp-benchmark":
        from packetforge.coverage import fp_benchmark
        from packetforge.detect import suricata_available
        from packetforge.environments import load_environment
        if not suricata_available():
            print("ERROR: need 'suricata' on PATH", file=sys.stderr)
            return 2
        bench = fp_benchmark(load_environment(args.env), args.rules,
                             duration_s=args.duration, volume=args.volume, seed=args.seed)
        print(bench.render())
        return 0

    if args.cmd == "scenario":
        import random
        from pathlib import Path

        from packetforge.compose import compose_scenario, flows_for_volume
        from packetforge.environments import load_environment
        env = load_environment(args.env)
        n_flows = flows_for_volume(args.volume, args.duration) if args.volume else args.flows
        storyline = load_flowset(args.storyline).flows if args.storyline else None
        intrusion = None
        if args.attack:
            from packetforge.scenarios import build_attack
            intrusion = build_attack(args.attack, env, args.start + 100.0,
                                     random.Random(args.seed), intensity=args.intensity,
                                     evasions=tuple(args.evasions or ()))
            storyline = (storyline or []) + intrusion.flows
        fs = compose_scenario(env, start_time=args.start, duration_s=args.duration,
                              noise_flows=n_flows, seed=args.seed, storyline=storyline,
                              texture=args.texture)
        write_pcap(fs, args.out)
        vol = f", volume={args.volume}" if args.volume else ""
        print(f"wrote {args.out}: {len(fs.flows)} flows ({env.name}, link={env.link_type}{vol})")
        if intrusion is not None:
            from packetforge.scenarios import write_ground_truth
            base = str(Path(args.out).with_suffix(""))
            write_ground_truth(intrusion, base + ".GROUND_TRUTH.md", base + ".GROUND_TRUTH.json")
            print(f"wrote {base}.GROUND_TRUTH.md — {len(intrusion.ground_truth)} ATT&CK stages")
        if args.validate:
            if not validators_available():
                print("ERROR: need zeek + tshark on PATH to validate", file=sys.stderr)
                return 2
            print(validate_flowset(fs).summary())
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
