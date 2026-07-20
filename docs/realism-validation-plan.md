# Realism Validation v2 — plan

"Realistic" for a detection tool means two things, measured against diverse references and
tracked over time:
- **Q1 (purpose):** do real detections reach the same verdict on synthetic and real
  traffic — same false-positive rate, same alert mix, same true-positive behaviour?
- **Q2 (general):** can a *strong, diverse* jury tell synthetic from real?

Realism = **yes to Q1 and no to Q2.** Gate 2 (one classifier, one old capture) only partly
answered Q2; this plan makes **Q1 the headline**.

## Options considered
- **A — Detection-Equivalence-First:** the only metric is Q1. Purpose-aligned, hardest to
  game; bounded by the ruleset's coverage.
- **B — Dual-Gate Adversarial:** Q1 + a strong statistical adversary panel (flow-GBM +
  nPrint/CNN + human). Most rigorous; heaviest.
- **C — Reference-Panel Benchmark:** a versioned, multi-reference, CI-tracked scorecard;
  detection-outcome primary, C2ST secondary. Nails references/tracking/honesty.

## Recommendation — C as the frame, A as the core metric, B's panel staged in
Detection-outcome equivalence (A) is the primary metric, delivered as a versioned
reference-panel benchmark (C), with the adversary panel (B) staged as the second gate.

## Design
1. **Reference panel** — modern/diverse real captures + first-class **bring-your-own**
   (`--real your.pcap`). Each profiled (mix, hosts, duration).
2. **Mix-conditioning** — synthesise an analog whose protocol mix / host count / duration
   match the reference; always report per-service (no counting cheat).
3. **Metric 1 (primary): detection-outcome equivalence** — over matched real vs synthetic:
   FP-rate divergence, alert-distribution Jensen-Shannon divergence, attack-transfer TP
   parity. Built on `detect.py`/`coverage.py`.
4. **Metric 2 (secondary, staged): adversary panel** — flow-GBM C2ST (have) → nPrint
   packet-bit → human blind panel. Held-out; never grade with the judge you tune.
5. **Rich features** — inter-arrival cadence, packet-size sequence, JA3/JA4, TTL/window.
6. **Scorecard + CI + honesty** — versioned `realism-scorecard.json`; CI diffs vs last.

## Traps handled
mix mismatch (conditioning + per-service), capture-artifact leakage (same Zeek pipeline),
Goodhart (held-out adversary, Metric 1 primary), scoping ("to adversary X vs reference Y"),
reference provenance (trusted benign labels only).

## Roadmap (each phase shippable)
1. Detection-outcome metric + references + conditioning.
2. Rich features + nPrint adversary (held-out).
3. Human blind-panel harness.
4. CI scorecard + regression tracking.
