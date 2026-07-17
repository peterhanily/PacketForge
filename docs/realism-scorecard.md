# The realism scorecard

[`realism-scorecard.json`](../realism-scorecard.json) is a single versioned artifact that
records, in numbers, how close a synthetic capture is to a real reference across every gate
PacketForge measures. It turns "is this realistic enough?" into a tracked value that moves as
the generator improves, rather than a claim in a README.

## What it measures

| Gate | Question | Headline metric | Pass bar |
|------|----------|-----------------|----------|
| **validity** | Does real Zeek/tshark reproduce the rendered capture? | `matched_ratio` | all flows match, `ok=true` |
| **realism** | Can an adversary separate synthetic flows from real ones (C2ST)? | `c2st_auc` | ≤ 0.65 |
| **detection** | Do detections behave the same — false-positive rate, alert mix? | `alert_js` | ≤ 0.30 |

`c2st_auc` is a cross-validated classifier's AUC on the real-vs-synthetic task: **0.5** means an
adversary cannot tell the two apart, **1.0** means they are trivially separable. `alert_js` is
the Jensen–Shannon divergence between the two captures' Suricata alert distributions: **0** is
identical, **1** is disjoint. Each gate also lists the features that separate the two sets, under
`honest_gaps`.

## Current baseline

The committed baseline (reference: `smallFlows.pcap`, 696 flows) reports `verdict: gap`:

- **Realism** — `c2st_auc = 1.0`. A capture that is valid, in the sense that real Zeek reproduces
  it exactly, can still be trivially distinguishable in feature space. The strongest tells are the
  TCP window fingerprint (`first_window`), the first packet size, and per-flow size and duration
  spread. Validity is necessary but not sufficient for realism.
- **Detection** — `alert_js = 1.0`. The reference fires roughly 217 benign false positives per hour
  under ET Open. The synthetic now fires a realistic ~205/hr (dynamic-DNS, noisy-TLD, and
  external-IP-lookup noise), so it is no longer conspicuously silent — but on a *different*
  signature set than this particular reference, so the alert distributions remain disjoint.
  Matching a specific network's benign signatures is a reference-conditioning problem, not a
  volume one.

The scorecard states this plainly. PacketForge today is a rigorous, Zeek-validated
network-detection lab, not a realism oracle, and the scorecard is where that distance closes one
measurable step at a time.

## The realism ratchet

The C2ST is not just a verdict; it is a worklist. Each release measures the classifier's AUC and
reads its feature importances — the top feature *is* the current giveaway — then a deterministic
fix retires that tell and the loop repeats. A first pass ("Stage 0") drove several tells down at
once: the synthetic went from a single TCP-window value to a realistic per-OS population, from
~100% `SF` connections to a real mix of failures (`S0`/`REJ`/`RSTO`), from uniformly small packets
to a heavy-tailed size distribution, and from **0 to ~205 benign IDS alerts/hour**. The kernel-MMD
distance fell accordingly. The headline AUC stays high because it is a max over all features and
because matching *this reference's exact distributions* is the next stage (reference-conditioning);
`first_window` remains the named next target. The metric going up when the work improves — and
refusing to move on distribution-match until the work is actually done — is the point.

## Generating and checking

Regenerate the scorecard against a real reference (requires `zeek` and `tshark`; add `--rules`
for the detection gate, which requires `suricata`):

```bash
packetforge realism-scorecard \
  --real /path/to/reference.pcap --env office \
  --rules /path/to/etopen-all.rules \
  --out realism-scorecard.json
```

Check a change against the committed baseline. The command exits non-zero if any tracked metric
regresses beyond its per-metric tolerance (the accepted run-to-run noise floor):

```bash
packetforge realism-scorecard --real reference.pcap --rules etopen-all.rules \
  --check realism-scorecard.json
```

## How CI tracks it

Recomputing the realism number requires Suricata, the `[realism]` extra, and a real reference
capture that cannot be redistributed. Per-PR CI therefore does not recompute it; instead it
guards the artifact. `tests/test_scorecard.py` asserts that the checked-in scorecard stays
schema-valid, self-consistent (it never regresses against itself), and free of local paths. The
full regression gate (`--check`) is a maintainer step, run wherever the tools and a reference are
available.

The tracked metrics, their direction, and their tolerances are defined in one place: `_METRICS`
in [`src/packetforge/scorecard.py`](../src/packetforge/scorecard.py).
