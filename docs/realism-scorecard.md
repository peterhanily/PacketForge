# The realism scorecard

One versioned, checked-in artifact — [`realism-scorecard.json`](../realism-scorecard.json) —
that states, in numbers, how close a synthetic capture is to a real reference across every gate
PacketForge can measure. It exists so the answer to *"is this realistic enough?"* is a number that
goes up when the work improves and can't quietly rot, rather than a claim in a README.

## What it measures

| Gate | Question | Headline metric | Pass bar |
|------|----------|-----------------|----------|
| **validity** | Does real Zeek/tshark reproduce what we rendered? | `matched_ratio` | all flows match, `ok=true` |
| **realism** | Can an adversary separate synthetic flows from real ones? (C2ST) | `c2st_auc` | ≤ 0.65 |
| **detection** | Do detections *behave* the same — FP rate, alert mix? | `alert_js` | ≤ 0.30 |

`c2st_auc` is a cross-validated classifier's AUC on the real-vs-synthetic task: **0.5** means an
adversary can't tell them apart, **1.0** means they're trivially separable. `alert_js` is the
Jensen–Shannon divergence between the two captures' Suricata alert distributions: **0** identical,
**1** disjoint. Every gate names its own tells; nothing is smoothed over — see `honest_gaps`.

## The honest gap, today

The committed baseline (reference: `smallFlows.pcap`, 696 flows) reads **`verdict: gap`**, and says
so plainly:

- **Realism** — `c2st_auc = 1.0`. A synthetic capture that is *valid* (real Zeek reproduces it
  perfectly) is still *trivially distinguishable* in feature space. The strongest tells are the
  TCP window fingerprint (`first_window`), the first packet size, and per-flow size/duration
  spread. Validity is necessary but nowhere near sufficient for realism.
- **Detection** — `alert_js = 1.0`. The reference fires ~217 benign false-positives/hour under ET
  Open; the synthetic fires **zero**. The synthetic is "too clean" — it doesn't reproduce the
  messy benign-app signatures (chat clients, updaters, ad networks) that make real traffic noisy.

Publishing this gap *is* the point. It's the honest scope line: PacketForge today is a rigorous,
Zeek-validated *network-detection lab*, not a realism oracle. The scorecard is where that closes or
doesn't, one measurable step at a time.

## Generating and checking

Regenerate the scorecard against a real reference (needs `zeek` + `tshark`; add `--rules` for the
detection gate, which needs `suricata`):

```bash
packetforge realism-scorecard \
  --real /path/to/reference.pcap --env office \
  --rules /path/to/etopen-all.rules \
  --out realism-scorecard.json
```

Gate a change against the committed baseline — exits non-zero if any tracked metric regressed
beyond its per-metric tolerance (the run-to-run noise floor we forgive):

```bash
packetforge realism-scorecard --real reference.pcap --rules etopen-all.rules \
  --check realism-scorecard.json
```

## How CI tracks it

A realism recompute needs Suricata, the `[realism]` extra, and a real reference capture — and we
can't redistribute someone else's capture. So per-PR CI can't recompute the number; instead it
**guards the artifact**: `tests/test_scorecard.py` asserts the checked-in scorecard stays
schema-valid, self-consistent (never regresses against itself), and leaks no local paths. The full
regression gate (`--check`) is a maintainer step, run wherever the tools and a reference exist.

The metrics tracked for regression, their direction, and their tolerances live in one place —
`_METRICS` in [`src/packetforge/scorecard.py`](../src/packetforge/scorecard.py).
