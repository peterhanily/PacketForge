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

- **Realism** — `c2st_auc = 0.978`. A capture that is valid, in the sense that real Zeek reproduces
  it exactly, can still be distinguishable in feature space. Reference-conditioning has retired the
  TCP-window, byte-volume, and connection-state tells (see the ratchet below); the strongest
  *remaining* tells are within-flow packet-timing dynamics (`ia_std`, `ia_burst`) and packet-count
  structure (`l_orig_pkts`, `l_pkt_ratio`). Validity is necessary but not sufficient for realism.
- **Detection** — `alert_js = 1.0`. The reference fires roughly 217 benign false positives per hour
  under ET Open. The synthetic now fires a realistic ~226/hr (dynamic-DNS, noisy-TLD, and
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
distance fell accordingly.

A second pass then added **reference-conditioning**: the matched synthetic draws its SYN window,
TTL, and packet-timing from the reference's *measured* populations instead of the generator's
defaults. That retired the two dominant tells outright — `first_window` and `ia_mean` fell out of
the ranking, and the top feature-importance collapsed from ~0.37 to under 0.03, so no single tell
carries the classifier any more. The headline AUC moved from 1.0 to ~0.99 and MMD from 0.17 to
0.11.

A third pass conditioned the **connection-state mix**: the analog now folds the reference's full
Zeek `conn_state` histogram onto the states it can render and reproduces its established-vs-failed
split and its S0:REJ failure ratio, instead of using a built-in mix. That retired `cs_REJ` — it
dropped out of the ranking entirely. The headline AUC held at 0.987: the AUC is a *max* over
features, so retiring a non-dominant tell doesn't move it until the dominant one falls. That is the
honest shape of the ratchet — each pass removes a real tell, but the number only drops when the
*strongest* tell is the one retired. After that pass the top tells became one family: per-flow
originator byte volumes (`l_orig_bytes`, `l_orig_ipb`, `orig_bpp`).

A fourth pass conditioned exactly those. The analog now measures the reference's per-service
originator-byte distribution and grows each flow toward a drawn target with *legitimate* protocol
content — TLS client application-data, and for HTTP a browser-sized cookie (or, past a header
line's worth, a request body) — never filler the parser rejects. The synthetic stays Zeek-clean
(every flow reproduces, zero weirds) while its `orig_bytes` marginal goes from flat (~270 bytes for
every TLS flow) to matching the reference across the full heavy tail (median 2607 vs 2642, p90
31428 vs 31441). That retired the whole byte-volume family: AUC 0.987 → 0.978, MMD 0.11 → 0.10.
The tells that surfaced next are a new family again — within-flow timing dynamics (`ia_std`,
`ia_burst`) and packet-count structure (`l_orig_pkts`, `l_pkt_ratio`). Four passes in, the pattern
holds: the aggregate distance (MMD) falls steadily, 0.17 → 0.10, while the max-over-features AUC
descends only as each *dominant* family is retired in turn. The metric refuses to flatter the
generator until that work is actually done.

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
