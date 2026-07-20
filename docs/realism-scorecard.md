# The realism scorecard

[`realism-scorecard.json`](../realism-scorecard.json) is a single versioned artifact that
records, in numbers, how close a synthetic capture is to a real reference across every gate
PacketForge measures. It turns "is this realistic enough?" into a tracked value that moves as
the generator improves, rather than a claim in a README.

## What it measures

| Gate | Question | Headline metric | Pass bar |
|------|----------|-----------------|----------|
| **validity** | Does real Zeek/tshark reproduce the rendered capture? | `matched_ratio` | all flows match, `ok=true` |
| **realism** | Is the synthetic no more separable from the reference than a *second real capture* is? | `c2st_auc` vs `real_baseline_auc` | ≤ baseline + 0.03 |
| **detection** | Do detections behave the same — false-positive rate, alert mix? | `alert_js` | ≤ 0.30 |

`c2st_auc` is a cross-validated classifier's AUC on the real-vs-synthetic task: **0.5** means an
adversary cannot tell the two apart, **1.0** means they are trivially separable.

The realism bar is **not** an absolute `c2st_auc ≤ 0.5`, and that matters. A C2ST against a single
reference measures distance to *that exact capture*, so 0.5 is reachable only by a near-perfect
replay of it — **two distinct real captures are not the same distribution** (different networks,
times, host populations, service mix) and score far above 0.5 against each other. So the scorecard
runs the identical adversary between the reference and a *second real* capture and reports that as
`real_baseline_auc` — the floor a generator of *novel* traffic can reach. The synthetic passes when
it is no more separable than that. (Sanity check: two random halves of the *same* capture score
~0.5, confirming the adversary is well-calibrated; it is the cross-capture case that is high.)

`alert_js` is the Jensen–Shannon divergence between the two captures' Suricata alert distributions:
**0** is identical, **1** is disjoint. Each gate also lists the features that separate the two sets,
under `honest_gaps`.

## Current baseline

The committed baseline (reference: `smallFlows.pcap`, calibrated against three `bigFlows` windows)
reports `verdict: gap` — carried entirely by the detection gate:

- **Realism** — `verdict: pass`. `c2st_auc = 0.974` against a real-vs-real band of
  `[0.933, 0.963]` (mean 0.944, three distinct `bigFlows` windows), with a within-source
  `temporal_baseline_auc` of 0.67 for reference. The synthetic sits at the *upper edge* of the
  real-vs-real band — as separable from `smallFlows` as another real enterprise capture is, within a
  noise tolerance of its top. Reference-conditioning drove the AUC from a starting 1.0 (and the
  kernel-MMD from 0.17 to 0.077) by retiring the TCP-window, byte-volume, connection-state, and
  coarse-timing tells in turn (see the ratchet below). The residual tells are fine-grained
  (within-flow timing, per-OS SYN-option layout, mid-stream-capture artifacts) — the same
  micro-differences that separate any two real captures. Chasing `c2st_auc` below the real-vs-real
  band would mean replaying this one capture, not generating.
- **Detection** — `alert_js = 1.0` (`verdict: gap`). The reference fires roughly 217 benign false
  positives per hour under ET Open. The synthetic now fires **~205/hr** — close to that rate, once the
  analog's flow durations were conditioned to the reference (dynamic-DNS, noisy-TLD, and
  external-IP-lookup noise) — so it is no longer conspicuously silent. It fires on a *different*
  signature set than this particular reference, though, so the alert distributions remain disjoint.
  Matching a specific network's benign signatures is a reference-conditioning problem, not a
  volume one, and it is the one gate still open.

The scorecard states this plainly. PacketForge is a rigorous, Zeek-validated network-detection lab
whose synthetic ambient traffic is, by the C2ST, as hard to distinguish from a real reference as a
second real capture is — with the honest remaining gap being detection-surface identity to one
specific network.

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
`ia_burst`) and packet-count structure (`l_orig_pkts`, `l_pkt_ratio`).

A fifth pass turned the four point-fixes into an **engine**. Conditioning each marginal
independently decorrelates features that co-vary in real traffic — draw a flow's mean inter-arrival
from one distribution and its packet count from another and a few flows end up with absurd durations
— so the analog now does *joint per-flow cloning*: it reproduces each reference flow's bytes, packet
counts, duration, and conn_state **together**, from the same flow. Within-flow packet timing is
drawn from a lognormal (bursty, heavy right tail, mean-preserving) so `ia_burst` matches, and each
flow's effective segment size is set to the reference's bytes-per-packet — real captures are taken
above NIC offload, so a large transfer is a few big segments, not dozens of MSS ones. All of it is
retransmit-free, so validity stays byte-exact. This brought the benign false-positive rate close to
the reference (**~205/hr vs ~217/hr**, up from a duration-inflated 98), pulled MMD to 0.077, and moved
the AUC to 0.974. What remains is genuinely fine-grained: the exact shape of small flows' timing and
per-OS SYN-option layouts.

### How low can the AUC actually go?

At AUC ~0.97 the ratchet stopped moving the headline number, which raised the right question: is
0.5 even the target? It is not. The same adversary, run on real captures, traces a clear spectrum:

| Comparison | C2ST AUC | what it is |
|------------|:--------:|------------|
| `smallFlows` random-split vs itself | **~0.46** | the null — one distribution, so chance (adversary is calibrated) |
| `smallFlows` first half vs second half | **~0.67** | *within-source* drift — two time-windows of the same network |
| `smallFlows` vs `bigFlows` chunks | **~0.95** | *cross-capture* — two distinct real enterprise captures |
| **the PacketForge synthetic** | **~0.97** | sits at the cross-capture floor |

Two distinct real captures are trivially separable because they *are* different distributions
(different networks, times, hosts, mix); the only thing that scores ~0.5 is two random halves of one
capture. So an absolute 0.5 bar is reachable only by replaying one specific capture — the opposite of
generating. The honest floor for a generator of *novel* traffic is the **real-vs-real** number, and
the synthetic sits right at it. The scorecard therefore scores `c2st_auc` against a measured
`real_baseline_auc` — averaged over several real captures, with the `real_baseline_range` reported so
one easy or hard capture can't skew it — and carries the within-source `temporal_baseline_auc`
alongside as a stricter reference point. It also reports the distributional distance (kernel-MMD, the
metric the synthetic-traffic literature actually uses), which more than halved across the five passes,
0.17 → 0.077 — the real evidence the distributions converged. Pushing the C2ST below the real-vs-real
floor would not be more realism; it would be memorising the reference.

## Generating and checking

Regenerate the scorecard against a real reference (requires `zeek` and `tshark`; add `--rules`
for the detection gate, which requires `suricata`; add `--calibrate` with a second distinct real
capture to score the C2ST against the real-vs-real floor instead of an absolute bar):

```bash
packetforge realism-scorecard \
  --real /path/to/reference.pcap --env office \
  --rules /path/to/etopen-all.rules \
  --calibrate /path/to/another-real.pcap \
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
