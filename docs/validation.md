# Validation: gates 1 to 3

PacketForge asks three questions of a capture, each with its own command and its own number. This
document states what each gate asserts, how to run it, and how to read the result. Gate 4, which
asks whether a reconstruction matches the incident it depicts, is covered in
[correspondence.md](correspondence.md).

| Gate | Question | Command |
|---|---|---|
| 1. Validity | Do real Zeek and tshark reproduce the capture? | `packetforge validate` |
| 2. Realism | Is the synthetic more separable from a real capture than a second real capture is? | `packetforge realism-audit` |
| 3. Detection | Do rules behave the same on the synthetic as on the reference? | `packetforge realism-detection` |

Gate 1 is a pass or fail contract and runs over every shipped sample. Gates 2 and 3 measure
against a real reference capture. Zeek, tshark and Suricata are external programs, not Python
dependencies.

## Gate 1: validity

The round-trip gate compiles a FlowSet, runs real Zeek and real tshark over the resulting pcap,
and asserts three things.

- **Clean reassembly.** Zeek produces no `weird.log` and no `reporter.log` entries.
- **Clean dissection.** `tshark -q -z expert` reports zero errors and zero non-benign warnings.
- **Field-for-field agreement.** Zeek's `conn`, `dns`, `http`, `ssl` and `smtp` logs match what
  each renderer declared it emitted, plus any `expect` block the IR carries.

The conn.log fields held to account are `service`, `conn_state`, `history`, `orig_bytes`,
`resp_bytes`, `orig_pkts` and `resp_pkts`. Duration is excluded because Zeek derives it its own
way. Four tshark warnings that real captures also carry are excluded (connection reset, receiver
window full, and two Kerberos notices tshark emits without the ticket keys). Errors are not.

```bash
packetforge validate flows.yaml
packetforge scenario --env office --flows 400 --seed 7 -o out.pcap --validate
```

The report prints `PASS` or `FAIL`, the packet count, matched flows over total flows, the four
tool counts, and one `MISMATCH` line per disagreeing field. It passes only when every count is
zero and every flow matched. Anything else is a generator bug.

### Cross-validation and transfer proof

Gate 1's evidence widens when tools nobody here wrote parse the same capture and agree.
`packetforge crossval` runs Zeek, Suricata, tshark, p0f and an external JA3 tool over one capture
and reports what each saw: Zeek services, Suricata app-protocols, tshark protocol layers, p0f OS
families, and JA3 digests. JA3 is a hash of the TLS ClientHello's version, ciphers, extensions,
curves and point formats. With `--flowspec`, crossval also checks the JA3 digest PacketForge
declared against the one the external tool read off the wire.

```bash
# real captures carry NIC-offloaded bad checksums, so crossval runs Zeek with -C and
# Suricata with -k none; those packets are analysed rather than discarded
packetforge crossval capture.pcap --flowspec source.yaml
# profile a real capture, build a same-mix analog, confirm both parse the same
packetforge transfer-proof real.pcap --env office
```

Read the result for what it is. Crossval establishes that independent tools parse the capture
without complaint and agree on its fingerprints, not that the traffic is real. Uninstalled tools
are reported as skipped rather than faked, and p0f is optional. Arkime and RITA are out of scope
because they require Elasticsearch and MongoDB.

## Gate 2: realism

Gate 2 measures distinguishability adversarially. A classifier is trained to separate PacketForge
flows from real ones, and its cross-validated AUC is the score. That construction is a Classifier
Two-Sample Test (C2ST): 0.5 means the adversary cannot tell the two sets apart, 1.0 means they are
trivially separable. The learner is a gradient-boosted tree over 5 folds, and a held-out second
learner scores the same task so a fix has to convince a model it was not tuned against.

Both sides share one feature pipeline, so nothing separates on capture tooling. Zeek `conn.log`
supplies per-flow byte and packet counts, ratios, history length, protocol and a one-hot
`conn_state`, Zeek's summary of how a connection began and ended (`SF` for a normal open and
close, `REJ` for a refused connection). The pcaps add inter-arrival, packet-size, TTL, window,
TCP-timestamp and ClientHello features. The audit also reports a kernel MMD (Maximum Mean
Discrepancy, a distribution distance where 0 means identical), a per-service AUC so the adversary
cannot win by counting which side has more DNS, and a ranked list of tells by KS distance and
permutation importance. Fewer than 20 flows on a side reports `INCONCLUSIVE`, never a vacuous 0.5.

```bash
pip install "packetforge[realism] @ git+https://github.com/peterhanily/PacketForge"
packetforge scenario --env home --flows 700 --texture realistic -o synth.pcap
packetforge realism-audit --real smallFlows.pcap --synthetic synth.pcap
```

### Why 0.5 is the wrong target

A C2ST against one reference measures distance to that exact capture, so 0.5 is reachable only by
a near-perfect replay of it. Two distinct real captures are not one distribution: they differ in
network, time, host population, service mix and capture vantage, and the same adversary separates
them at roughly 0.95 to 1.0. The floor a generator of novel traffic can reach is therefore the
real-vs-real number on the same panel, not 0.5. A random split of a single capture scores about
0.46, which confirms the adversary reports chance when the two sides are one distribution.

### Two panels, two sets of numbers

The repository publishes two measurements that look contradictory until the panel is named.

| Panel | Real-vs-real | Synthetic | What was compared |
|---|---|---|---|
| Enterprise | 0.933 to 0.963 (mean 0.944) | 0.974 | smallFlows against three bigFlows windows |
| Mixed public | 0.963 to 1.000 (median 0.998) | 0.999 | 10 pairs from 5 independent real captures |

Both are correct. The C2ST measures separability against whichever real captures were chosen, so
the absolute number moves with the panel, and the only stable reading is the distance between the
synthetic and the real pairs on the same panel. On the enterprise panel the synthetic is a
reference-conditioned analog of `smallFlows` and sits 0.011 above the top of the band, inside the
0.03 tolerance the scorecard allows. On the mixed public panel it is a standalone `home` scenario
scored against five independent captures (smallFlows, bigFlows, the Ultimate PCAP, and two IoT-23
benign home captures), and its 0.999 falls inside the range the real pairs span. Neither number
says the synthetic is indistinguishable in the abstract. Both say it is about as separable from
real traffic as real traffic is from other real traffic, to this adversary on these features.

A synthetic at or near its panel's band is as separable as two real captures are. One well above
the band has a fidelity gap, and the ranked tells say where. Weight those tells before acting on
them: a high-KS, low-importance tell such as TTL when comparing internet egress to a LAN is a
population difference, not a fixable gap.

The cross-capture metric is near-saturated, because any two real captures already score close to
1.0. The sharper signal is within-source variation: how separable the first half of a capture is
from its second half. Real captures sit at 0.65 to 0.83 there. The synthetic moved from about 0.53
into the 0.65 to 0.71 range once the ambient generator gained a non-stationary activity envelope,
which puts it inside the real band at its lower edge.

Five of the nine environments (`cloud`, `aws-vpc`, `azure-vnet`, `gcp-vpc` and `oci-vcn`) have no
real ambient capture to baseline against, because most cloud network data is exposed as flow logs
and never as packets. The `k8s-lateral` attack shape has an anchor in a real Kubernetes honeypot
capture, but a real cluster's API traffic is opaque mTLS, so that anchor is structural rather than
byte-level. [`appendix/cloud-baselines.md`](appendix/cloud-baselines.md) catalogues what real
cloud pcap exists and where none can. The five passes that moved the enterprise AUC from 1.0 to
0.974 are recorded in [`appendix/realism-ratchet-history.md`](appendix/realism-ratchet-history.md).

## Gate 3: detection behaviour

Gate 3 asks whether a ruleset behaves the same way on the synthetic as on the reference.
`packetforge realism-detection` runs Suricata over both and compares their alert distributions.

```bash
packetforge realism-detection --real reference.pcap --env office --rules etopen-all.rules
packetforge coverage --env office --rules etopen-all.rules --md coverage.md
```

The headline is `alert_js`, the Jensen-Shannon divergence between the two signature histograms,
where 0 means an identical mix of signatures and 1 means disjoint support. `sig_coverage` is the
fraction of the reference's alerting signatures the synthetic also fires, and the report lists the
signatures only one side fired plus false positives per hour on each. `packetforge coverage`
answers the complementary question: it runs a ruleset over all 26 attacks and writes the ATT&CK
coverage matrix, so a gap shows up as an uncovered technique rather than a missing alert.

### Signature-conditioning

Matching the alert rate is not enough: an analog that fires the right number of benign alerts on
the wrong signature set has disjoint support, and the divergence stays near 1 whatever the rate.
Emerging Threats rules are open, deterministic pattern-matchers, so they can be read and satisfied
by construction. `packetforge.signatures` parses the pinned ruleset, reads the reference's own
alert histogram, and renders inert flows that trip exactly those signatures: a User-Agent match
becomes a request carrying that User-Agent, a `dns.query` match becomes a lookup for that name. On
`smallFlows`, which trips 5 benign signatures, this moved `alert_js` from 1.0 to about 0.10 with
all 5 reproduced and the Zeek round-trip still green. The engine refuses to synthesise a trigger
for a MALWARE, CNC or EXPLOIT rule, because that would fabricate an attack the ground truth does
not contain, and signatures it cannot invert are surfaced as `unmatched`.

## The scorecard artifact

[`realism-scorecard.json`](../realism-scorecard.json) records every gate that ran against a named
reference in one versioned file, so the numbers move with the generator instead of living in a
README. It holds the reference's name, SHA-256, flow count and duration, the generator version,
commit, environment and seed, a verdict block per gate, an `honest_gaps` list naming every gate
that did not pass, and the calibration captures the C2ST was scored against.

The committed baseline uses `smallFlows.pcap` as its reference and three `bigFlows` windows as
calibration. Validity passes at 410 of 410 flows. Realism passes with `c2st_auc` 0.974 against a
`real_baseline_range` of 0.933 to 0.963 and a `temporal_baseline_auc` of 0.67. The detection block
predates signature-conditioning and still records `alert_js` 1.0, so the overall verdict is `gap`.

```bash
# regenerate (needs zeek and tshark; --rules needs suricata)
packetforge realism-scorecard --real reference.pcap --env office \
  --rules etopen-all.rules --calibrate another-real.pcap --out realism-scorecard.json
# check a change against the committed baseline; exits non-zero on regression
packetforge realism-scorecard --real reference.pcap --rules etopen-all.rules \
  --check realism-scorecard.json
```

`--check` compares each tracked metric against the baseline within a per-metric tolerance, so
run-to-run noise does not read as a regression. The metrics, directions and tolerances live in
`_METRICS` in [`src/packetforge/scorecard.py`](../src/packetforge/scorecard.py).

Per-PR CI guards the artifact rather than recomputing the number, because recomputing it needs
Suricata, the `[realism]` extra and a reference capture that cannot be redistributed.
`tests/test_scorecard.py` asserts the checked-in scorecard stays schema-valid, self-consistent and
free of local paths, and the full `--check` run is a maintainer step.

## Reproducing gate 2

The panel captures are not redistributed here, and several of their licences forbid rehosting.
Download smallFlows and bigFlows from tcpreplay, the Ultimate PCAP from its author and the benign
IoT-23 captures from Stratosphere into a gitignored directory.

```bash
export PYTHONPATH=src
python -m packetforge scenario --env home --volume busy --duration 300 --seed 7 \
  --texture realistic -o /tmp/synth-home.pcap
python scripts/baseline_panel.py \
  --real /tmp/smallFlows.pcap /tmp/bigFlows.pcap /tmp/ultimate.pcapng /tmp/iot23_1.pcap \
  --synth /tmp/synth-home.pcap
```

`baseline_panel.py` prints the pairwise AUC matrix, the real-vs-real floor, each synthetic against
each real, and the within-source split for every capture. The pcaps stay local.
