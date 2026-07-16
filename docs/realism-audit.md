# The realism audit (Gate 2)

PacketForge validates a capture at two levels. **Gate 1 (validity)** requires real Zeek to
reproduce the capture: if Zeek's logs disagree with what was rendered, that is a bug.
**Gate 2 (realism)** measures a harder property adversarially. An independent classifier is
trained to separate PacketForge flows from real ones, and its cross-validated AUC is the
distinguishability score — a Classifier Two-Sample Test (C2ST). An AUC of 0.5 means the
adversary cannot tell the two apart; 1.0 means they are trivially separable.

The audit reports that number alongside the features that produced it: per-feature distances
and permutation importance, so each iteration has a concrete tell to remove. The classifier
only measures and ranks; it never generates. Every fix stays hand-authored and deterministic,
preserving the no-ML-at-generation-time contract.

## Running it

```bash
pip install 'packetforge[realism]'          # scikit-learn, scipy, numpy
# a real reference is any benign, multi-protocol capture, e.g. tcpreplay's smallFlows.pcap
packetforge scenario --env home --flows 700 --texture realistic -o synth.pcap
packetforge realism-audit --real smallFlows.pcap --synthetic synth.pcap
```

The report gives the C2ST AUC, a kernel-MMD distance, per-service AUC (mix-invariant), and
the ranked tells (feature, KS distance, permutation importance).

## Method

- **One feature pipeline, both sides.** Features are derived from Zeek `conn.log` for the real
  and synthetic captures alike, so nothing separates on capture tooling.
- **Mix-invariance.** Per-service AUC compares HTTP to HTTP and TLS to TLS, so the adversary
  cannot win by counting which set has more DNS.
- **Tested calibration.** Two captures from the same generator score about 0.5; clearly
  different distributions score near 0.96. A metric that always reported "distinguishable"
  would carry no information.
- **Held-out second learner.** A separate classifier scores the same task alongside the
  primary one, so an improvement has to convince a model the fix was not tuned against.
- **Precise scope.** "Indistinguishable" applies to a flow-feature, gradient-boosted adversary
  on these features — never as an unqualified claim. A stronger packet-bit adversary (nPrint
  with a CNN) is the next step once flow-level tells are removed.

## The measure-and-fix loop

The audit drives a deterministic loop: measure, read the top tell, correct it in the renderer,
re-measure. The first run against `smallFlows.pcap` shows one turn of the loop.

| | C2ST AUC | duration KS | duration importance |
|---|--:|--:|--:|
| before | 0.998 | 0.459 | 0.117 (#1 tell) |
| after the fix | 0.997 | 0.268 | 0.017 (retired) |

The top tell was flow duration. Real HTTP has a heavy tail (median 6.9 s, maximum 192 s),
while the renderer packed each conversation tightly at roughly 0.2 s. The fix was a
deterministic, heavy-tailed linger — an idle keepalive before teardown — in the `realistic`
texture. That retired the duration tell, and the next one surfaced immediately: the byte-size
distribution.

Each fix removes one tell and exposes the next, and the AUC falls over successive iterations.
It remains high while several tells are still open, which the scorecard reports rather than
hides. The known remaining tells, worst first, are byte-size distributions, connection-state
diversity (real traffic carries S1, SH, RSTO, and others where PacketForge is mostly SF), and
packet-size shape.
