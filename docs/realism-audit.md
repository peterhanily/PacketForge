# Gate 2 — the realism audit

PacketForge has always had **Gate 1: validity** — real Zeek must reproduce a capture, or
it's a bug. Gate 2 adds **realism, measured adversarially**: an independent classifier is
trained to tell PacketForge flows from *real* ones, and its cross-validated AUC is the
distinguishability statistic (a Classifier Two-Sample Test). 0.5 = indistinguishable to
that adversary; 1.0 = trivially told apart. Alongside the number, per-feature distances
and permutation importance **name the tell to fix** — because the point is a deterministic
fix → re-measure loop, exactly like the consistency gate.

The classifier only *measures and guides*; it never generates. Every fix stays
hand-authored and deterministic, preserving the no-ML-at-generation contract.

## Run it

```bash
pip install 'packetforge[realism]'          # scikit-learn, scipy, numpy
# a real reference is anything benign & multi-protocol, e.g. tcpreplay's smallFlows.pcap
packetforge scenario --env home --flows 700 --texture realistic -o synth.pcap
packetforge realism-audit --real smallFlows.pcap --synthetic synth.pcap
```

Output: the C2ST AUC, a kernel-MMD distance, per-service AUC (mix-invariant), and the
ranked tell list (feature, KS distance, permutation importance).

## What makes it rigorous (not junk)

- **Same pipeline both sides** — features come from Zeek `conn.log` for real *and*
  synthetic, so nothing separates on capture tooling.
- **Mix-invariance** — per-service AUC compares http-to-http, tls-to-tls, so the adversary
  can't cheat by counting "which set has more DNS."
- **Calibration is tested** — two captures from the *same* generator score ~0.5
  (`test_c2st_is_calibrated`: observed 0.49), and clearly different distributions score
  high (~0.96). A metric that always cried "distinguishable" would be worthless.
- **Scoped honestly** — the result is "indistinguishable *to a flow-feature gradient-boosted
  adversary on these features*", never an unqualified claim. The stronger, packet-bit
  adversary (nPrint + CNN) is the next rung once flow-level tells are driven out.

## The loop, demonstrated

First honest measurement against `smallFlows.pcap`:

| | C2ST AUC | duration KS | duration importance |
|---|--:|--:|--:|
| **before** | 0.998 | 0.459 | 0.117 (#1 tell) |
| **after the fix** | 0.997 | **0.268** | **0.017** (retired) |

The #1 tell was **flow duration**: real HTTP has a heavy tail (median 6.9s, max 192s);
ours were uniformly ~0.2s because the renderer packs the conversation tightly. Fix: a
deterministic heavy-tailed *linger* (idle keepalive before teardown) in the `realistic`
texture. That retired the duration tell — and the audit immediately surfaced the **next**
one (`l_orig_bytes`, the byte-size distribution). That is the ratchet: each fix retires a
tell and reveals the next, and you drive the AUC down over many iterations.

The overall AUC is still high (many tells remain) — honestly so. The value is the process:
a measured number and a named, fixable tell, every step. Remaining known tells, worst
first: byte-size distributions, connection-state diversity (real traffic has
S1/SH/RSTO/etc.; ours is mostly SF), and packet-size shape.
