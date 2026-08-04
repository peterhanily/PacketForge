# Realism ratchet history

This file records how the C2ST AUC of the matched synthetic analog fell from 1.0 to 0.974 across
five conditioning passes. It is a record of what changed and when. The current measured numbers
live in [validation.md](../validation.md), not here.

## How to read the numbers

A **C2ST** (classifier two-sample test) trains a classifier to separate real flows from synthetic
ones and reports its AUC. 0.5 means the classifier cannot tell the two sets apart, and 1.0 means
they separate trivially. PacketForge runs a 5-fold cross-validated gradient-boosted C2ST over
per-flow features taken from real Zeek logs, and reads the feature importances to find the tell
that is carrying the classifier. **MMD** is the kernel maximum mean discrepancy between the two
feature distributions, so it measures distance rather than separability.

| Pass | Conditioning added | C2ST AUC | Kernel MMD |
|------|--------------------|:--------:|:----------:|
| 1 | population defaults | 1.0 | 0.17 |
| 2 | reference window, TTL, timing | 0.99 | 0.11 |
| 3 | conn_state histogram | 0.987 | 0.11 |
| 4 | per-service originator bytes | 0.978 | 0.10 |
| 5 | joint per-flow cloning | 0.974 | 0.077 |

## Pass 1: population defaults

The generator emitted a single TCP window value on every flow and sent uniformly small packets.
Close to 100 percent of connections closed as `SF`, Zeek's conn_state for a flow that established
and closed normally, and no IDS alerts fired at all. Each of those is a categorical tell: a value
real traffic never takes. The pass replaced the constant window with a per-OS population and gave
packet sizes a heavy tail. It added a real mix of failures (`S0`, `REJ`, `RSTO`) and took the
benign alert rate from 0 to roughly 205 per hour. AUC stayed at 1.0 and MMD landed at 0.17.

## Pass 2: reference-conditioning

The top features were `first_window` and `ia_mean`, the SYN window value and the mean inter-arrival
time. The analog began drawing its SYN window, TTL and packet timing from the reference's measured
populations instead of the generator's defaults. Both features fell out of the ranking and the top
feature importance dropped from about 0.37 to under 0.03, so no single tell carried the classifier.
AUC moved from 1.0 to about 0.99 and MMD from 0.17 to 0.11.

## Pass 3: connection-state mix

The top feature was `cs_REJ`, the share of connections the server refused. The analog now folds the
reference's full Zeek conn_state histogram onto the states it can render, reproducing both the
established-versus-failed split and the S0:REJ failure ratio. `cs_REJ` dropped out of the ranking
entirely. AUC held at 0.987 and MMD held at 0.11. The tells that surfaced next were one family:
per-flow originator byte volumes (`l_orig_bytes`, `l_orig_ipb`, `orig_bpp`).

## Pass 4: originator byte volumes

The analog began measuring the reference's per-service originator-byte distribution and growing
each flow toward a drawn target using protocol-legal content: TLS client application data, and for
HTTP a browser-sized cookie or, past a header line's worth, a request body. No filler that a parser
would reject was added, so every flow still reproduced under real Zeek with zero weirds. The
`orig_bytes` marginal went from flat (about 270 bytes on every TLS flow) to tracking the reference
across the full tail, median 2607 against 2642 and p90 31428 against 31441. AUC moved from 0.987 to
0.978 and MMD from 0.11 to 0.10. The next tells were within-flow timing (`ia_std`, `ia_burst`) and
packet-count structure (`l_orig_pkts`, `l_pkt_ratio`).

## Pass 5: joint per-flow cloning

Conditioning each marginal independently decorrelates features that co-vary in real traffic. Draw a
flow's mean inter-arrival from one distribution and its packet count from another and some flows end
up with implausible durations. This pass replaced the four point-fixes with one step: each synthetic
flow reproduces a single reference flow's bytes, packet counts, duration and conn_state together.
Within-flow packet timing is drawn from a mean-preserving lognormal so `ia_burst` matches. Each
flow's effective segment size is set to the reference's bytes per packet, because real captures are
taken above NIC offload and a large transfer arrives as a few large segments. The cloning is
retransmit-free, so byte-exact validity holds. AUC moved from 0.978 to 0.974 and MMD from 0.10 to
0.077. The benign alert rate, which inflated durations had held at 98 per hour, returned to about
205 per hour against the reference's 217 per hour.

## The AUC is a maximum over features

The classifier reports the best separation it can find, so the headline AUC tracks whichever tell is
strongest. Retiring a weaker tell removes it from the feature importances without moving the number.
Pass 3 is the clear case: `cs_REJ` disappeared from the ranking and the AUC stayed at 0.987. The
feature importances are the worklist and the AUC is the score, and the two move on different
schedules. A pass that changes nothing visible in the headline can still have removed a real tell.

## What 0.5 would mean

The same adversary, run on real captures, traces a spectrum that puts the synthetic number in scale.

| Comparison | C2ST AUC | What it measures |
|------------|:--------:|------------------|
| Random split of one capture | 0.46 | the null: one distribution |
| First half against second half | 0.67 | within-source drift |
| Two distinct real captures | about 0.95 | cross-capture distance |
| Synthetic against the reference | 0.974 | where the analog sits |

Two distinct real captures separate easily because they are different distributions: different
networks, times, host populations and service mix. An absolute 0.5 bar is therefore reachable only
by replaying one specific capture, which is the opposite of generating. The floor for a generator of
novel traffic is the real-vs-real number, so the scorecard scores `c2st_auc` against a measured
`real_baseline_auc` and reports the band it was averaged over. Kernel MMD more than halved across
the five passes, 0.17 to 0.077, which is the distributional evidence that the two sets converged.
