# Gate 4: correspondence

Gates 1 to 3 ask whether a capture looks like real traffic. Gate 4 asks whether a capture is
warranted by the sources it was built from. This document covers what the gate checks, how to read
a result, and what a pass does not mean.

## The gap the other gates cannot reach

| Gate | Question | Instrument |
|---|---|---|
| Validity | Does real Zeek reproduce what was rendered? | `zeek -r`, `tshark -z expert` |
| Realism | Can a classifier separate synthetic from real? | classifier two-sample test (C2ST) |
| Detection | Do detections behave the same on both? | Suricata and Sigma over both captures |

All three are measured in [validation.md](validation.md), and none says whether a capture depicting
a named real incident matches that incident. A capture can be byte-perfect under Zeek,
indistinguishable under a C2ST, and still be a fabrication.

Sample 18 is the worked example. It passed all three gates, and when the victim's technical
post-mortem landed four days later it scored about 1 of 20 on substantive network facts. The
sources were not the problem: invented detail and evidence-backed detail were rendered at the same
fidelity, with nothing separating them, so a reader's default was to treat all of it as evidenced.
The per-fact scoring is in [exploitgym-postmortem-delta.md](exploitgym-postmortem-delta.md).

## Two modes

- **Emulation.** Something was actually run, so ground truth is the executor's own log. Samples 01
  to 17 work this way and Gate 4 is vacuous for them.
- **Reconstruction.** Nobody ran anything. The referent is someone else's incident, seen only
  through prose, so no ground truth exists. What exists is a warranted claim set.

Samples 18 and 19 reconstruct the same July 2026 intrusion from different source bases. Each ships
`RECONSTRUCTION.md`, not `GROUND_TRUTH.md`, because the old name licensed rendering a guess at the
same fidelity as an entailment.

## What the gate checks

A claim set (`flows/*.claims.yaml`) records what each source says: one claim per row with a stance,
a quoted span, and the flow ids it licenses. `packetforge warrant` checks it against the rendered
flows in both directions.

- **Forward licence.** Every rendered flow cites a claim that licenses it, or is declared
  illustrative.
- **Backward coverage.** Every claim is rendered, or declared unmodelled with a reason. This
  catches a claim sitting in a source, unrendered and unremarked.
- **Quantity.** Floors and ceilings are measured from the wire, never from flow names, so renaming
  a flow cannot move `failed-flow-fraction`. A declared gap suppresses its own quantity check: the
  failure being prevented is silent under-rendering.
- **Conflict.** No flow may assert resolution of something a source explicitly left open.
- **Sourcing.** Citations are required where the stance demands one and forbidden where it does
  not. A flow resting on a third party's preliminary statement about another organisation is
  flagged.
- **Content.** A claim may carry `expects` predicates over the flows it licenses: a dotted field
  path mapped to a literal or a regex. Without these, licensing is flow-id bookkeeping.

Below the claim level, individual fields carry markings. The unit is the value a reader would check
in a Zeek log, not the flow, addressed as `<flow_id>.<dotted.path>`. Each marking carries an
ICD 203 class (observed, judgment, assumption or fabricated), a NASA-STD-7009B pedigree level and a
PAV derivation verb. Unmarked fields default to fabricated, so forgetting to mark fails safe.
Aleatoric fields are excluded: source ports, jitter and segment sizes vary on any real network, so
any plausible draw is fine.

Provenance also travels inside the capture. `warrant --pcapng` writes a per-packet comment naming
the flow, the claim licensing it, and that flow's field-class mix.

```
$ tshark -r samples/19-openai-hf-exploitgym-v2/storyline.provenance.pcapng \
    -T fields -e frame.comment -c 3
SYNTHETIC | flow=v1_dns_hub | claim=P01/HF2 observed | fields 5J/6F/2-
SYNTHETIC | flow=v1_dns_hub | claim=P01/HF2 observed | fields 5J/6F/2-
SYNTHETIC | flow=v1_tls_hub_fetch_malicious_dataset | claim=P01/HF2 observed | fields 6J/9F/2-
```

Zeek reads pcapng through libpcap and ignores block options, so both encodings yield the same 104
connections, and a capture separated from its manifest still says what it is.

A claim set may also pre-register predictions: what the render commits to beyond its sources, each
with a probability and a pre-declared baseline. `warrant --score-key` scores them against a later
source with a log score of `100 * log2(p_outcome / baseline)`, mean Brier, and the Murphy
reliability, resolution and uncertainty decomposition.

## Reading a result

```
$ packetforge warrant --claims flows/openai-hf-exploitgym-v2.claims.yaml \
                      --flows flows/openai-hf-exploitgym-v2.yaml
GATE 4 — correspondence  (July 2026 autonomous-agent intrusion at Hugging Face (reconstruction v2), cutoff 2026-07-29)
  mode                     reconstruction
  flows                    104
  claims                   31
  claims_rendered          24
  claims_unmodelled        7
  claims_accounted         31
  claims_unaccounted       0
  flow_stance_mix          {'observed': 104}
  network_facts            1579
  field_class_mix          {'observed': 32, 'judgment': 587, 'assumption': 0, 'fabricated': 755, 'aleatoric': 205}
  epistemic_surface        619
  sourced_fraction         0.0203
  content_checked_flows    55
```

The run then prints the census tail, ten INFO lines for the declared gaps, and the verdict.

```
  VERDICT: PASS (0 fail, 0 warn, 7 declared gaps) — 2.0% of network facts are sourced
```

Read the census before the verdict. 32 of 1579 network facts appear in a cited source, 619 are
epistemic (facts a fuller account could show to be wrong), and a claim asserts something checkable
about 55 of the 104 flows. The seven declared gaps name what the capture cannot carry, such as an
eleven-node pod fleet, a control-plane fact outside this capture's vantage (the point where the
sensor sits). The manifest is [CLAIMS.md](../samples/19-openai-hf-exploitgym-v2/CLAIMS.md).

Sample 18, built from the two disclosures available before the post-mortem, fails.

```
  [resolves-open-question] C12 is flagged by HF1 as NOT established, but flows ['s5_db_answer_key', 's6_tls_exfil'] render it as fact: Whether partner or customer data was affected was NOT established at the time of disclosure.
  [floor-violated] C06: source gives a floor of 172800 capture-span-seconds; the artifact has 336.5. Quote: "moved laterally into several internal clusters over a weekend"
  VERDICT: FAIL (19 fail, 3 warn, 4 declared gaps) — 1.3% of network facts are sourced
```

Each finding corresponds to an error the post-mortem later confirmed. The four unlicensed flows are
the four fabrications, eight of the ten unaccounted claims are the eight substantive misses, and
`resolves-open-question` is the invented exfiltration. The check fires from the sources sample 18
already had, on the day it was built.

## What CI asserts

CI runs the gate on both reconstructions. Sample 19 must pass and sample 18 must fail: sample 18 is
kept as the "before" artifact, so a pass on it would mean it had been quietly edited. A test
regenerates `CLAIMS.md` and `CLAIMS.json` from each claim set and asserts byte identity with the
shipped files, so the manifest cannot drift from the artifact. Another asserts that running the
gate leaves the rendered capture byte-identical: Gate 4 is metadata and never touches a packet.

## Where the design was attacked

Three attacks worked before they were closed. A claim set with no sources, marking every field
observed, reported as 100% sourced, so a field can no longer be better-sourced than the claim it
cites. Sample 18's findings were laundered into a pass with boilerplate `unmodelled_reason` strings
and blanket `illustrative_flows`, so a claim set that is mostly gaps or reuses a gap reason
verbatim is now caught. Every TCP port in sample 19 was repointed to 1337 and every hostname
blanked, and the unchanged claim set still passed, so `expects` predicates now pin the literals the
sources name.

## Prior art

Claim-level evidentiary warranting is mature in intelligence analysis (ICD 203 and ICD 206),
digital forensics (the Casey C-Scale, CASE), assurance cases (SACM and GSN) and natural-language
generation attribution. It is absent from the synthetic-data field, where warranting is
dataset-level and the record-level work relates a record to a reference distribution rather than to
evidence, so the vocabulary here is adopted rather than invented. The cautionary case is MITRE
Attack Flow: 39 of 40 published flows cite sources at document level, 0 of 934 actions cite a
source, and 7.4% of actions carry any confidence value. That is what an optional field becomes.

## The limit

Gate 4 does not make a reconstruction right. It makes the artifact stop misrepresenting which parts
are which. A capture that passes can still be wrong about the incident, but it can no longer be
wrong silently, and its unmodelled list says where to look.

- **Register anchoring.** The backward check asks whether every claim written down is accounted
  for, never whether every claim the source makes was written down. Deleting an inconvenient claim
  still turns a fail into a pass with no packet changes. The defence is process: extract the
  register in a commit that touches no flow YAML, before the storyline exists.
- **What a pass means.** A pass says the accounting is coherent and the `expects` predicates hold,
  not that the capture is a correct account of the incident. That is why no verdict is reported
  without the sourced fraction beside it.
- **Source hashes.** The `sha256` recorded per source is of the retrieved prose, and nothing
  verifies it. There is no retained copy and no verify command, so it is a provenance record.
