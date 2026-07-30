# Gate 4 — warranting a reconstruction

> **Status: all four phases implemented 2026-07-30.** See §12 for what was built versus what
> this document originally proposed, including one deliberate deviation and one hole the work
> opened and then closed.
>
> Measured outcome: **sample 18 FAIL (19 findings, 1.7% of its network facts sourced), sample 19
> PASS (0 findings, 7 declared gaps, 2.6% sourced)**, with zero change to any rendered byte.
> 40 warrant tests; 398 in the suite overall.

## 1. The problem

PacketForge has three gates and they all answer the same kind of question.

| Gate | Question | Where |
|---|---|---|
| Validity | Does real Zeek reproduce what we rendered? | `validation/roundtrip.py` |
| Realism | Can an adversary tell synthetic from real? | `realism.py` (C2ST vs a real-vs-real floor) |
| Detection | Do detections behave the same on both? | `realism_detection.py`, `coverage.py` |

All three warrant **realism** — *is this like real traffic?* None warrants **correspondence** —
*is this like the incident it claims to depict?* That gap didn't matter for samples 01–17, which
depict technique classes with no external referent. It mattered entirely for sample 18, which
scored ~1 of 20 on substantive network facts against the post-mortem that followed four days
later — not because the sources were thin, but because invented detail and evidence-backed detail
were rendered at identical fidelity, with nothing in the artifact distinguishing them.

Worse, samples 18 and 19 bypass all three gates: their manifests are hand-written and `cp`'d by
`make-samples.sh`, never touching `Intrusion`, `write_ground_truth`, or `scorecard.py`. The one
sample class needing the most instrumentation had the least.

**The category error to name explicitly.** Zeek and tshark certify well-formedness and dissector
agreement — not warrant. NIST IR 8354 (Digital Investigation Techniques) makes the point that
digital processes fail systematically rather than randomly, so a passing gate measures *the
generator*, not *the storyline*. Reading "18/18 green" as evidence of correctness is exactly how
this project shipped a fully validated artifact that scored ~1 of 20 on substantive facts. Gate 4
exists because Gates 1–3 cannot, even in principle, say anything about correspondence.

## 2. What the field actually does

A six-area prior-art sweep produced one finding that determines the whole design:

> **Nothing in the synthetic-data field annotates individual generated records with the evidence
> that licensed them.** Warranting is dataset-level everywhere. The three places record-level
> annotation does exist — Alaa et al.'s α-Precision/Authenticity, Data-IQ/Data Maps, per-row DCR —
> all annotate a record's relationship to a *real reference distribution*, never to *evidence*.

Claim-level evidentiary warranting is mature, but only in fields that don't generate artifacts:
intelligence analysis (ICD 203/206), digital forensics (Casey C-Scale, CASE), assurance cases
(SACM/GSN), and NLG attribution (AIS, FActScore, TRAM). **So this is a transplant, not an
incremental metric** — which also means the vocabulary should be adopted, not invented.

The cautionary case is MITRE Attack Flow: across its published corpus, 39/40 flows cite sources at
*document* level, **0 of 934 actions cite a source**, and only 7.4% of actions carry any
confidence value. That is what happens when the field is optional. Gate 4 must be mandatory and
enforced by the existing determinism-plus-gate mechanism, or it will end up the same way.

## 3. Two modes, and a naming bug

Two different things are currently called the same thing:

- **Mode E — execution-grounded.** Something was actually run; ground truth is the executor's own
  log. This is how the field does it (Atomic Red Team, CALDERA, ATT&CK Evaluations, OTRF
  Security-Datasets). PacketForge approximates it through reference-conditioning against
  `realcap/` and the JA3/C2 transfer proofs. Ground truth genuinely exists.
- **Mode R — reconstruction.** Nobody ran anything; the referent is someone else's incident
  observed only through prose. **No ground truth exists.** What exists is a warranted claim set.

`samples/18-openai-hf-exploitgym/GROUND_TRUTH.md` is not ground truth. Renaming it in Mode R
(`RECONSTRUCTION.md` / `CLAIMS.json`) is a one-line change with real force: the current name is
what licensed rendering guesses at the same fidelity as entailments.

## 4. The vocabulary — adopted, not invented

| Concern | Adopt | Values |
|---|---|---|
| Carrier for field-level marking | **STIX 2.1 `granular_markings`** | `selectors: []` — JSONPath subset, dotted names + `[n]`. e.g. `flows.[3].l7.http.user_agent` |
| Epistemic class of a field | **ICD 203 Standard (3)** + one addition | `OBSERVED` / `ASSUMPTION` / `JUDGMENT` / **`FABRICATED`** |
| Derivation strength | **PAV verbs** | `retrievedFrom` (verbatim) · `importedFrom` (restated) · `derivedFrom` (inferred) · `sourceAccessedAt` (consulted, nothing taken) |
| Traceability level | **NASA-STD-7009B Input Pedigree** | L4 real-world system → L0 insufficient evidence. Grades *traceability*, not accuracy — assessable without knowing the truth |
| Source grade × corroboration | **Admiralty / AJP-2.1**, two axes, never fused | A–F reliability × 1–6 credibility |
| Citation record | **STIX `external-reference`** | `source_name` + `url` + `hashes.SHA-256` of the retrieved prose |
| Likelihood axis | **MITRE Attack Flow's `confidence`** (STIX integer 0–100, published terms) | Speculation 0 · Very Doubtful 10 · Doubtful 30 · Even Odds 50 · Probable 70 · Very Probable 90 · Certainty 100 |
| "Cannot be judged" | **STIX**, not MISP | a non-numeric sentinel. MISP gives Admiralty `f`/`6` a `numerical_value: 50`, so anything that averages silently converts *ignorance* into *moderately credible* |

**Granularity: the field, not the flow.** The unit must be *the value a reader would check in
Zeek's `conn`/`dns`/`http`/`ssl` output*. Splunk's `attack_data` labels a whole Sysmon log as
"the T1003.001 artifact" with no per-event label, which is why those datasets can answer *did my
search fire?* but not *what fraction of what I claimed is actually there?* A manifest that marks a
whole pcap — or even a whole flow — is decorative. This is a correction to my first draft, which
marked at flow level.

Two additions the research argued for that I'd adopt:

- **`FABRICATED` is the fourth class and the default.** Following VERIS's absence discipline — a
  blank marking must never read as a positive claim — anything unmarked defaults to the *weakest*
  class, so forgetting to mark fails safe rather than silently asserting.
- **Aleatoric vs epistemic** as an orthogonal flag (Hüllermeier & Waegeman). Aleatoric = the real
  network genuinely varies and any plausible draw is fine (inter-arrival jitter, ephemeral ports,
  TLS randoms). Epistemic = the source didn't say and we chose. **Only epistemic detail can be
  wrong when a post-mortem lands.** This one split separates most of sample 18's misses from its
  one hit, and it's what makes a post-hoc score meaningful rather than punishing us for sequence
  numbers.

The SHA-256-of-source detail is not academic here: OpenAI's post **was edited on 2026-07-28**,
after sample 18 was built against it. Hashing retrieved prose is the difference between "the
vendor said X" and "here is the document, and here is proof it has since changed."

Three conditions on adopting any of this, each from a documented failure:

- **If you cannot write a one-paragraph rubric for each value, do not ship the field.** VERIS
  ships `confidence` as a bare `["High","Medium","Low","None"]` enum with no per-value guidance
  anywhere in the schema; STIX's 0–100 integer is calibrated only by a conversion appendix, with
  the documented result that one producer's 70 is another's 90.
- **Write the interaction rule before anyone needs it.** Two nominally independent axes are not
  applied independently in practice — empirical work on the Admiralty code finds analysts cannot
  integrate reliability and credibility when the two disagree. Decide now what
  *(vendor-post-mortem, contradicted-by-another-source)* means.
- **Use half-open intervals and state the convention.** ICD 203's own bands share every boundary
  value between adjacent cells, vary from 10 to 25 points wide, and span 01–99% so certainty and
  impossibility are unrepresentable.

Implementation note: **store the number, render the words.** Keep STIX `confidence` 0–100 as the
stored value and derive the ICD 203 phrasing from it at manifest-render time, rather than storing
prose — otherwise the words and the number drift, and only the words get read.

## 5. The checks

Bidirectional, plus three more:

1. **Forward — licence.** Every rendered flow cites a claim that licenses it, or is declared
   `illustrative`. *(ICD 206's SRC trigger rule, restated: any field classed `OBSERVED`, or whose
   `ASSUMPTION`/`JUDGMENT` rationale names a source, MUST carry a citation. Fields classed
   `FABRICATED` MUST NOT — that asymmetry is itself checkable.)*
2. **Backward — coverage.** Every claim is rendered, or explicitly declared unmodelled with a
   reason. This is the check that catches "17,000 events" sitting in the source, unrendered and
   unremarked.
3. **Quantity.** Claims carrying `floor`/`ceiling` are measured against the artifact. **A declared
   gap suppresses its own quantity check** — the failure mode being prevented is *silent*
   under-rendering, not declared under-rendering. The gap list is the deliverable.
4. **Conflict.** No flow may assert resolution of something a source explicitly left open
   (`stance: source-unresolved`).
5. **Sourcing.** Flows resting only on a self-described *preliminary* claim by a third party about
   someone else's infrastructure are flagged, not silently accepted.

And one honest refusal: some units **cannot be measured from a capture at all**. An action count is
not a flow count; cluster identity is not on the wire; credential counts aren't observable in
encrypted traffic. Naming such a unit isn't an error — it's a statement that the claim belongs in
the manifest. Silently converting an action count into a flow count is the error, and it is
precisely what sample 18 did with "more than 17,000 recorded events" → 16 flows.

### Two prohibitions on the manifest itself

- **Never transpose the conditional.** ENFSI Guidance Note 1 requires reporting the probability of
  the findings given the propositions, never the reverse. A PacketForge manifest must never assert
  or imply `P(storyline | packets)` — the packets were *generated from* the storyline, so any such
  claim is circular by construction. This rules out any "the capture confirms…" phrasing.
- **Never buy credibility by dropping a proposition level.** ENFSI Guidance Note 2: where
  activity-level evidence is absent, confident source-level detail reads to the reader as strong
  support for the activity. Rendering byte-exact session detail while the actual open question is
  whether the actor performed the action at all manufactures unearned credibility.

### The headline census

Print the provenance ratio at the top of the manifest, before anything else, the way ATT&CK
Evaluations publishes citation coverage across its reference tables:

```
41 network facts:  9 OBSERVED · 12 JUDGMENT · 20 FABRICATED
31 source claims:  24 rendered · 7 declared unmodelled · 0 unaccounted
```

A reader should not have to reconstruct that ratio. It is the first thing that tells them what
kind of artifact they are holding.

## 6. Evidence it works

A prototype implementing §5 was run against both samples using claim sets built from their actual
source corpora.

**Sample 18** (claims from HF's 07-16 disclosure + OpenAI's 07-21 post): **FAIL — 18 failures, 2 warnings.**

```
flows 16 · claims 20 · claims_accounted 10/20 · failed_flow_fraction 0.0 · span 0.09h
flow_stance_mix {UNLICENSED: 4, entailed: 9, strongly-implied: 2, source-unresolved: 1}

[unlicensed-flow]        s1_dns_deaddrop, s1_tls_stage2_pull, s3_ssh_node, s6_dns_exfil
[unaccounted-claim]      C01 C02 C03 C07 C08 C10 C11 C13 C14 O04   (10 of 20)
[resolves-open-question] C12 — source said customer-data impact was NOT established;
                              s5_db_answer_key + s6_tls_exfil render it as fact
[floor-violated]         C06  weekend → floor 172,800s; artifact has 336s
[floor-violated]         C11  decoy activity → floor 0.2 failed-flow fraction; artifact has 0.0
[floor-violated]         C13  "the compromised nodes" → floor 2 hosts; artifact has 1
[third-party-preliminary] s5_dns_proddb rests on OpenAI's self-declared preliminary claim
                          about HF's infrastructure — render the attempt, not the outcome
```

Every one of those corresponds to an error the post-mortem later confirmed. The four unlicensed
flows are the four fabrications. Eight of the ten unaccounted claims are the eight substantive
misses. The `resolves-open-question` hit is the fabricated exfil. **The check fires on day one,
from the sources sample 18 already had.**

**Sample 19** (claims from the 07-27 post-mortem): **PASS — 0 failures, 0 warnings.**

```
flows 104 · claims 31 · claims_accounted 31/31 (24 rendered, 7 declared unmodelled)
flow_stance_mix {entailed: 104} · failed_flow_fraction 0.25 · span 54.12h
```

The seven declared gaps are the honest ones: the eleven-node fleet (control-plane fact, not
visible at this vantage), the 181 mesh enrolments (mostly off-camera), the 17,600-action count
(not a flow count), Stage 1, the allowlist-rejected SSRF (*a failure with no wire trace — by
construction unrenderable*), and the cross-provider credential replay.

## 7. Feasibility, measured

Three things checked against the code rather than assumed:

- **Adding a provenance field cannot change rendered bytes.** Nothing hashes or serialises the
  whole `Flow` model — the only `model_dump` in the compile path is on `flow.expect`. `Flow` is
  `extra="forbid"`, but an optional field with a default is backward-compatible, and
  `FlowSet._check_version` compares *major* version only, so this is a `0.1 → 0.2` bump.
  `ingest/evidenceforge.py` is unaffected. **Needs a determinism test pinning byte-identity.**
- **Provenance can travel inside the capture.** A pcapng EPB carrying `opt_comment` is read back
  by tshark as `frame.comment` (verified). scapy 2.7 ships `PcapNgWriter`/`wrpcapng`.
- **pcapng does not break the gate.** Converting sample 19's campaign capture to pcapng and
  re-running the full gate: **0 weird, 0 reporter, 0 tshark errors/warnings, and Zeek derives the
  identical 104 connections.**

That third result matters more than it looks. It means the honesty markers can stop being crude —
today a bare `capture.pcap` separated from its manifest reveals itself only through RFC 5737
addresses and AWS `…EXAMPLE` keys. With in-band pedigree comments, a detached capture carries its
own provenance into Wireshark.

## 8. Anti-patterns to design against

Every one of these is documented in a system that tried and failed at this.

1. **Citing at plan granularity.** SCYTHE's Conti emulation plan carries *one* source line for a
   ~40-step chain, so evidenced beats and invented connective tissue are typographically
   identical. Atomic Red Team is worse by construction: its model sets `extra="forbid"` with no
   citation field, so per-test sourcing cannot be added. A single storyline-level `source:` key is
   not a fix — which is exactly what samples 18/19 have today.
2. **Hedging only in the narrative layer.** MITRE CTID's `Intelligence_Summary.md` is meticulously
   hedged with per-claim references; none of it survives into `APT29.yaml`, whose commands are
   stated flatly. Any tool ingesting the YAML — the stated purpose — sees confident procedure. If
   confidence lives in a README rather than in the IR, the same erasure happens.
3. **Opt-in labelling.** Marking only the uncertain parts is *actively* misleading, because it
   teaches the reader that unmarked means checked. ENFSI-BPM-FIT-01 §13.1 states the operative
   psychology: readers assume everything is factual "unless otherwise stated by the author."
   Default must be the weakest class, and coverage must be provably total.
4. **A detachable manifest.** A `GROUND_TRUTH.md` that can be separated from the pcap means the
   pcap circulates as an unqualified claim. Do not rely on co-location, a filename convention, or
   a repo directory to carry epistemic status. *(This is why in-band pcapng provenance moves up
   the plan.)*
5. **Treating an ATT&CK technique as procedural evidence.** Only ~43% of Enterprise techniques
   appear in any documented campaign; median campaign↔intrusion-set Jaccard overlap is 10%.
   Structured CTI describes *what* adversaries do, not enough of *how*. A manifest row reading
   `T1071.001` and nothing else has asserted essentially nothing about the wire — and samples
   18/19 lean heavily on exactly that.
6. **Implying environment specificity the sources don't support.** 97.6% of ATT&CK software
   objects lack version indicators. Rendering a precise TLS version, cipher, server banner, or
   User-Agent at the same fidelity as an evidence-backed hostname is this error. **Sample 19 does
   this**: `python-requests/2.32.3`, `aws-sdk-go/1.55.5 (go1.22.5; linux; amd64)`, `nginx`,
   `mongo` segment counts — every one is authored, none is sourced, and nothing in the artifact
   says so. Under Gate 4 they would all be classed `FABRICATED`, which is the honest answer.
7. **Labelling from the intended schedule rather than from observed evidence.** CIC-IDS2017 labels
   a flow malicious because it fell inside an attack time-window — "a resulting flow's content and
   characteristics are not verified" (Engelen et al.). That is structurally this project's failure:
   what the storyline *intended* is rendered at the same fidelity as what a source *supports*.
8. **A manifest a README could satisfy.** CIC-IDS2017 ticks "Labelled Dataset" and "MetaData" in
   its own 11-criterion framework by pointing at a prose section and a day-to-attack-name table.
   If PacketForge's manifest can be satisfied by prose, it will be — samples 18/19's hand-written
   manifests are exactly that today.
9. **Documentation that drifts from the artifact.** CIC-IDS2017's published time windows did not
   reproduce its own labels, and nobody noticed for four years. For a deterministic generator this
   is trivially testable and should be CI: **regenerating from the published storyline must
   reproduce the shipped manifest byte-for-byte.**
10. **Absence of a label read as evidence of benignity.** LANL, CIC-IDS2017's fall-through rule,
    CIC-UNSW-NB15's "any remaining flows will be labeled benign" — all collapse *not asserted* into
    *asserted benign*. Adopt CTU-13's fix: an explicit `unknown` class. They are different claims
    and must be different values.
11. **Shipping pipeline artifacts as phenomena.** CICFlowMeter terminates a TCP flow on the first
    FIN, in violation of RFC 793; the leftover ACK/FIN "appendices" become their own flows, inherit
    the attack label, and make up 25.9% of CIC-IDS2017 — and models then learn to classify them on
    header-length features with no semantic connection to the attack. PacketForge manufactures
    comparable things: retransmit synthesis, VXLAN mirror re-stamping, re-parse artifacts. Each
    must be traceable as pipeline-origin rather than incident-origin.

### 8a. A measured leak worth fixing (new finding)

IDEVAL's attack packets carried TTL 253/126 because attack and background traffic were synthesised
on different machines — so seven attack types were detectable by a field nobody intended to be part
of the attack. PacketForge has two code paths too: storyline YAML versus `compose.py`. I tested
sample 19's SYNs for the same hazard:

```
              TTL                      TCP option order
attack   n=19  64: 100%                Linux order: 100%
ambient  n=205 64: 62%, 128: 38%       Linux 62%, Windows 38%
SYN window: 64240 for 100% of both.  No value appears in attack that is absent from ambient.
```

**Not IDEVAL's bug** — there is no impossible value, no attack-only fingerprint, and the substrate
comes from one shared code path. **But the same class of hazard is present:** `TTL == 128` implies
*not attack* with certainty in this capture, because storyline flows are hand-set `src_os: linux`
while ambient draws from an 82/18 Linux/Windows mix. A model trained here learns "Windows ⇒
benign", which is false in general.

It is defensible — the compromised hosts really are Linux pods and nodes — but it should be
*measured*, not assumed. Two checks, the second borrowed rather than invented:

- **Substrate-only classifier.** Reusing `realism.py`'s existing machinery: a classifier given
  only TTL, SYN window, option order and IP-ID behaviour — all storyline-semantic fields removed —
  must not separate attack from ambient better than the OS population alone predicts.
- **Mahoney & Chan's r-statistic.** Their 2003 analysis of IDEVAL is the published method for
  exactly this. For each header field, count distinct values *r* and watch how it grows with
  traffic volume: in a real capture *r* keeps growing, in a synthetic one it saturates. Where
  `r_synthetic << r_real` for a field, that field is a generator artifact rather than a
  phenomenon. Their demonstration is the cautionary number: a detector reading **one byte** of the
  source IP achieved 45% detection on IDEVAL — and 0% once real traffic was mixed in. PacketForge
  already collects real reference captures in `realcap/`, so both the per-field *r* comparison and
  their mixing test are available today.

This is a Gate 2 concern, not Gate 4 — worth logging separately.

## 9. Phased delivery

**Phase 1 — the manifest and the check (no schema change). ✅ DONE 2026-07-30.**
Delivered as `src/packetforge/warrant.py` (≈430 lines), `packetforge warrant`,
`_correspondence_gate` in `scorecard.py` with two CI regression metrics, claim sets in
`flows/*.claims.yaml`, generated `CLAIMS.md`/`CLAIMS.json` per Mode-R sample, and
`tests/test_warrant.py`. Verified: 381 tests pass (was 360), ruff clean, all 24 captures still
pass the Zeek/tshark gate, and `git status` shows **no pcap or Zeek-log churn** — the metadata
layer touched nothing. Original description follows.

`warrant.py` + a `claims.yaml` per
Mode-R sample + `packetforge warrant` CLI verb + `gates.correspondence` in `scorecard.py`
(alongside validity/realism/detection, feeding `honest_gaps`). Rename Mode-R manifests. Ship the
census and the gap list *above* the kill chain. **~400 lines, no bytes change, no schema bump.**
Delivers everything in §6.

Adopt the ATT&CK Evaluations reference-table row shape for the manifest, because it splits the two
things samples 18/19 conflate — the *beat* and the *observable*:

| beat id | storyline beat | rendered observable (exact Zeek field values a reader should find) | flow ids | provenance class | source refs |
|---|---|---|---|---|---|

Stable beat ids matter: they are what lets a later post-mortem be scored row by row.

**Phase 2 — per-field marking in the IR.** `Flow.markings: list[GranularMarking]` with STIX
selectors; ICD 203 class + PAV verb + pedigree level per selector; `FlowSet.provenance` carrying
sources with SHA-256, the Source Summary Statement, and the claim register. Default-`FABRICATED`
for unmarked fields. Gate fails on dangling selectors, on `OBSERVED` without citation, and on
`FABRICATED` *with* one. **Schema `0.2`.** This is where the aleatoric/epistemic split earns its
keep.

**Phase 3 — in-band provenance and the publication-class gate.** pcapng output with per-flow
`opt_comment` carrying pedigree + claim id, so a detached capture still declares itself (§8.4).
Verified feasible in §7. And an **artifact-class gate**, following ENFSI §1.4: below an
evidence-coverage threshold, a storyline may ship only as an *illustrative exercise*, never as an
*incident reconstruction*. **The remedy for thin sourcing is downgrading the artifact class, not
adding hedging prose.** Sample 18, at 10 of 20 claims accounted, would have been refused the
"reconstruction" label and published as an exercise — which is what it actually was.

**Phase 4 — scoring.** Pre-register the claim set with probabilities; when a post-mortem lands,
`packetforge warrant score` reports a Metaculus-style **baseline log score**
`S = 100·log2(p_outcome / π_baseline)` with probabilities clipped to [0.01, 0.99], plus mean Brier
with the Murphy REL−RES+UNC decomposition and a reliability diagram. The log score is the unique
proper *local* rule, so a claim scores only on the probability assigned to what actually happened
— it punishes exactly this project's observed failure: confident assertion of invented detail.
Baselines must be pre-declared per claim (0.5 binary, 1/N for N-way, empirical base rate where one
exists — "HTTPS is the C2 channel" must not be scored against 0.5).

Phases 1 and 4 are the ones that would have changed the outcome. 2 and 3 are depth.

**The load-bearing precondition, independent of all of it:** stop hand-writing and `cp`-ing Mode-R
manifests. While samples 18/19 bypass `Intrusion`, `write_ground_truth` and `scorecard.py`, no gate
can constrain them, and the manifest will drift from the pcap exactly as CIC-IDS2017's published
attack windows drifted from its labels — undetected for four years. Generating the manifest from
the storyline, and asserting byte-identity in CI, is the cheapest item on this page and blocks
everything else.

**And a constraint on Phase 2+:** do not commit to a claim compiler until a *second* Mode-R
incident exists to prove the beat templates generalise. One sample is not a language.

## 10. What this does not fix

Metadata cannot invent the mesh-VPN phase. The blind re-run measured the ceiling of perfect
discipline at ~14 of 20 from the 07-23 corpus; the residual — the raw-socket cleartext beacon, the
HDF5 primitive, C2 scale off by 50× — was unknowable, and no schema changes that.

Gate 4's promise is narrower and worth stating plainly: **it does not make the reconstruction
right. It makes the artifact stop lying about which parts are which.** A capture that passes Gate 4
can still be wrong about the incident — it just can no longer be wrong *silently*, and its
unmodelled list will say where to look.

Two further limits, honestly:

- **It depends on honest authoring.** Nothing stops an author writing a claim that doesn't really
  license the flow beneath it. The check is a discipline aid and an audit trail, not a proof.
- **It is vacuous for Mode E.** Samples 01–17 have no external referent to correspond to; the gate
  should skip them rather than manufacture ceremony.

## 11. Decisions needed before any code

1. **Does the Flow IR carry this, or a sidecar?** The IR is described in `DESIGN.md` as the
   EvidenceForge contract. Provenance arguably belongs to it — for EF-sourced flows the warrant is
   strong and automatic ("derived from event X") — but it's a cross-project commitment. Phase 1
   deliberately avoids the question.
2. **Mandatory or optional?** The Attack Flow evidence says optional means unused. But mandatory
   in Mode E is ceremony. Proposal: mandatory in Mode R, absent in Mode E, and the mode is declared
   in the FlowSet.
3. **Is this repo the right home?** The transplant — record-level evidentiary warranting for
   generated artifacts — appears to be genuinely absent from the synthetic-data field. That may be
   worth writing up separately rather than burying in a PCAP generator.

## Sources

Prior-art sweep of 2026-07-29/30 across: public netsec datasets and their labelling critiques;
adversary-emulation systems; per-claim confidence formalisms (ICD 203/206, Admiralty/AJP-2.1,
STIX 2.1, MISP, PROV-O/PAV, Sigma, VERIS, datasheets-for-datasets); synthetic-data evaluation
(α-Precision/Authenticity, Data-IQ, DCR, NASA-STD-7009B, C2PA); IR/forensics reporting standards
(Casey C-Scale, CASE, hierarchy of propositions); and forecasting/scoring (Gneiting & Raftery,
Murphy decomposition, Good Judgment Project, Metaculus baseline scoring). Empirical results in
§6–§7 were produced locally against this repo.

---

## 12. What was actually built (2026-07-30)

All four phases shipped. Two things differ from the plan above, and one hole opened and closed
during implementation — recorded here rather than quietly reconciled.

### Delivered

| Phase | Delivered as |
|---|---|
| 1 — manifest + bidirectional check | `warrant.py`, `packetforge warrant`, `gates.correspondence` in `scorecard.py` (+2 CI regression metrics), `flows/*.claims.yaml`, generated `CLAIMS.md`/`CLAIMS.json`, `GROUND_TRUTH.*` → `RECONSTRUCTION.*` |
| 2 — per-field marking | STIX-style selectors, ICD 203 class + NASA pedigree + PAV verb per marking, aleatoric/epistemic split, default-`FABRICATED`, field census and epistemic surface |
| 3 — in-band provenance + class gate | `compile/pcapng.py`, `warrant --pcapng`, `artifact_class: reconstruction \| exercise` |
| 4 — scoring | `Prediction` register, `AnswerKey`, baseline log score + Brier + Murphy decomposition, `warrant --score-key` |

### Deviation: markings live in the claim set, not the Flow IR

The plan said `Flow.markings` at schema `0.2`. They went into `ClaimSet.field_markings` with
`<flow_id>.<dotted.path>` selectors instead. Reasons: the storyline YAML is the human-authored
artifact and 104 flows × ~12 marked fields would have made it unreadable; the claim set is already
the warranting layer; and the only consumer that needs provenance *inside* a `Flow` is an upstream
emitter producing it, which does not exist. Consequence: **no schema bump was needed and the Flow
IR is untouched**, which also means no commitment was made on the EvidenceForge contract. If an
emitter appears, `FieldMarking` moves onto `Flow` unchanged.

### The hole this work opened, and closed

Phase 1–3's checks are all *accounting* checks, and accounting alone is gameable. Declaring every
flow `illustrative` and the single claim `unmodelled` made a storyline about nothing pass with
**zero findings** — a bare `PASS` on an artifact with no sourced facts, which is exactly the
misleading-precision failure §5 says to avoid, reintroduced by the fix itself. Found by attacking
the gate rather than by a test.

Closed by two additions: a reconstruction must have at least one `observed` field and at least one
claim that reaches the wire (`nothing-sourced`, `nothing-rendered`), and **no verdict is ever
reported bare** — the CLI line and the manifest header both carry the sourced fraction, because a
green gate says the accounting is coherent, not that the capture is right.

### What the numbers actually say

| | sample 18 | sample 19 |
|---|---|---|
| verdict | FAIL, 19 findings | PASS, 0 findings |
| network facts | 174 | 1,221 |
| of which sourced | 3 (**1.7%**) | 32 (**2.6%**) |
| declared gaps | 4 | 7 |
| prediction score | mean log **−172.4**, 1 of 15 beat the prior | 6 registered, none resolved yet |

The sourced fractions are the honest headline. Neither capture is mostly evidence, and both now
say so on their face. That is the whole of what this delivers: it does not make a reconstruction
right, it stops the artifact concealing which parts are which.


---

## 13. What an adversarial audit found (2026-07-30)

Five independent reviewers were told to assume this work was theatre and to attack it. All five
returned *partly-theatre* with 38 findings between them. That was the right verdict on the tree
they saw. What follows is what they broke, what is fixed, and what is still true.

### Attacks that worked, and are now closed

| Attack | Result then | Result now |
|---|---|---|
| A claim set with **zero sources** marking every field `observed` | PASS, "100.0% of facts are sourced" | FAIL — `unsourced-marking`: a field cannot be better-sourced than the claim it cites |
| **Laundering** sample 18's 19 findings to a PASS with boilerplate `unmodelled_reason` + `illustrative_flows`, zero packet changes | PASS, 0 findings | FAIL — `mostly-unmodelled` + `boilerplate-gap-reason` |
| **Falsifying the capture**: every TCP port → 1337, every hostname blanked, unchanged claim set | PASS, 0 findings | FAIL, 30 findings — `expects` predicates on ten claims now pin the literals the sources name |
| `failed-flow-fraction` satisfied by **renaming flows** `denied` → `refused` | 0.25 → 0.11 with byte-identical output | measure is wire-state only; renaming changes nothing |
| pcapng timestamps **truncated** where pcap rounds | 936 of 2785 packets 1 µs early; Zeek logs differed | identical `conn`/`ssl`/`dns`/`http` from both encodings |
| A "prediction" every one of whose fields is already `observed` (X14 — the sole positive) | scored +71, headline "1 of 15 beat the prior" | `prediction-is-not-a-prediction`; register is 14, headline **0 of 14** |

Also fixed: `flow_facts` dropped explicitly-authored defaults (`conn_state: SF`); `aleatoric_fields`
short-circuited and silently voided explicit markings; the Murphy identity failed on any
probability with three decimals; `baseline` was unclipped and unrationalised, and one forward
prediction could never resolve false; `pedigree`/`derivation` were cited from NASA-STD-7009B and
PAV but enforced nowhere; an `exercise` scored differently but read identically; duplicate flow ids
and licensed-and-illustrative flows passed silently.

### What is still true, and is the honest limit

**The claim register is not anchored to the source.** The backward check asks *is every claim you
wrote down accounted for?* — never *did you write down every claim the source makes?* Deleting
inconvenient claims still turns a FAIL into a PASS with no packet changes. `expects` closes the
gap between the register and the packets; nothing closes the gap between the source and the
register. The only defences available are process, not code: extract the register from a source in
a commit that touches no flow YAML, before the storyline exists, so the git history shows it was
not fitted to the render. That is a rule, not a check, and it should be written down as one.

**"Sample 19 passes" therefore means something narrower than it sounds.** It means: the register
is complete and referentially sound, the ten claims carrying `expects` are satisfied by the flows
they license, and 55 of 104 flows have some asserted content. It does not mean the capture is a
correct account of the incident, and the manifest now says so above the fold.

### Not done

`sha256` of source prose is recorded and never verified — there is no retained copy to compare
against and no `verify-sources` command. It is a provenance *record*, not a check, and should be
described that way until one exists. Gate 4 is also still absent from `README.md`, `DESIGN.md`
and `capabilities.md`; it is discoverable only from the CHANGELOG, the sample READMEs and this
document.
