# ADR 001: Compile packets from a versioned Flow IR

This record captures the decision that set PacketForge's boundary with EvidenceForge. It was taken
before the first renderer was written, and it still describes the shipped architecture.

## Status

Accepted and implemented. The Flow IR, the compiler and the round-trip gate are in the tree.

Step 4 of the merge path below, the EvidenceForge-facing pull requests, is blocked on the
maintainer's explicit approval and has not been started. Nothing is pushed to EvidenceForge and no
comments are made on its issues without the repository owner's explicit approval. Such changes are
drafted in this repo for review first.

## Context

EvidenceForge generates logs from a canonical incident model. One event feeds every emitter, so two
emitters cannot disagree about a port, a hash or a timestamp. EvidenceForge issue #332 asked
whether the same model could also produce packet captures.

The open question was not how to write packets, since scapy does that. It was what PacketForge
should couple to, because that choice decides whether packets and logs can be proved consistent.
Three couplings were available: EvidenceForge's outputs, its internals, or a contract between them.

## Option A: log post-processor, coupled to outputs

PacketForge reads a finished EvidenceForge bundle (conn.log, dns.log, http.log, ssl.log and the
ground truth) and reverse-derives packets from the rows.

- **Gain.** No coupling to EvidenceForge internals. It works against any bundle that already exists
  and never touches the activity generator.
- **Cost.** Zeek logs are a lossy projection of the wire. http.log carries metadata but not the
  request bytes, ssl.log carries no application data, and nothing carries segmentation, so the tool
  must re-synthesize what the event already knew. Consistency becomes second-order (event to logs
  to capture) instead of logs and packets being siblings of one event.
- **Verdict.** Fastest to demo against real data, but it inverts the value proposition.

## Option B: native emitter, coupled to internals

PacketForge is a PcapEmitter subscribing to the same canonical event stream the Zeek emitters
consume, living inside the EvidenceForge tree.

- **Gain.** Consistency by construction, with no reconstruction step. It reuses the network, DNS,
  HTTP and TLS contexts directly, inherits sensor multiplexing from the base emitter, and merges
  back trivially because the code is already an emitter.
- **Cost.** It couples to internal dataclasses in the area EvidenceForge was refactoring. It is
  hard to ship standalone, and it puts experimental packet code inside the core product before the
  approach is proven.
- **Verdict.** The right destination, the wrong starting point.

## Option C: IR compiler, coupled to a contract

Define a small versioned Flow IR. A FlowSpec carries the 5-tuple, timing, a segmentation plan, the
per-protocol layer-7 payload, a TLS fingerprint id and an OS profile id: everything needed to
render bytes and nothing about why the traffic happened. EvidenceForge gains one additive emitter
that projects each canonical event onto the IR, and PacketForge compiles the IR to packets.

- **Gain.** The IR is emitted from the canonical event, so consistency is preserved rather than
  reconstructed, and a versioned contract insulates the compiler from refactoring on the other
  side. The compiler also accepts hand-authored IR, so it stands alone, and the only code that
  would land in EvidenceForge is a small serializer.
- **Cost.** One more artifact and schema to version, plus a two-repo contract to keep in sync.
- **Verdict.** The best boundaries: a standalone experiment and a clean merge at once.

| | A: log post-processor | B: native emitter | C: IR compiler |
|---|---|---|---|
| Couples to | log outputs | event internals | versioned IR |
| Consistency | second-order, lossy | by construction | by construction |
| Standalone development | yes | no | yes |
| Exposed to refactor churn | no | yes | no |
| Risk to the core now | none | high | minimal |
| Merge-back | awkward | trivial | easy, becomes B |

## Decision

Build PacketForge as a standalone Option C compiler, and design the IR so that promotion to a
native emitter is a later mechanical step. The merge path is a ratchet, not a leap.

1. PacketForge standalone compiles hand-authored IR and EvidenceForge-emitted IR.
2. EvidenceForge PR 1: an additive FlowSpecEmitter writing flows.jsonl. It computes nothing new.
3. EvidenceForge PR 2: an opt-in pcap artifact family, gated by the Zeek round-trip in CI.
4. Optional promotion: call the compiler in process instead of across a file. That is Option B.

## Consequences

- The IR is a public surface. It is versioned, and a breaking change costs a bump on both sides.
- Validation had to be built early. When the contract is a file, the only way to know the compiler
  honoured it is to read the capture back with real Zeek and `tshark -z expert` and diff the fields.
  That gate became the project's central deliverable.
- The compiler is usable with no EvidenceForge in the picture. Every attack, environment and sample
  in this repo compiles from IR that PacketForge composes itself.
- Volumetric fields are read back, not authored. The feasibility proof had Zeek report a duration of
  0.3297 where the event claimed 0.3521, because Zeek computes duration its own way. Durations,
  byte and packet counts and missed_bytes come from the rendered capture.

## Postscript: the round-trip measured the argument

`packetforge ef-roundtrip` ingests a real EvidenceForge run, renders a capture, runs real Zeek over
it, and diffs the result against EvidenceForge's own logs. On the branch-office scenario the
capture is clean: no weird.log, no reporter.log, and no tshark expert errors. Agreement is 100% on
proto, service, the DNS query, qtype and answers, the HTTP method, host, uri and status, and the
TLS version, cipher and SNI, plus exact byte counts on flows with no Zeek analyzer attached.
conn_state, Zeek's summary code for how a connection ended, agrees on about 99% of flows.

That run is Option A executed as an experiment, and it confirms the case for Option C.
Reconstructing from EvidenceForge's logs recovers the whole story and every indicator field. It
does not recover exact payload volumetrics, because the logs do not carry the bytes. An
EvidenceForge integration should therefore emit the IR from the canonical event, which does carry
the bytes, rather than post-process logs.

The run also works as a consistency oracle in the other direction. It found three places where
EvidenceForge's synthesized log values differ from what real Zeek emits from packets: ICMP
conn_state (SF against Zeek's OTH), the text form of IPv6 answers, and URI percent-encoding.

## Lineage

Flowsynth is a three-phase packet-capture compiler. It parses a text intermediate language, renders
it to packets with automatic sequence and acknowledgement handling, and outputs libpcap on a scapy
backend. Three things were adopted from it: the split between a compiler and an ordered timeline,
scapy as the packet backend, and pairing the generator with an IDS-testing loop.

Three things were not adopted. Flowsynth is hand-authored only, it has no consistency to any log
layer, and it ships neither a validation harness nor a determinism contract. PacketForge is
machine-fed from a typed IR, validated against real tools, and byte-identical across runs.

## Related

- [`../DESIGN.md`](../DESIGN.md): how the compiler is built today.
- [`feasibility-evidence.md`](feasibility-evidence.md): the proof that preceded this decision.
- [`../validation.md`](../validation.md): gates 1 to 3, measured.
