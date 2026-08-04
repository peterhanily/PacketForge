# Design

How PacketForge is built: the intermediate representation, the compile layer, the renderers, and
the rules a change has to keep true. Read this before adding a protocol or evaluating a merge.

## What it is

PacketForge compiles a description of an incident into a packet capture. It is a companion to
[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge), which generates the log side of the
same incident from the same description, so the two cannot disagree about a port, a hostname or a
byte count. That agreement is tested rather than asserted: real Zeek reads the capture back, and
its logs are diffed field by field against what the renderers said they emitted. Generation calls
no model and draws no unseeded randomness, so one input yields one byte-identical capture. Why a
compiler over a versioned contract, rather than a post-processor over Zeek logs or an emitter
inside EvidenceForge, is recorded in [ADR 001](appendix/adr-001-ir-compiler.md).

## The Flow IR

`src/packetforge/models/flowspec.py` holds the whole contract, in pydantic v2. A `FlowSet` is the
top-level document: a `schema_version`, a `CaptureMeta` (link type, snaplen, MAC OUI, texture),
and a list of `Flow`. A `Flow` carries the 5-tuple, the start time, each endpoint's OS profile,
the round-trip time, one L7 payload, and a target `conn_state` (Zeek's code for how a connection
opened and closed).

L7 payloads are a discriminated union on `kind`. Pydantic dispatches on the literal, so a
malformed payload fails at load rather than halfway through rendering, and a validator pins each
kind to its legal transports: an `http` payload declared over UDP is rejected.

The IR is the contract because it is the only thing the packet machinery reads. It says what is
needed to render bytes and nothing about why the flow happened, which is what lets EvidenceForge
project its canonical event onto it without PacketForge knowing anything about events.
`schema_version` keeps the two projects independent: it is checked on load and a major-version
mismatch is refused, so an old compiler cannot silently mis-render a newer document.

## The compile layer

`compile/timeline.py` is the top of the pipeline: parse the IR, render each flow, merge, write.
Every flow gets its own RNG seeded from its `flow_id` and 5-tuple, so rendering is order
independent and a flow's bytes do not depend on what else is in the capture. Packets are then
stable-sorted by timestamp. A capture declaring `linux_sll` has its frames rewritten as Linux SLL,
the cooked link layer a host-side `tcpdump` produces, which carries no destination MAC.

`compile/tcp.py` owns TCP. Sequence and acknowledgement arithmetic, MSS segmentation, the
handshake, the shape of each supported `conn_state` (`SF`, `S0`, `REJ`, `RSTO`, `RSTR`), and
teardown. It also reconstructs Zeek's `history` string, which records the first occurrence per
direction of each connection event letter. History is built from exactly the packets emitted, and
the same pass measures the packet counts, byte counts and duration the validator holds Zeek to.
The builder is pure, taking resolved endpoint parameters and importing neither the fingerprints
nor the IR.

`compile/vantage.py` projects one rendered incident to a sensor position. A **vantage** is where a
sensor sits plus what that placement does to the packets reaching it. An edge TAP (a passive tap
on the WAN side) applies source NAT and a TTL decrement. A core SPAN (a mirrored switch port) adds
an 802.1Q tag. A host capture keeps only that host's packets, cooked to Linux SLL. A cloud traffic
mirror wraps each frame in VXLAN, the UDP 4789 encapsulation AWS and GCP mirroring and Kubernetes
overlays use. Every projection is a pure transform over the same rendered incident.

`compile/fragment.py` splits oversized IPv4 packets into fragments, which Zeek reassembles into
the same flows, so it is a reassembly test for anything that does not. `compile/pcapng.py` writes
pcapng with a comment on each packet block and one on the section header, so provenance travels
inside the artifact rather than in a sidecar a forwarded capture loses.

## One renderer per protocol

`renderers/` mirrors EvidenceForge's one emitter per output format. A renderer takes the flow, the
two resolved endpoints and a seeded RNG. It returns packets plus an `expected` dictionary stating
what a correct parser should read back. `RENDERERS`, keyed by L7 kind, is the only dispatch.

23 protocols have a protocol-specific renderer, counting the `namequery` module as the three wire
protocols it covers (LLMNR, NBT-NS and mDNS), plus two opaque shells for TCP and UDP. Several
things that read like protocols are not separate renderers. DoH and DoT are TLS flows on 443 and
853 with the matching ALPN. WinRM is an HTTP POST to `/wsman` carrying sized filler SOAP bodies.
RDP is an opaque TCP flow whose first originator bytes are a literal X.224 connection request,
just enough for Zeek to populate the `rdp.log` mstshash cookie.

A binary protocol gets minimal real structure over a sized opaque remainder. Kerberos renders a
real ASN.1 envelope and a real encryption type, so an RC4 downgrade shows up in `kerberos.log`,
around a filler ticket blob. A protocol with no renderer gets an opaque shell: correct handshake,
teardown and volumetrics, no dissection claimed. Every payload is inert by construction, which
[inert-by-construction.md](inert-by-construction.md) covers, and
[capabilities.md](capabilities.md) carries the current protocol list.

Adding a protocol is five things: a model in `flowspec.py`, a renderer module, a `RENDERERS`
entry, a case in the determinism test, and a green `packetforge validate` on a flow that uses it.

## Data-driven fingerprints

L2 to L4 identity comes from YAML, not from code. `fingerprints/tcp/` holds one profile per OS
(`windows_10`, `windows_7`, `linux`, `macos`) giving the TTL, the SYN window, the exact SYN option
order, whether TCP timestamps are advertised, and the IP-ID policy. `resolve_endpoint` turns an
IP, a port and an OS name into the endpoint the TCP builder renders, so a host's packets never
contradict what the log layer says that host is.

`fingerprints/ja3/` holds numeric TLS client profiles. JA3 is the MD5 of a ClientHello's version,
cipher list, extension list, curves and point formats, with GREASE values excluded. The
ClientHello is emitted from the same numbers the JA3 is computed from, so the bytes and the
declared fingerprint agree by construction rather than by check. `ja3_to_profile` runs that
backwards, to re-emit a JA3 seen in a real capture. `fingerprints/certs.py` issues the certificate
a TLS 1.2 server presents in the clear, from one committed key with dates taken from the flow's
start time.

## The composer

`compose.py` builds a capture a hunter has to work through. It draws ambient flows from the
service mix of an environment, one of the 9 YAML profiles under `environments/profiles/`. Arrivals
are bursty and non-stationary, so the first half of a capture is separable from the second, as it
is in a real capture. Storyline flows come from `scenarios.py`, where each attack builder returns
its flows plus a ground-truth record mapping flow ids to ATT&CK techniques, which `bundle.py`
writes out as the answer key.

Two limits are worth knowing before extending it. The `ot` environment's ambient mix is thin,
because `s7` and `dnp3` have no renderer and fall through to opaque TCP with zero application
bytes. Composition also degrades past roughly 22 hours of window, when the ephemeral source-port
band wraps and 5-tuples begin to collide, which is why sample 19 ships two captures.

## Determinism, and how it is enforced

Byte-identical output is the engine contract PacketForge inherits, and the property most easily
broken by accident. Seeding is per flow, derived from a SHA-256 of the `flow_id`, the 5-tuple and
an optional salt. Nothing draws from the global RNG, so flows can be reordered, added or removed
without perturbing each other.

The wall clock is the real hazard. scapy fills unset time and GUID fields from `time.time()` at
serialisation, and every such field is a leak. The ones found so far: the NTP `orig` and `sent`
timestamps, SMB2 `ServerTime` and `ServerStartTime`, and the Kerberos `rtime`. Certificate
validity dates are the same class of hazard. All are pinned from the flow's start time, and the
rule for a new renderer is to pin every time-bearing field rather than accept a default.

The guard is `tests/test_determinism.py`. `test_no_renderer_reads_wall_clock` renders each
time-bearing renderer under a monkeypatched clock at 2017 and again at 2030, and requires
byte-identical output. Two adjacent renders at second resolution can match by luck, which is
exactly how such a leak stays hidden. A second test renders every entry in `RENDERERS` twice and
asserts the case list covers the dispatch table.

## The validation gate

Four gates, each with a command and a published answer.

| Gate | Question | Command |
|---|---|---|
| 1. Validity | Does real Zeek reproduce what was rendered? | `packetforge validate` |
| 2. Realism | Can a classifier separate it from a real capture? | `packetforge realism-audit` |
| 3. Detection | Do rules behave the same on both? | `packetforge realism-detection` |
| 4. Correspondence | Is it warranted by the sources it was built from? | `packetforge warrant` |

Gate 1 is the contract a generator change has to keep. `validation/roundtrip.py` compiles the
FlowSet, runs real Zeek and real tshark over the pcap, and asserts three things. Zeek writes no
`weird.log` and no `reporter.log`. `tshark -q -z expert` reports zero errors, and no warnings
beyond four that real captures also carry. Zeek's `conn`, `dns`, `http`, `ssl` and `smtp` logs
match the renderer-measured expectations field for field. A change is not done until this is green
on the affected flows.

Gates 2 and 3 measure a capture against a real reference, the first with a cross-validated
classifier two-sample test (C2ST), the second by running the same rules over both. Gate 4 checks a
reconstruction against the claim set that licenses it, a question the other three cannot reach. The
numbers are in [validation.md](validation.md) and [correspondence.md](correspondence.md).

## Repository layout

```
src/packetforge/
  models/flowspec.py         the Flow IR: FlowSet, Flow, the L7 union
  compile/                   timeline.py tcp.py vantage.py fragment.py pcapng.py
  renderers/                 one module per protocol, plus the two opaque shells
  fingerprints/              tcp/*.yaml ja3/*.yaml ja4.py certs.py loader.py
  environments/profiles/     one YAML per network environment
  ingest/ validation/        EvidenceForge logs -> Flow IR; roundtrip.py is Gate 1
  compose.py                 ambient traffic + storyline -> one FlowSet
  scenarios.py               the 26 attacks, the evasion modifiers, ground truth
  warrant.py realism.py realism_detection.py trinity.py  Gates 4, 2, 3 and a combined report
  signatures.py              signature-conditioned benign flows
  detection_ci.py bundle.py  pytest fixtures; capture + logs + answer key + manifest
  cli/                       the packetforge subcommands
  12 further modules         ruleset grading, scoring, reporting, transfer proofs
detection/ flows/            rulesets; hand-authored FlowSpecs and claim sets
integration/evidenceforge/   the draft FlowSpecEmitter, local only
poc/ scripts/ tests/         the feasibility proof; tooling; the pytest suite
samples/                     19 sample folders holding 26 captures
```

CI runs Python 3.9 and 3.11. Zeek, tshark and Suricata are external programs, not Python
dependencies, and tests needing them skip when they are absent.

## The EvidenceForge round-trip

`packetforge ef-roundtrip <ef_output>` reads an EvidenceForge output directory, whose Zeek logs
are NDJSON correlated by `uid`. It builds a FlowSet from EvidenceForge's own 5-tuples, timing and
L7 detail, compiles it, runs real Zeek, and diffs the result against EvidenceForge's original
logs.

On the `branch-office-example` scenario the capture is clean: no `weird.log`, no `reporter.log`,
no tshark errors. Protocol and service agreement is at or near 100%, as is every DNS, HTTP and TLS
indicator field. `conn_state` agrees at about 99%, and byte counts are exact for analyzer-free
flows. That result is not reproducible from this repository: no EvidenceForge output is checked
in, so the numbers come from a local run and nothing in CI re-measures them.

Two findings outlast the numbers. Reconstructing from logs recovers the story and every IOC field
but not exact payload volumetrics, because Zeek's logs do not carry the bytes. That is the
argument for emitting the IR from the canonical event instead. The round-trip also works as a
consistency oracle for synthesised logs. It found three places where EvidenceForge's values differ
from what real Zeek emits from actual packets: ICMP `conn_state`, where EvidenceForge writes `SF`
and Zeek writes `OTH`; the text form of IPv6 answers; and URI percent-encoding. PacketForge
matches real Zeek in all three.

## The merge path to EvidenceForge

The merge is a ratchet rather than a leap. The first upstream change would be a small additive
`FlowSpecEmitter` serialising what is already on each canonical event to `flows.jsonl`, computing
nothing new. It is drafted at `integration/evidenceforge/`. The second would wire PacketForge in
as a `pcap` artifact family behind the existing `artifacts.mode` switch, gated on the round-trip
in CI. A later step could collapse the file boundary and call the compiler in process, which
changes no packet code. [ROADMAP.md](ROADMAP.md) tracks the state of each.

Constraint of record: nothing is pushed to EvidenceForge, no pull request is opened against it,
and no comment is made on its issues without the repository owner's explicit approval. Every
EvidenceForge-facing change is drafted in this repository for review first.
