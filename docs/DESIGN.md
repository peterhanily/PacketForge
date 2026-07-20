# PacketForge — Design & Implementation Plan

Status: **planning** (feasibility proven — see [`feasibility-evidence.md`](feasibility-evidence.md))
Merge target: [Cisco-Talos/EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) (issue #332)

---

## 1. What PacketForge is

PacketForge renders **deterministic, valid, consistency-checked PCAPs** from the same
canonical incident model that EvidenceForge already uses to generate logs. Where
EvidenceForge answers *"what did the sensors log?"*, PacketForge answers *"what was
actually on the wire?"* — and guarantees the two agree, because both derive from one
source of truth.

The guarantee is not asserted, it is **tested**: generate the packets, run **real
Zeek** over them, and diff Zeek's `conn.log`/`dns.log`/`http.log`/`ssl.log` against
the log rows EvidenceForge emits for the same events. If they disagree, it's a bug.
This turns "how do you know a synthetic PCAP is realistic?" into a mechanical
pass/fail gate.

## 2. Lineage — what we borrow, and from whom

### From EvidenceForge (the structure and the values)
- **Consistency by construction.** One canonical event feeds every output. Two
  renderers cannot disagree about a port, hash, or timestamp because there is only
  one value. PacketForge extends this one layer down, to packets.
- **Deterministic engine.** No LLM at generation time, no randomness that isn't
  seeded from the scenario. Same input → byte-identical PCAP. (Proven: the PoC
  produces an identical MD5 across runs.)
- **Renderer-per-format pattern.** EvidenceForge has `ZeekDnsEmitter`,
  `ZeekHttpEmitter`, … each a small class over the shared event. PacketForge mirrors
  this with `DnsRenderer`, `HttpRenderer`, `TlsRenderer`, … over the shared flow IR.
- **Sensor/visibility model.** EvidenceForge already knows sensor placement
  (SPAN/TAP/host) and which flows each sensor sees. A PCAP is naturally *per-sensor*;
  we reuse this instead of reinventing it.
- **Output-target abstraction.** `default | sof-elk | splunk` today; PCAP is a new
  target/artifact family, opt-in via the existing `artifacts.mode: none | storyline
  | selected | all` switch.
- **Ground truth + manifest.** Every bundle documents what happened. PacketForge
  adds a `pcap` section to `ARTIFACTS_MANIFEST.json`, same as email v1 did.
- **Built-in validation as a first-class deliverable.** EvidenceForge ships a
  4-pillar eval and external-parser harnesses (SOF-ELK, Splunk). PacketForge ships
  the Zeek/Suricata round-trip harness as its equivalent.

### From Flowsynth (the compiler mechanics)
Flowsynth (Secureworks/Neo23x0) is a three-phase **packet-capture compiler**:
*parse* a text IL → *render* to packets (auto SEQ/ACK, `tcp.initialize`
auto-handshake) → *output* hexdump or libpcap, on a scapy backend.

- **The compiler-timeline split** — an ordered intermediate representation rendered
  to packets — is exactly the boundary PacketForge should keep. We adopt it.
- **scapy as the packet backend** — proven, Wireshark/Zeek-clean output. We adopt it.
- **The IDS-testing loop** (Flowsynth pairs with Dalton to test pcaps against
  Suricata/Snort/Zeek) — we adopt this as the validation gate.

What we deliberately **do not** inherit from Flowsynth: it is hand-authored only
(no consistency to any log layer), Python 2.7, single-file, untyped, and has no
validation harness or determinism contract. PacketForge is machine-fed from a typed
IR, validated, and deterministic — while *also* accepting hand-authored IR the way
Flowsynth accepts synfiles.

## 3. The consistency thesis, proven

A single hand-authored canonical event (DNS lookup + HTTP C2 beacon) was rendered to
a 1,406-byte PCAP and read back by **Zeek 8.2.1**. Every field EvidenceForge carries
was reproduced independently, with **zero** `weird.log`/`reporter.log` entries and
zero `tshark` expert warnings. Full evidence in
[`feasibility-evidence.md`](feasibility-evidence.md). The working generator is
[`../poc/pcap_poc.py`](../poc/pcap_poc.py).

The lesson that shapes the architecture: some summary fields must be **read back**
from the packets, not authored. Zeek reported `duration=0.3297` where the event
"claimed" `0.3521`, because Zeek computes duration its own way. Volumetric/timing
fields (`duration`, `*_bytes`, `*_pkts`, `missed_bytes`) should be *derived from the
rendered PCAP*, and the log emitter should agree with the PCAP — not the reverse.

---

## 4. Three implementation methods

The methods differ on **one axis: what PacketForge couples to.**

### Method A — Log post-processor (couple to EvidenceForge *outputs*)
PacketForge is a standalone tool that reads a finished EvidenceForge output bundle
(`conn.log`, `dns.log`, `http.log`, `ssl.log`, ground truth) and reverse-derives
packets from those log rows.

- **Pros:** zero coupling to EvidenceForge internals; works against any existing
  bundle; fully independent repo; never touches the 17k-line `ActivityGenerator`.
- **Cons:** Zeek logs are a *lossy projection* — `http.log` has metadata but not the
  verbatim request bytes; `ssl.log` has no application data; nothing carries exact
  segmentation. PacketForge would have to re-synthesize or guess what the event
  already knew. Two independent reconstructions (log emitter + packet deriver) can
  drift. Consistency becomes *second-order* (`event → logs → pcap`) instead of the
  EvidenceForge guarantee (`event → {logs, pcap}`). Merge-back is awkward: it's built
  as an external consumer, not an emitter.
- **Verdict:** fastest to demo against real data, but it inverts the core value
  proposition. Wrong foundation.

### Method B — Native emitter (couple to EvidenceForge *internals*)
PacketForge is a `PcapEmitter(SensorMultiplexEmitter)` that subscribes to the same
canonical `SecurityEvent` stream the Zeek emitters consume, living (eventually) at
`src/evidenceforge/generation/emitters/pcap/`.

- **Pros:** true consistency by construction — same event → logs **and** packets,
  no lossy reconstruction. Reuses `NetworkContext`/`DnsContext`/`HttpContext`/
  `SslContext` directly. Sensor multiplexing is inherited from the base class
  (per-sensor pcaps for free). Merge-back is trivial: it is *already* an emitter.
  Maximally aligned with how EvidenceForge is built.
- **Cons:** couples to EvidenceForge's internal dataclasses; must track them through
  the in-progress **architecture reset** that is actively refactoring exactly this
  area. Hard to develop or ship "standalone." Puts fiddly, experimental packet code
  *inside* the core product before it's proven — the opposite of low-risk.
- **Verdict:** the right *destination*, the wrong *starting point*.

### Method C — IR compiler (couple to a *contract*) — **recommended**
Define a small, stable, versioned **Flow IR** (a `FlowSpec`: 5-tuple, timing,
history/segmentation plan, per-protocol L7 payload, TLS-fingerprint id, OS-profile
id — everything needed to render bytes, nothing about *why* it happened).

- EvidenceForge gains a *tiny, additive* `FlowSpecEmitter` that serializes what is
  already on each event to `flows.jsonl`. Low-risk: it computes nothing new, it
  just projects the canonical event onto the IR.
- **PacketForge is a separate compiler**: `FlowSpec → packets → pcap`, exactly
  Flowsynth's parse/render/output split, but typed and validated.

- **Pros:**
  - **Consistency preserved** — the IR is emitted *from the canonical event*, so it
    is not a lossy log reconstruction (unlike A). `event → IR → pcap` and
    `event → logs` share the same source.
  - **Decoupled from churn** — the IR is a versioned contract, insulating PacketForge
    from the architecture reset (unlike B).
  - **Independently useful & shippable** — PacketForge compiles hand-authored IR too
    (the Flowsynth use case), so it stands alone as an experiment, which is exactly
    how issue #332 framed it ("separate experimental side project *or* an artifact
    output mode").
  - **Low blast radius on the core** — the only thing that lands in EvidenceForge is
    a ~200-line serializer emitter; all the risky packet machinery stays in
    PacketForge until it's proven.
  - **Clean promotion path to B** — because the IR emitter already lives in
    EvidenceForge and the compiler is pure, "promote to native emitter" later is just
    "call the compiler in-process instead of via a file." No rework of the packet
    code.
- **Cons:** one extra artifact and schema to design and version; a two-repo contract
  to keep in sync. Both are cheap and both are *features* pre-merge (they are what
  keep the projects independently developable).
- **Verdict:** best boundaries, lowest risk, most future-proof, and it is the only
  method that is simultaneously a standalone experiment **and** a clean merge.

### Side-by-side

| | A: log post-proc | B: native emitter | C: IR compiler |
|---|---|---|---|
| Couples to | log outputs | event internals | versioned IR contract |
| Consistency | 2nd-order (lossy) | by construction | by construction |
| Standalone dev | yes | no | **yes** |
| Exposed to arch-reset churn | no | **yes** | no |
| Risk to EF core now | none | high | **minimal** (tiny serializer) |
| Merge-back | awkward | trivial | **easy → becomes B** |
| Independently useful | no | no | **yes (Flowsynth-style)** |

---

## 5. Design principles (what a network artifact must do to earn adoption)

Established threat-hunting practice sets a strong prior on what a network artifact has
to do to be worth having. Reading the design through that lens:

- **High-pyramid signal (Pyramid of Pain).** The value of an artifact rises with where
  its signal sits: hashes/IPs (trivial for an adversary to change) at the bottom, **tools
  and TTPs** at the top. A PCAP that only leaks atomic IOCs is low value. So PacketForge
  prioritizes **high-pyramid signal**: JA3/JA4 (tooling fingerprint), C2 **beacon cadence
  and jitter**, protocol-behavior tells — not just "an IP talked to an IP." A design
  requirement, not a nice-to-have: *render the behavior, not just the atoms.*
- **Hypothesis-driven hunting.** Data should let a hunter form and confirm a hypothesis by
  **pivoting across layers**: spot a beacon in the logs → confirm it in the PCAP → extract
  the JA3 → hunt that JA3 fleet-wide. That pivot only works if the layers are consistent —
  which is the whole thesis.
- **"Logs that don't look (as) fake."** EvidenceForge's stated bar is realism that survives
  an experienced analyst, measured by blind panels. The packet layer must clear the same
  bar: at least as internally consistent as the logs, or it is a net negative. This is why
  per-OS TCP fingerprints and JA3-consistent-with-the-client-software matter — a mismatched
  fingerprint is a new tell the logs never had.
- **Deterministic, reproducible, no-hype engineering.** A non-deterministic ML/GAN traffic
  generator does not fit the generation path. Deterministic, seeded, canonical-event-derived
  is the only approach consistent with the existing engine.
- **Validate against real tools.** EvidenceForge already validates against SOF-ELK and
  Splunk; PCAPs should be held to **real Zeek/Suricata** — precisely the round-trip gate. The
  acceptance criterion is "real Zeek over the synthetic PCAP reproduces EvidenceForge's own
  Zeek logs."
- **Protect the core; scope honestly.** Issue #332 flagged PCAPs/malware as "likely
  difficult." The honest answer: cleartext + handshake-visible protocols first
  (DNS/HTTP/TLS-handshake), **opaque TCP shells** for binary protocols (SMB/Kerberos/RDP)
  rather than half-dissected garbage, no fake full-take capture, opt-in per storyline. And
  keep the risky code *out* of the core tree until it is proven — which is Method C.

**Conclusion:** treat packets as *another deterministic projection of the canonical event,
validated against the real parser, carrying high-pyramid behavioral signal, scoped honestly,
and introduced without destabilizing the core.* Method C is the plan that does all five.

---

## 6. Recommendation

**Build PacketForge now as a standalone Method-C IR compiler, and design the IR so
that promotion to a native EvidenceForge emitter (Method B) is a later, mechanical
step.**

Rationale in one line: Method C is the only option that is *simultaneously* a
low-risk standalone experiment, a by-construction-consistent generator, insulated
from the architecture-reset churn, and a clean path to merge — which is exactly the
set of properties issue #332 calls for.

Concretely, the merge story is a ratchet, not a leap:
1. **PacketForge standalone** compiles hand-authored + EvidenceForge-emitted IR.
2. **EvidenceForge PR #1 (tiny):** additive `FlowSpecEmitter` writing `flows.jsonl`.
   Reviewable in isolation, computes nothing new, cannot regress existing outputs.
3. **EvidenceForge PR #2 (opt-in):** wire PacketForge as a `pcap` artifact family
   behind `artifacts.mode`, invoked as the external compiler, gated by the Zeek
   round-trip in CI.
4. **Promotion (optional, later):** collapse the file boundary — call the compiler
   in-process as `PcapEmitter`. Same packet code, now Method B.

---

## 7. Scope (V1) and validation gate

**In V1 (the honest, high-value core):**
- Protocols rendered fully: **DNS**, **cleartext HTTP**, **TLS handshake** (real
  ClientHello/ServerHello/Certificate with a controllable **JA3**) + opaque
  application-data records sized to byte counts, **ICMP**, and **cleartext SMTP**
  (splicing EvidenceForge's existing `.eml`).
- Binary protocols (SMB/Kerberos/RDP/LDAP/RPC): **honest opaque TCP shells** —
  correct handshake/teardown/volumetrics, no L7 dissection claimed.
- **Per-OS L2–L4 fingerprints** (TTL, TCP options/window) driven by the host OS
  EvidenceForge already knows — so the packet layer never contradicts the log layer.
- Opt-in per storyline; targeted captures, not full-take.

**Out of V1:** decryptable TLS, realistic binary-protocol payloads, retransmit/loss
dynamics (add later via blind-panel feedback), EVTX/memory/disk images.

**The validation gate (CI, non-negotiable):**
1. `zeek -r out.pcap` produces **no** `weird.log` / `reporter.log`.
2. `tshark -z expert` reports **zero** errors/warnings/malformed.
3. Field-level diff: Zeek's `conn/dns/http/ssl` logs == EvidenceForge's own emitter
   output for the same events (5-tuple, `conn_state`, `history`, byte/pkt counts,
   DNS answers, HTTP host/uri/status, TLS version/cipher/SNI).
4. (Optional) Suricata fires the expected alerts and no spurious malformed events.

This is the PoC harness, productionized. It is also the answer to the objection raised in #332.

---

## 8. Repository structure (mirrors EvidenceForge)

```
PacketForge/
  src/packetforge/
    models/flowspec.py        # the IR (pydantic) — the versioned contract
    compile/timeline.py       # FlowSpec -> ordered packet timeline (Flowsynth's split)
    compile/tcp.py            # SEQ/ACK, segmentation, conn_state patterns, teardown
    renderers/                # one module per protocol (cf. EF emitters/)
      dns.py  http.py  tls.py  smtp.py  icmp.py  opaque_tcp.py
    fingerprints/             # data-driven, like EF config/
      ja3/*.yaml              # client TLS fingerprints (chrome, firefox, curl, ...)
      tcp/*.yaml              # per-OS TCP option/TTL/window profiles (p0f-style)
    validation/roundtrip.py   # zeek/tshark/suricata gate (the EF eval analog)
    cli/                      # packetforge compile | validate
  flows/                      # example FlowSpecs (cf. EF scenarios/)
  poc/                        # the proven feasibility PoC (reference)
  tests/                      # round-trip test is the crown jewel
  docs/
```

## 9. Risks & open questions

- **Fingerprint coherence is the real work.** JA3 must match the client software the
  UA/process tree imply; TCP options must match the host OS. Getting this wrong adds a
  tell. Mitigation: drive both from the OS/software EvidenceForge already models;
  blind-panel iterate.
- **IR versioning.** The contract must version cleanly so EvidenceForge and
  PacketForge can evolve independently. Use an explicit `schema_version`, like
  `ARTIFACTS_MANIFEST`.
- **Encrypted-but-known-plaintext.** For TLS training, decide per scenario: answer in
  ground truth, a cleartext variant, or (only if real crypto) an SSLKEYLOGFILE. Not a
  blocker; a design fork.
- **Binary protocols later.** When needed, prefer template-and-mutate of real captured
  handshakes via `tcprewrite`/`bittwiste` (deterministic seeded rewrite) over
  from-scratch synthesis of ASN.1/SMB2.
- **Licensing.** EvidenceForge is MIT (Cisco). PacketForge is MIT to keep merge
  frictionless. No GPL deps (scapy is GPLv2 but used as a library/tool, not linked
  into a distributed binary — confirm before shipping).

## 10. Roadmap (maps to issue #332's five-step scope)

1. **[done]** IR schema `v0` + `compile/` + DNS/HTTP/ICMP/opaque-TCP renderers +
   round-trip gate → green. *(#332 steps 1–4: take an event, add a target, generate a
   family, validate with a real parser.)*
2. **[done]** TLS 1.2 renderer with a controllable JA3; Zeek confirms version/cipher/
   SNI and `established=T`. *(the realism question that most decides adoption.)*
3. **[done, V1 + polish]** Per-OS TCP fingerprints + SMTP; then GREASE, a second JA3
   profile (JA3 now a discriminator), per-OS TCP Timestamps, and TLS 1.3. *Still open:*
   exact p0f option ordering, retransmit/jitter dynamics, a blind-panel realism pass.
4. **[blocked on maintainer approval — not started]** `FlowSpecEmitter` proposed to
   EvidenceForge (PR #1), then `pcap` artifact family (PR #2), behind `artifacts.mode`.
   *(#332 step 5.)* No EvidenceForge interaction happens without explicit approval.

> Constraint of record: **nothing is pushed to EvidenceForge and no issue comments are
> made without the maintainer's (repo owner's) explicit approval.** PacketForge is
> developed in its own repo; EvidenceForge PRs are drafted for review here first.

## 11. Real-data validation (the EvidenceForge round-trip)

`packetforge ef-roundtrip <ef_output>` ingests a real EvidenceForge run, renders a
pcap, runs real Zeek, and diffs our output against EvidenceForge's *own* logs. On the
`branch-office-example` scenario the pcap is clean (0 weird/reporter/tshark errors)
and agreement is: proto 100%, service 100%, conn_state ~99%, DNS query/qtype/answers
100%, HTTP method/host/uri/status 100%, TLS version/cipher/SNI 100%, and exact byte
counts 100% for analyzer-free opaque flows.

Two results matter beyond the numbers:

- **The Method-A vs Method-C thesis is now empirical.** Reconstructing from EF's logs
  recovers the whole story and every IOC field, but *not* exact L7 payload
  volumetrics (EF's logs don't carry the bytes). That gap is exactly why the eventual
  EvidenceForge integration should emit the Flow IR from the canonical event
  (carrying exact bytes) rather than post-processing logs.
- **The round-trip is a consistency oracle.** It caught three places where EF's
  directly-synthesized log values differ from what real Zeek emits from actual
  packets: ICMP `conn_state` (EF `SF` vs Zeek `OTH`), IPv6 answer text form, and URI
  percent-encoding. PacketForge matches real Zeek in all three. This is a reusable
  way to find where synthetic logs diverge from real tooling.

## 12. Phase 2 — depth: many traffic types, mixed and noisy captures

**Delivered:** faithful renderers for DHCP, NTP, SSH, FTP, SNMP, Modbus/TCP, and
RADIUS (14 protocols total); network-tap **environments** (office/home/cloud/ot) with
Ethernet-vs-Linux-SLL link types; and a **scenario composer** that lays down concurrent
environment-appropriate ambient noise and weaves in a storyline. **Next:** Kerberos and
LDAP renderers (scapy has the layers; heavier ASN.1), then S7/DNP3 for OT and more of
the long tail (RDP, SIP, MQTT, TFTP, mDNS/LLMNR, QUIC/DoH).

The round-trip surfaced the frontier directly: opaque random bytes on analyzer ports
are dissected as *malformed*, so protocols without a faithful renderer are still
rendered structure-only or skipped. The goal is captures that read like real networks:

1. **Faithful enterprise-protocol renderers** — DHCP, Kerberos, LDAP, NTP, SMB, NBNS
   — parseable by Zeek/Suricata without malformed events. Each follows the TLS
   pattern: minimal real structure + opaque/encrypted remainder, validated by the
   round-trip.
2. **Ambient/baseline noise mixed with malicious events** — a scenario is mostly
   benign background (browsing, DNS, updates, auth) with the storyline woven in, so a
   hunter must actually hunt. Density, periodicity, and diurnal shape are knobs.
3. **Multiple environments / network types in one bundle** — corporate LAN, DMZ,
   cloud VPC, OT/ICS segments, guest wifi — each with its own address plan, service
   mix, and sensor vantage; composable into one capture or a set.
4. **Sensor-vantage realism** — reuse EvidenceForge's SPAN/TAP/host visibility so the
   same event yields different packets at different capture points.
5. **Fidelity dynamics** — *done:* per-OS TCP timestamps, GREASE, a discriminating
   second JA3 profile, TLS 1.3. *Remaining:* exact p0f option ordering,
   retransmits/jitter, and a blind-panel review pass (§5 bar).

The architecture already supports this: new protocols are new renderers over the same
TCP core and IR; noise and multi-network are FlowSet composition; the round-trip gate
keeps every addition honest.
