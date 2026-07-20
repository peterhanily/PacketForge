# EvidenceForge integration (DRAFT — local only, nothing upstreamed)

This shows how PacketForge would integrate with EvidenceForge, prepared **locally**. Nothing here has been
pushed to EvidenceForge, and no PR has been opened. It shows exactly how PacketForge
would plug into EvidenceForge, and proves the fit against EvidenceForge's real code.

## The idea (recap)

The log-reconstruction path (`packetforge ef-roundtrip`) already works today without
touching EvidenceForge, but it can't recover exact payload volumetrics — the logs
don't carry the bytes. The clean fix is a tiny, additive emitter that serializes the
**canonical `SecurityEvent`** to the PacketForge Flow IR. From the event we have the
exact bytes, so the pcap matches EvidenceForge's own numbers.

## What's here

- **`flowspec_emitter.py`** — the proposed emitter. `event_to_flow(event)` maps a
  `SecurityEvent` (NetworkContext + DnsContext/HttpContext/SslContext) to a Flow-IR
  dict; `FlowSpecEmitter` is the EvidenceForge-shaped wrapper that writes `flows.jsonl`.
  Dependency-free and duck-typed, so it drops into EvidenceForge without importing
  PacketForge.
- **`prove_local.py`** — a bridge that runs the emitter against EvidenceForge's **real**
  model classes and emits a FlowSet, proving the mapping fits EF's data model.

## Proof it works (reproduce locally)

```bash
EF=/path/to/EvidenceForge          # a local clone with `uv sync` done
# 1) EvidenceForge's own venv maps real canonical events -> a FlowSet:
(cd "$EF" && PYTHONPATH=src .venv/bin/python \
   /path/to/PacketForge/integration/evidenceforge/prove_local.py /tmp/ef_flows.json)
# 2) PacketForge compiles it and Zeek validates:
cd /path/to/PacketForge
PYTHONPATH=src .venv/bin/python -c "import json; \
  from packetforge.models.flowspec import FlowSet; \
  from packetforge.validation import validate_flowset; \
  print(validate_flowset(FlowSet.model_validate(json.load(open('/tmp/ef_flows.json')))).ok)"
```

Result observed here: the emitter maps EF's `SecurityEvent`/`NetworkContext`/
`DnsContext`/`HttpContext`/`SslContext` cleanly; the compiled pcap is **clean under
real Zeek** (0 weird/tshark errors); and an analyzer-free opaque flow reproduces the
canonical event's bytes **exactly** (1234/5678 → 1234/5678) — the volumetric fidelity
the log path can't reach.

## Where it plugs into EvidenceForge (the two additive changes)

1. **A new emitter** at `src/evidenceforge/generation/emitters/flowspec.py`, registered
   in `EvidenceForge`'s `_init_emitters()` alongside the Zeek emitters, gated on
   `environment.artifacts.mode` (exactly how email artifacts are gated). It writes
   `flows.jsonl` into the output bundle.
2. **A `pcap` artifact family**: after generation, if `artifacts.mode` selects it,
   compile `flows.jsonl` with PacketForge into `artifacts/pcap/<sensor>.pcap` and add a
   `pcap` section to `ARTIFACTS_MANIFEST.json` — mirroring the email artifact family.

Both are additive: they compute nothing new for the existing log outputs and cannot
regress them. The precise diff is kept locally.

## Constraint of record
Nothing in here is pushed to EvidenceForge or opened as a PR without the maintainer's
(and the contributor's) explicit approval. This directory is the review artifact.
