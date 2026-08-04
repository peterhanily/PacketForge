# EvidenceForge integration

A draft of how PacketForge would plug into EvidenceForge, prepared here and reviewed here. Nothing
in this directory has been pushed to EvidenceForge and no pull request has been opened. It is the
review artifact, not a change.

## The idea

`packetforge ef-roundtrip` already works without touching EvidenceForge: it reads a finished
EvidenceForge run, renders packets, and diffs real Zeek's output against EvidenceForge's own logs.
What that path cannot recover is exact payload volumetrics, because the logs do not carry the
bytes.

The fix is a small additive emitter that serialises the canonical `SecurityEvent` to the
PacketForge Flow IR. The event carries the exact bytes, so a capture rendered from it matches
EvidenceForge's own numbers rather than approximating them.

## What is here

- **`flowspec_emitter.py`.** The proposed emitter. `event_to_flow(event)` maps a `SecurityEvent`,
  with its network, DNS, HTTP and SSL contexts, to a Flow IR dictionary. `FlowSpecEmitter` is the
  EvidenceForge-shaped wrapper that writes `flows.jsonl`. It is dependency-free and duck-typed, so
  it drops into EvidenceForge without importing PacketForge.
- **`prove_local.py`.** A bridge that runs the emitter against EvidenceForge's real model classes
  and emits a FlowSet, which shows the mapping fits the data model rather than a stand-in for it.

## Reproducing the proof

```bash
EF=/path/to/EvidenceForge          # a local clone with `uv sync` already run

# 1. EvidenceForge's own venv maps real canonical events to a FlowSet:
(cd "$EF" && PYTHONPATH=src .venv/bin/python \
   /path/to/PacketForge/integration/evidenceforge/prove_local.py /tmp/ef_flows.json)

# 2. PacketForge compiles that FlowSet and real Zeek validates the result:
cd /path/to/PacketForge
PYTHONPATH=src .venv/bin/python -c "import json; \
  from packetforge.models.flowspec import FlowSet; \
  from packetforge.validation import validate_flowset; \
  print(validate_flowset(FlowSet.model_validate(json.load(open('/tmp/ef_flows.json')))).ok)"
```

Observed locally: the emitter maps `SecurityEvent` and its four contexts cleanly, the compiled
capture is clean under real Zeek (zero weird entries, zero tshark errors), and an analyzer-free
opaque flow reproduces the canonical event's byte counts exactly, 1234 and 5678 in and out. That
last part is the fidelity the log-reconstruction path cannot reach.

The same guarantee is covered by `tests/test_ef_integration.py`, which runs against duck-typed
canonical events, so it needs no EvidenceForge checkout.

## Where it would plug in

Two additive changes, neither of which computes anything new for the existing log outputs, so
neither can regress them.

1. **A new emitter** at `src/evidenceforge/generation/emitters/flowspec.py`, registered in
   `_init_emitters()` alongside the Zeek emitters and gated on `environment.artifacts.mode`, which
   is how email artifacts are already gated. It writes `flows.jsonl` into the output bundle.
2. **A `pcap` artifact family.** After generation, if `artifacts.mode` selects it, compile
   `flows.jsonl` with PacketForge into `artifacts/pcap/<sensor>.pcap` and add a `pcap` section to
   `ARTIFACTS_MANIFEST.json`, mirroring the email artifact family.

## Constraint of record

Nothing here is pushed to EvidenceForge, proposed as a pull request, or raised on its issue
tracker without the repository owner's explicit approval.
