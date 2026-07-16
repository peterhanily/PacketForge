# EvidenceForge integration sketch

How PacketForge would plug into EvidenceForge as an **opt-in** `pcap` artifact — additive,
consistent by construction, and unable to affect the existing log outputs. This is a
proposal for [issue #332](https://github.com/Cisco-Talos/EvidenceForge/issues/332); it is
not upstreamed.

## The idea

The log-reconstruction path (`packetforge ef-roundtrip`) already works today without
touching EvidenceForge, but it can't recover exact payload volumetrics — the logs don't
carry the bytes. The clean fix is a tiny, additive emitter that serializes the **canonical
`SecurityEvent`** to the PacketForge Flow IR. From the event we have the exact bytes, so
the pcap matches EvidenceForge's own numbers, by construction.

## What's here

- **`flowspec_emitter.py`** — the proposed emitter. `event_to_flow(event)` maps a
  `SecurityEvent` (NetworkContext + DnsContext/HttpContext/SslContext) to a Flow-IR dict;
  `FlowSpecEmitter` is the EvidenceForge-shaped wrapper that writes `flows.jsonl`.
  Dependency-free and duck-typed, so it drops in without importing PacketForge.
- **`prove_local.py`** — a bridge that runs the emitter against EvidenceForge's real model
  classes and emits a FlowSet, demonstrating the mapping fits EF's data model.

## Reproduce locally

```bash
EF=/path/to/EvidenceForge          # a local clone with `uv sync` done
# 1) map real canonical events -> a FlowSet using EvidenceForge's own venv:
(cd "$EF" && PYTHONPATH=src .venv/bin/python \
   /path/to/PacketForge/integration/evidenceforge/prove_local.py /tmp/ef_flows.json)
# 2) PacketForge compiles it and Zeek validates:
cd /path/to/PacketForge
PYTHONPATH=src .venv/bin/python -c "import json; \
  from packetforge.models.flowspec import FlowSet; \
  from packetforge.validation import validate_flowset; \
  print(validate_flowset(FlowSet.model_validate(json.load(open('/tmp/ef_flows.json')))).ok)"
```

Observed: the emitter maps `SecurityEvent`/`NetworkContext`/`DnsContext`/`HttpContext`/
`SslContext` cleanly; the compiled pcap is **clean under real Zeek** (0 weird/tshark
errors); and an analyzer-free opaque flow reproduces the canonical event's bytes
**exactly** (1234/5678 → 1234/5678) — the volumetric fidelity the log path can't reach.

## Where it plugs in (two additive changes)

1. **A new emitter** at `src/evidenceforge/generation/emitters/flowspec.py`, registered in
   `_init_emitters()` alongside the Zeek emitters, gated on `environment.artifacts.mode`
   (exactly how email artifacts are gated). It writes `flows.jsonl` into the output bundle.
2. **A `pcap` artifact family**: after generation, if `artifacts.mode` selects it, compile
   `flows.jsonl` with PacketForge into `artifacts/pcap/<sensor>.pcap` and add a `pcap`
   section to `ARTIFACTS_MANIFEST.json` — mirroring the email artifact family.

Both are additive: they compute nothing new for the existing log outputs and cannot
regress them. PacketForge stays an **optional** dependency; if it's absent, the emitter
still writes `flows.jsonl` and the pcap step is skipped. Real Zeek runs only in CI, where
it diffs the pcap-derived logs against EvidenceForge's own — so "consistent by
construction" is enforced, not asserted.
