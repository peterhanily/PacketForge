# PacketForge — project context for coding agents

## What this is
A companion to [EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) that
generates deterministic, validated synthetic PCAPs consistent with EvidenceForge's
canonical incident model. Proposed in EvidenceForge issue #332. Read
[`docs/DESIGN.md`](docs/DESIGN.md) before implementing anything.

## Hard constraints
- **Never push to EvidenceForge, open PRs against it, or comment on its issues
  without the user's explicit approval.** PacketForge is developed in its own repo;
  any EvidenceForge-facing change is drafted here for review first.
- **Deterministic only.** No LLM calls and no unseeded randomness in the generation
  path. Same input must produce byte-identical PCAPs (matching EvidenceForge's
  engine contract).
- **Consistency is the product.** Packets derive from the canonical event / Flow IR,
  never from re-parsing lossy logs. Every change must keep the Zeek round-trip green.

## Validation gate (see DESIGN.md §7)
A change to the generator is not done until, on the affected flows:
`zeek -r out.pcap` emits no `weird.log`/`reporter.log`; `tshark -z expert` shows zero
errors/warnings; and Zeek's conn/dns/http/ssl logs match EvidenceForge's own emitter
output field-for-field.

## Design values (borrowed from EvidenceForge; honor them)
Canonical single source of truth · renderer-per-protocol · data-driven fingerprint
config · ground-truth manifest · built-in validation as a first-class deliverable ·
honest scope (opaque TCP shells for binary protocols, no fake full-take).
