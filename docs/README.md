# Documentation

Start at the [project README](../README.md) if you have not read it. This page says what every
other page is for.

## If you are here to

| | |
|---|---|
| Understand what this is | [concepts](concepts.md), then the [sample gallery](../samples/) |
| Check whether it covers your protocol, network or technique | [capabilities](capabilities.md) |
| Put it in a detection pipeline | [detection CI](detection-ci.md), then [grading a ruleset](../detection/README.md) |
| Decide whether it is safe to run and redistribute | [inert by construction](inert-by-construction.md), then [SECURITY](../SECURITY.md) |
| Audit the realism claim | [validation](validation.md) |
| Audit a reconstruction of a real incident | [correspondence](correspondence.md), then [the sample 18 scoring](exploitgym-postmortem-delta.md) |
| Build on it or merge it | [DESIGN](DESIGN.md), then [ROADMAP](ROADMAP.md) |

## Reference

**[concepts.md](concepts.md).** The four gates, the difference between ground truth and a
reconstruction, and the glossary the other pages assume.

**[capabilities.md](capabilities.md).** What PacketForge renders today: protocols, environments,
capture modes, the attack library, and the artifacts each run produces. This page owns the counts.
Everywhere else links here rather than restating them.

**[DESIGN.md](DESIGN.md).** How it is built. The Flow IR, the compile layer, one renderer per
protocol, how determinism is enforced, and the path into EvidenceForge.

## How to use it

**[detection-ci.md](detection-ci.md).** PacketForge as a fixture source: a rule must fire on the
attack capture and stay quiet on the benign twin rendered from the same seed. Includes the pytest
form, export to `suricata-verify`, and a GitHub Actions job.

**[../detection/README.md](../detection/README.md).** Grading a ruleset by hand: an ATT&CK coverage
matrix, a false-positive benchmark, Sigma over Zeek logs, and a regression corpus.

## Evidence

**[validation.md](validation.md).** Gates 1 to 3. What each one measures, the commands, the current
numbers against real captures, and the residual gaps. Read this before quoting any realism figure.

**[correspondence.md](correspondence.md).** Gate 4. How a reconstruction of a real incident is
checked against the sources that license it, and what that check does and does not promise.

**[exploitgym-postmortem-delta.md](exploitgym-postmortem-delta.md).** A capture built from two
disclosure posts, scored four days later against the technical post mortem that followed. One
technique right, two roughly right, four wrong, eleven missing. The capture still ships, and CI
asserts that it still fails Gate 4.

**[inert-by-construction.md](inert-by-construction.md).** Why a capture that models ransomware or
lateral movement is safe to run, and the tests that enforce it.

## Appendix

Record rather than reference. Accurate when written, kept because the argument or the measurement
still matters.

**[appendix/adr-001-ir-compiler.md](appendix/adr-001-ir-compiler.md).** The decision to build an IR
compiler coupled to a versioned contract, rather than a log post-processor or an emitter inside
EvidenceForge.

**[appendix/feasibility-evidence.md](appendix/feasibility-evidence.md).** The 2026-07 proof of
concept that justified building this at all, with the measured field-by-field comparison.

**[appendix/realism-ratchet-history.md](appendix/realism-ratchet-history.md).** How the Gate 2
adversary's AUC was driven from 1.0 to 0.974 over five conditioning passes, and what each pass
retired.

**[appendix/cloud-baselines.md](appendix/cloud-baselines.md).** What real cloud packet capture
exists for baselining, and where none can exist even in principle.

## Figures

The diagrams in these pages are generated. Edit [`../scripts/make-figures.py`](../scripts/make-figures.py)
and run it to rebuild both the light and dark variants:

```bash
python3 scripts/make-figures.py docs/img
```
