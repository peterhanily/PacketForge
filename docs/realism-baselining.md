# Realism baselining — measuring against a real-vs-real floor

How realistic is a synthetic capture? The naive test — "can a classifier tell it from real?" —
has a trap: **a classifier can tell almost any two real captures apart too.** Two genuinely
different real captures (different network, time, device mix, capture vantage) score ~0.98+ on a
cross-validated classifier two-sample test (C2ST). So a synthetic scoring 0.999 against one real
reference means little on its own. The honest question is:

> Is **synth-vs-real** worse than the **real-vs-real floor** — the bar any generator of *novel*
> (non-replayed) traffic could realistically reach?

This doc is the method, the reference panel, the current numbers, and how to reproduce them.

## The tools

- **`packetforge realism-audit --real R.pcap --synthetic S.pcap`** — one C2ST run: a cross-validated
  gradient-boosted AUC, a held-out second learner (Goodhart guard), kernel-MMD, per-service
  (mix-invariant) AUC, and a ranked list of the per-feature *tells* (KS distance × permutation
  importance) to fix. Underpowered comparisons (< 20 flows a side) report **INCONCLUSIVE**, never a
  vacuous 0.5.
- **`scripts/baseline_panel.py --real A.pcap B.pcap … --synth S.pcap`** — the calibrated view: the
  full pairwise AUC matrix over a panel, the **real-vs-real floor** (median of the real pairs), each
  synth-vs-real delta *to that floor*, and a within-source sanity floor (first vs second half of each
  capture — a homogeneous capture scores ~0.5 against itself).

Both read one pipeline (`src/packetforge/realism.py`): `zeek -C -r` for conn.log flow features +
tshark-derived packet features (inter-arrival stats, packet-size stats, TTL/window, TCP-timestamp
presence, and TLS ClientHello shape ≈ JA3). The *same* Zeek/tshark path runs on both sides, so
nothing separates on capture tooling.

## Reading a result

| Signal | Meaning |
|---|---|
| synth-vs-real ≈ real-vs-real floor | as hard to tell from real as two real captures are from each other — **pass** |
| synth-vs-real ≫ floor | a genuine fidelity gap beyond mere population difference — **fix the top tells** |
| within-source ≫ 0.5 | the capture is internally heterogeneous (varies across its own timespan) |
| INCONCLUSIVE | too few flows / too few independent reals to run the test |

Always read the **delta to the floor**, not the distance to 0.5. And weight the per-feature tells:
a high-KS / low-importance tell (e.g. TTL when comparing internet-egress to a LAN) is usually
*population* mismatch, not a fixable fidelity gap.

## The real reference panel

None of these are redistributed here — they are ingested for **local scoring only**, pinned by URL,
never vendored (several licenses forbid rehosting). Downloaded captures live in the gitignored
`realcap/` (or `/tmp`).

| Capture | Kind | Baselines | License |
|---|---|---|---|
| tcpreplay **smallFlows** / **bigFlows** | benign, mixed | generic ambient (HTTP/TLS/DNS) | free (tcpreplay) |
| **The Ultimate PCAP** (Weber) | benign, AD protocol zoo | office per-service fingerprints | attribution |
| **IoT-23** benign (Stratosphere) | benign, consumer IoT LAN | `home` env | CC-BY-4.0 |
| **MACCDC** (Netresec) | mixed, real AD under attack | `office` ambient + SMB-lateral | research |
| **Malware-Traffic-Analysis.net** | malicious | `c2-beacon` (real JA3/JA3S), Trickbot SMB | no-rehost |
| **sbousseaden/PCAP-ATTACK**, **OTRF Security-Datasets** | malicious, per-technique | BZAR svcctl, kerberoast | ARR / MIT |
| **CTU-13 / WannaCry** (Stratosphere) | mixed | botnet C2, ransomware SMB | CC-BY |
| **4SICS**, **automayt/ICS-pcap** | benign OT | `ot` (Modbus/DNP3/S7) | research |

A fuller 14-dataset survey (with download hints and the honest gaps) informed this panel.

## Current numbers (benign ambient)

Panel of 5 independent real captures (smallFlows, bigFlows, Ultimate PCAP, two IoT-23 benign):

```
real-vs-real floor:  0.998   (10 pairs, range 0.963–1.000)
synth home (ambient): 0.999  (floor + 0.002)
within-source:       real 0.65–0.83   synth ~0.65–0.71 (was ~0.53)
arrival self-similarity (Hurst): real ~0.62   synth ~0.78 (was ~0.5 Poisson)
```

**Read:** the improved ambient sits ~+0.002 above the real-vs-real floor — essentially at it. The
cross-capture metric is near-saturated (any two reals ~0.99). The sharper signal is the within-source
baseline (how much a capture varies across its own timespan): a seeded non-stationary activity
envelope (heavy-tailed ON/OFF arrivals + drifting service mix / resp-orig balance / reset rate) moved
synth from a stationary ~0.53 into the real band, and `hurst_aggvar` confirms the arrival process is
now self-similar rather than Poisson. Measured, not assumed.

### What this measurement retired
The measure→fix→re-measure loop closed several tells against this panel:
- **TLS ClientHello / TCP timestamps / IP-ID** (TLS 1.3 key_share/ALPN, per-OS timestamps and IP-ID):
  absent from the top tells in every real comparison after the fix.
- **Inter-arrival timing** (`ia_mean`): the `realistic` texture drops it from KS 0.71 → 0.49.
- **Originator byte volume** (`l_orig_bytes`): giving ambient clients real request/upload sizes drops
  it from KS 0.53 → 0.21 (importance 0.131 → 0.028).

## Attack fidelity (per-technique)

Bulk C2ST needs volume; single-technique captures are better compared **field-for-field** on the
Zeek log the detection keys on. Example — real PsExec (sbousseaden/OTRF) vs `psexec-lateral`, on
`dce_rpc.log` `endpoint::operation`: after enriching the svcctl sequence and adding the
`epmapper::ept_map` endpoint-mapper lookup, PacketForge's operation set matches the real capture
exactly (bar `CreateServiceW` vs a WOW64 variant). Anchoring against real captures also
drove `dcsync`: a real Empire DCSync capture (OTRF `empire_dcsync`, over an unsealed dynamic-port
channel where Zeek does log the ops) field-diffed against the renderer showed the full real sequence
(`DRSBind → DRSDomainControllerInfo → DRSCrackNames → DRSBind → DRSGetNCChanges → DRSUnbind`), which
`build_dcsync` now reproduces **field-for-field** (same Zeek `dce_rpc` operation multiset, still inert).
`kerberoasting` was confirmed to emit the `rc4-hmac`/etype-23 TGS-REP roast signature structurally.

Cloud attacks were baselined against real cloud/container captures (a k8s cryptojacking honeypot, real
Istio mesh, real Azure/AWS VNet captures — see the cloud gaps below): `k8s-lateral`'s attack shape
(API-server → `/apis/apps` DaemonSet → `kube-system`) matches the real capture, though a real cluster's
API traffic is opaque mTLS so it's a structural, not byte-level, anchor.

**Detection-outcome gate.** `packetforge realism-detection` compares the ET-rule alert distribution
of a synthetic analog to the real reference (Jensen-Shannon divergence). The analog's benign
false-positive surface is now **conditioned on the reference's own measured alert rate** — a clean
reference that trips no rules gets no fabricated FP surface, rather than a hardcoded 180/hr that made
the analog over-alert (`alert_js` 1.0 → 0.0 on a clean reference).

## The cloud gap

Cloud is the hardest env to baseline: most cloud network data is exposed only as flow logs, never
packets. A dedicated survey found what real cloud pcap *does* exist (a k8s cryptojacking honeypot,
real Istio mesh, real Azure/AWS VNet captures, a real DCSync) and proved where none can — see the
catalog in [`cloud-baselines.md`](cloud-baselines.md). `k8s-lateral`, the k8s/azure/aws substrate,
mesh-L7, and `dcsync` have real anchors; `imds-ssrf`, `cloud-exfil` content, and `oci-vcn` structurally
cannot (IMDS is link-local and excluded from all mirroring — which corroborates PacketForge's own
mirror invariant) and stay **UNVALIDATED against real traffic**, validated structurally or minted
on-host with the `scripts/cloud-capture/` kit.

## Reproduce

```bash
export PYTHONPATH=src
# 1. download the panel captures locally first (see the table's sources), into /tmp or realcap/
# 2. render a synthetic to score:
python -m packetforge scenario --env home --volume busy --duration 300 --seed 7 \
  --texture realistic -o /tmp/synth-home.pcap
# 3. the calibrated panel (floor + synth delta):
python scripts/baseline_panel.py \
  --real /tmp/smallFlows.pcap /tmp/bigFlows.pcap /tmp/ultimate.pcapng /tmp/iot23_*.pcap \
  --synth /tmp/synth-home.pcap
```
