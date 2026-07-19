# PacketForge

Deterministic, **Zeek-validated** synthetic PCAPs for threat-hunting training —
consistent with the [EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge)
incident model.

> **Temporary / experimental repository.** PacketForge was built to explore the idea in
> **[EvidenceForge issue #332](https://github.com/Cisco-Talos/EvidenceForge/issues/332)** —
> whether realistic, consistent synthetic PCAPs are feasible alongside EvidenceForge's
> synthetic logs. It's a proof of concept shared for discussion, and may be taken down or
> restructured. With thanks to **David Bianco** and the **EvidenceForge** project (Cisco
> Talos) for the canonical incident model and the #332 discussion that prompted this.

The premise is a test, not a claim: render packets from the same event that produces
the logs, then run **real Zeek** over the result and require its output to match the
logs EvidenceForge already emits. If Zeek agrees, the capture is valid and consistent
by construction. If it doesn't, it's a bug. "Realistic" stops being a matter of taste
and becomes a pass/fail gate.

```
$ packetforge scenario --env office --attack -o incident.pcap
wrote incident.pcap: 214 flows (office, link=ethernet)
wrote incident.GROUND_TRUTH.md — 5 ATT&CK stages

$ packetforge eval incident.pcap
Realism score: 100/100
  OK parseability        30/30  zeek weird/reporter=0, tshark errors/warnings=0
  OK timing_burstiness   25/25  inter-flow gap stdev/mean=2.89 (>=1.5 bursty)
  OK mac_vendor          15/15  1 distinct OUI(s), locally_administered=False
  OK byte_plausibility   15/15  0/117 service conns carry 0 bytes
  OK ttl_plausibility    15/15  observed TTLs=[64, 128]

$ zeek -r incident.pcap && ls *.log
conn.log dns.log http.log ssl.log smtp.log ldap.log smb_mapping.log ...
```

`incident.pcap` opens in Wireshark; `incident.GROUND_TRUTH.md` is the answer key. (`eval`'s
score is a heuristic floor — see [How realistic is it, really?](#how-realistic-is-it-really) for
the honest C2ST verdict.)

## What's in it

- **24 protocols, faithfully rendered** and Zeek-validated: DNS, HTTP, TLS 1.2/1.3
  (controllable JA3/JA4, GREASE, configurable ALPN), **QUIC-era encrypted DNS (DoH/DoT)**,
  SMTP, SSH, FTP, POP3, IMAP, IRC, SIP, DHCP, NTP, SNMP, RADIUS, **LDAP, SMB2/3, Kerberos,
  DCE-RPC** (AD), **LLMNR / NBT-NS / mDNS** (name resolution), **Modbus/TCP** (OT), ICMP —
  plus honest opaque shells for protocols without a full renderer yet. All over **IPv4 or
  IPv6** (dual-stack).
- **Network-tap environments** — corporate `office`, `home`, `ot`, and **cloud**:
  `aws-vpc`, `azure-vnet`, `gcp-vpc`, `oci-vcn`, and a Kubernetes `k8s` overlay — each with a
  real address plan, resolver, vendor MAC OUI, ambient service mix, and capture link type
  (Ethernet SPAN/TAP vs a host `tcpdump`'s cooked Linux SLL).
- **Multi-vantage & overlay capture** — render an incident once, then project it through the
  sensors you actually run: an edge TAP (source-NAT + router hop), a core SPAN (802.1Q VLAN),
  a host `tcpdump`, or a **VXLAN traffic mirror** (AWS VPC Traffic Mirroring / GCP Packet
  Mirroring / K8s CNI overlay, which Zeek decapsulates). Answers "does my detection fire
  *given where my sensors are*." The mirror honors the real cloud invariant that **link-local
  169.254/16 is excluded from mirroring** — IMDS traffic appears only on an on-host vantage.
  Plus **IP fragmentation** as a reassembly / IDS-evasion test.
- **ATT&CK attack library** — phishing kill chains, Kerberoasting/AS-REP roasting, **DCSync**
  (drsuapi `DRSGetNCChanges` from a non-DC host, matched to a real Empire capture), ransomware,
  DNS/DoH tunnelling, an inert **BZAR lateral-movement pack** (remote service creation,
  scheduled task, WMI, admin-share, discovery, PsExec co-detect), **LLMNR/NBT-NS poisoning**
  (Responder-style AiTM), and **cloud** attacks — IMDS credential theft (the Capital One
  shape), cloud-storage exfil, Kubernetes cluster lateral movement. Each carries a
  `GROUND_TRUTH.md`/`.json` answer key. `packetforge list-attacks` enumerates them.
- **Inert by construction** — malicious flows reproduce the detection *signal*, never the
  offensive *capability* (no service binary, command, shellcode, or malware); CI-enforced.
  See [`docs/inert-by-construction.md`](docs/inert-by-construction.md).
- **Detection-CI bundles** (`packetforge bundle`) — the pcap ships with the exact Zeek logs it
  produces, the ATT&CK ground truth, and a consistency manifest: grade a rule against the
  bundle without re-deriving anything.
- **A blind-panel evaluator** (`packetforge eval`) — a heuristic floor (parseability, timing,
  MAC/TTL plausibility), not the realism verdict. The real question — *can a classifier tell
  ours from real?* — is measured by the C2ST audit below, which is honest about where it can.

## Try it

```bash
python -m venv .venv && .venv/bin/pip install scapy pydantic pyyaml cryptography
export PYTHONPATH=src
# a full office intrusion + answer key:
.venv/bin/python -m packetforge scenario --env office --attack -o incident.pcap
# score it (needs zeek + tshark on PATH):
.venv/bin/python -m packetforge eval incident.pcap
# a visual forensic report:
.venv/bin/python -m packetforge report incident.pcap -o incident.html

# a cloud attack — AWS instance-metadata credential theft (the Capital One shape):
.venv/bin/python -m packetforge scenario --env aws-vpc --attack imds-ssrf -o imds.pcap
# the same incident through three sensors (edge TAP / core SPAN / host tcpdump):
.venv/bin/python -m packetforge scenario --env office --attack psexec-lateral --vantages -o inc.pcap
# a self-contained detection-CI bundle: pcap + its Zeek logs + ground truth + a consistency manifest:
.venv/bin/python -m packetforge bundle --env office --attack ransomware -o ransomware-bundle/
```

**The whole story in one run** (~25s; needs zeek+tshark, suricata for detection):

```bash
scripts/demo.sh
```

It generates a Kerberoasting-in-benign-AD capture and walks the full arc: real Zeek
parses it clean, a detection catches the RC4 TTP and stays silent on benign AES auth,
the same rule measurably weakens under **domain-fronting**, an ATT&CK **coverage matrix**
and **Sigma-over-Zeek** score it, five independent tools (Zeek/Suricata/tshark/p0f/pyja3)
agree it's real, and it **transfers** to a real capture.

Detection-lab commands: `detect`, `coverage`, `fp-benchmark`, `sigma`, `robustness`,
`corpus-build`/`corpus-verify` (see [`detection/README.md`](detection/README.md));
cross-validation: `crossval`, `transfer-proof` (see
[`docs/cross-validation.md`](docs/cross-validation.md)). `list-attacks` / `list-evasions`
enumerate the library. A tour of annotated captures with ground truth lives in
[`samples/`](samples/); per-phase design audits in [`docs/audits/`](docs/audits/).

## How it holds up on real data

`packetforge ef-roundtrip <evidenceforge_output>` ingests a real EvidenceForge run,
renders a pcap, and diffs our Zeek against EF's own logs. On the branch-office
scenario (all ~6,500 flows): clean capture, proto/service ~100%, DNS/HTTP/TLS IOC
fields 100%, conn_state 99%, exact byte counts for analyzer-free flows —
[`docs/DESIGN.md`](docs/DESIGN.md) §11.

## How realistic is it, really?

Two different claims, kept separate on purpose:

- **Consistency — proven.** Packets and logs derive from one event and real Zeek reproduces
  the declared fields; the round-trip is a pass/fail gate. As a **consistency / detection-CI
  harness**, that's the solid, load-bearing use case.
- **Indistinguishable-from-real — measured against a real-vs-real floor.** `packetforge
  realism-audit` runs a cross-validated **C2ST** (a gradient-boosted adversary) against real
  captures. The honest question isn't "does synth score 0.5?" — it never will, because *two
  different real captures* already score ~0.98 (different network, era, device mix). It's
  "is synth-vs-real worse than the real-vs-real floor?" Scored with
  [`scripts/baseline_panel.py`](scripts/baseline_panel.py) over a panel of public real captures
  (tcpreplay smallFlows/bigFlows, the Ultimate PCAP, IoT-23 benign): the real-vs-real floor is
  **~0.998** across 10 pairs, and PacketForge's ambient sits at **~0.999 — about +0.002 above
  the floor**, i.e. as separable from real as two real captures are from each other. Caveat kept
  in view: the C2ST is *near-saturated* at this feature resolution, so the sharper remaining signal
  is **within-capture heterogeneity** — real captures vary more across their own timespan than ours
  do. Method, dataset panel and how to reproduce: [`docs/realism-baselining.md`](docs/realism-baselining.md).

So: a consistency/CI harness whose ambient realism now lands at the real-vs-real floor on
flow+fingerprint features, with the honest residual (within-capture variation, and cloud — no
real cloud pcap exists to validate against yet; see the capture kit) called out rather than hidden.

## Status

Working and growing. The full current capability map — protocols, environments, attacks, and
capture modes — is in [`docs/capabilities.md`](docs/capabilities.md). Design and rationale in
[`docs/DESIGN.md`](docs/DESIGN.md); roadmap and honest per-phase audits in
[`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/audits/`](docs/audits/). MIT-licensed, to keep
a future merge into EvidenceForge frictionless.
