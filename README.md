# PacketForge

Deterministic, **Zeek-validated** synthetic PCAPs for threat-hunting training and
detection engineering — consistent with the
[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) incident model.

> **Temporary / experimental repository.** PacketForge was built to explore the idea in
> **[EvidenceForge issue #332](https://github.com/Cisco-Talos/EvidenceForge/issues/332)** —
> whether realistic, consistent synthetic PCAPs are feasible alongside EvidenceForge's
> synthetic logs. It's a proof of concept shared for discussion, and may be taken down or
> restructured. With thanks to **David Bianco** and the **EvidenceForge** project (Cisco
> Talos) for the canonical incident model and the #332 discussion that prompted this.

The premise is a test, not a claim: render packets from the same event that produces the
logs, then run **real Zeek** over the result and require its output to match. If Zeek
agrees, the capture is valid and consistent by construction. If it doesn't, it's a bug.
"Realistic" stops being a matter of taste and becomes a pass/fail gate.

```
$ packetforge scenario --env office --attack -o incident.pcap
wrote incident.pcap: 132 flows (office, link=ethernet)
wrote incident.GROUND_TRUTH.md — 5 ATT&CK stages

$ packetforge validate incident.yaml     # real Zeek must reproduce the declared fields
PASS  (…/… flows matched)  zeek weird=0 reporter=0  tshark errors=0

$ zeek -r incident.pcap && ls *.log
conn.log dns.log http.log ssl.log x509.log smtp.log ldap.log kerberos.log smb_files.log …
```

`incident.pcap` opens in Wireshark; `incident.GROUND_TRUTH.md` is the answer key.

## What's in it

- **21 protocols, faithfully rendered** and Zeek-validated: DNS, HTTP, TLS 1.2/1.3
  (controllable JA3/JA4, GREASE, **real X.509 certificates**), SMTP, SSH, FTP, POP3, IMAP,
  IRC, SIP, DHCP, NTP, SNMP, RADIUS, **LDAP, SMB2/3, faithful Kerberos** (AS/TGS with real
  enctypes), **Modbus/TCP** (OT), ICMP.
- **Extractable artifacts** — a forensic toolchain can pull real objects out of a capture:
  typed HTTP files (PDF/PE/PNG/ZIP…), TLS certificates (openssl-valid), SMB and FTP file
  transfers, SMTP email. Captures dissect in tshark/Wireshark with zero malformed packets.
- **Network-tap environments** — `office / home / cloud / ot` — shaping the address plan,
  host OS, vendor MAC OUI, ambient service mix, and **capture link type** (Ethernet for a
  SPAN/TAP, Linux SLL for a host `tcpdump`).
- **ATT&CK intrusions with ground truth** — phishing → C2 → discovery → lateral → exfil,
  Kerberoasting, AS-REP roasting, DNS tunneling, ransomware, and more — each mapped to a
  technique with a `GROUND_TRUTH.md`/`.json` answer key. Plus **evasion modifiers**
  (domain-fronting, JA3 randomization, slow-and-low…).
- **A detection lab** — run your Suricata rules or Sigma-over-Zeek against generated
  attacks + benign noise and get a coverage matrix, a false-positive rate, and a versioned
  regression corpus.
- **Multi-tool cross-validation** — every capture parsed by independent real tools
  (Zeek, Suricata, tshark, p0f, JA3/JA4) so "it's realistic" is checked, not asserted.
- **Adversarial realism validation** — beyond "does it parse", it asks "can a classifier
  tell it from real traffic?": a cross-validated **C2ST** audit, a **detection-outcome**
  comparison (do detections behave the same on synthetic as on a real reference?), a human
  **blind panel**, and a versioned **scorecard** that tracks realism over time and records
  the current gap.
- **Deterministic** — same input → byte-identical PCAP, across runs and machines.

## Try it

```bash
python -m venv .venv && .venv/bin/pip install -e .        # needs Python 3.9+
export PYTHONPATH=src
# a full office intrusion + answer key:
.venv/bin/python -m packetforge scenario --env office --attack -o incident.pcap
# compile + check against real Zeek/tshark:
.venv/bin/python -m packetforge validate flows/c2_beacon.yaml
# a visual forensic report:
.venv/bin/python -m packetforge report incident.pcap -o incident.html
```

The realism-validation suite (C2ST audit, scorecard) needs a few extra packages —
`pip install -e ".[realism]"`; everything else runs on the base install.

**The whole story in one run** (~25s; needs zeek+tshark, suricata for detection):

```bash
scripts/demo.sh
```

Detection-lab commands: `detect`, `coverage`, `fp-benchmark`, `sigma`, `robustness`,
`corpus-build`/`corpus-verify` (see [`detection/README.md`](detection/README.md));
cross-validation: `crossval`, `transfer-proof`, `malware-transfer` (see
[`docs/cross-validation.md`](docs/cross-validation.md)); realism validation: `realism-audit`,
`realism-detection`, `blind-panel`, `realism-scorecard` (see
[`docs/realism-scorecard.md`](docs/realism-scorecard.md)). `list-attacks` / `list-evasions` /
`list-families` enumerate the libraries. A guided tour of eight annotated captures — each
with its real Zeek logs and an answer key — lives in [`samples/`](samples/).

## How it holds up on EvidenceForge data

`packetforge ef-roundtrip <evidenceforge_output>` ingests a real EvidenceForge run,
renders a pcap, and diffs Zeek's output against EF's own logs. On the branch-office
scenario (all ~6,500 flows): clean capture, proto/service ~100%, DNS/HTTP/TLS IOC fields
100%, conn_state 99%, exact byte counts for analyzer-free flows. See
[`docs/DESIGN.md`](docs/DESIGN.md) and the
[integration sketch](integration/evidenceforge/README.md).

## Scope & honesty

This is a **network-layer** tool. Its strengths are consistency-by-construction, determinism,
and validation against real tools. Its boundaries are measured rather than asserted: the realism
scorecard reports that a classifier can still distinguish the synthetic from real reference
traffic today (verdict: `gap`), and closing that distance is tracked, ongoing work. Extractable
files are valid containers with benign filler, not real documents; and the detection lab's value
is testing **your** rules, not the small ruleset it ships with. Full design and rationale in
[`docs/DESIGN.md`](docs/DESIGN.md); the realism method and current numbers in
[`docs/realism-scorecard.md`](docs/realism-scorecard.md).

## License

MIT — see [`LICENSE`](LICENSE).
