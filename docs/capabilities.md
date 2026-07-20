# PacketForge capabilities

What PacketForge can render today. Everything below is deterministic, Zeek-validated, and
inert (fake traffic, true labels). `packetforge list-attacks` and `--list-envs` enumerate the
live sets; this page is the guided map.

## Protocols (24)

Rendered faithfully enough that real Zeek reads the fields back, over **IPv4 or IPv6**:

| Family | Protocols |
|---|---|
| Web / TLS | HTTP, TLS 1.2/1.3 (controllable JA3/JA4, GREASE, configurable ALPN), **DoH / DoT** (encrypted DNS) |
| Name resolution | DNS (A/AAAA/…), **LLMNR, NBT-NS, mDNS** |
| Active Directory | **Kerberos** (AS/TGS, real enctypes → RC4-downgrade visible), **LDAP**, **SMB2/3** (with an inert **NTLMSSP** session-setup that populates Zeek `ntlm.log` — the LLMNR-poisoning capture), **DCE-RPC** (svcctl, samr, srvsvc, winreg, atsvc, IWbemServices, **epmapper**) over SMB named pipes *or* **ncacn_ip_tcp** (raw DCE-RPC on 135 — the `ept_map` endpoint resolution real tools do first) |
| Mail | SMTP, POP3, IMAP |
| Infrastructure | DHCP, NTP, SNMP, RADIUS, SSH, FTP, SIP, IRC, ICMP |
| OT / ICS | **Modbus/TCP** |
| Opaque shells | honest sized TCP/UDP shells for protocols without a full renderer yet |

## Environments (9)

Each shapes the address plan, resolver, vendor MAC OUI, host-OS mix, ambient service mix, and
capture link type (Ethernet SPAN/TAP vs a host `tcpdump`'s cooked Linux SLL):

- **On-prem:** `office` (corporate AD LAN), `home`, `ot` (flat ICS segment)
- **Cloud:** `aws-vpc`, `azure-vnet`, `gcp-vpc`, `oci-vcn` — real VPC ranges, resolvers, and
  metadata-service quirks, captured host-side — plus a provider-agnostic `cloud` fallback
- **Kubernetes:** `k8s` — a pod network (Flannel/Calico CNI), seen at a mirror collector

## Advanced networking & capture

- **Multi-vantage projection** — render an incident once, then see it from the sensors you
  actually run: an edge TAP (source-NAT + a router-hop TTL decrement), a core SPAN (802.1Q
  VLAN), or a host `tcpdump` (only its flows, cooked SLL). CLI: `scenario --vantages`.
- **VXLAN traffic mirroring / CNI overlay** — a VPC Traffic Mirror (AWS), Packet Mirroring
  (GCP), vTAP (Azure), or a K8s VXLAN overlay: each frame encapsulated to a collector VTEP,
  which Zeek decapsulates to the inner conn + a `tunnel.log`. CLI: `scenario --mirror`. Enforces
  the real cloud invariant that **link-local 169.254/16 is excluded from mirroring** — so IMDS/SSRF
  traffic renders only on an on-host vantage, never in a mirror capture (as AWS/GCP mirroring does).
- **IP fragmentation** — a reassembly / IDS-evasion primitive; Zeek reassembles to the same
  flows. CLI: `scenario --fragment BYTES`.
- **Capture texture** — `clean`, `realistic` (RTT jitter, retransmits, dup-ACKs), and
  `conditioned` (heavy-tailed timing, reference-matched marginals).
- **Signature-conditioned benign surface** — invert the open ET Open ruleset to reproduce a
  real reference's *specific* benign alert signatures (not just their rate), so the analog's
  false-positive distribution matches the reference (`alert_js` → ~0.1). Refuses to synthesise
  MALWARE/CNC triggers. See [`realism-scorecard.md`](realism-scorecard.md#signature-conditioning).

## Attack library (ATT&CK-mapped, inert, ground-truthed)

| Tactic | Attacks |
|---|---|
| Initial Access / C2 | `phishing-intrusion`, `ipv6-c2`, `doh-tunnel`, `dot-tunnel` |
| Credential Access | `kerberoasting` (TGS-REP RC4/etype23 for service SPNs), `asrep-roasting`, `brute-force`, **`dcsync`** (drsuapi DRSGetNCChanges from a non-DC host, T1003.006), **`llmnr-poisoning`** (Responder AiTM → inert NTLM capture in `ntlm.log`, T1557.001), **`imds-ssrf`** (cloud IMDS, T1552.005) |
| Discovery | `port-scan`, `share-discovery`, `account-discovery` |
| Lateral Movement / Execution | **`remote-service`, `scheduled-task`, `wmi-exec`, `admin-share-transfer`, `remote-registry`, `psexec-lateral`** (the BZAR pack), **`k8s-lateral`** |
| Exfiltration / Impact | `dns-exfil`, `cloud-exfil` (T1567.002), `ransomware`, `ddos-syn-flood` |

The BZAR lateral-movement pack is validated against the real MITRE
[BZAR](https://github.com/mitre-attack/bzar) analytic — the notices actually fire. See
[`inert-by-construction.md`](inert-by-construction.md).

## Outputs

- **`scenario`** — a composed capture (`.pcap`) + a `GROUND_TRUTH.md`/`.json` answer key.
- **`bundle`** — a self-contained detection-CI package: the pcap, the exact Zeek logs it
  produces, the ground truth, and a `manifest.json` recording the consistency result and a
  content hash. Grade a rule against it without re-deriving anything.
- **Detection lab** — `detect`, `coverage`, `fp-benchmark`, `sigma`, `robustness`,
  `corpus-build`/`corpus-verify`; **cross-validation** — `crossval`, `transfer-proof`; a
  visual **`report`**; and the **`eval`** realism scorecard.
- **Real-C2 transfer proof** — reproduce a real malware family's observable network signal in an
  inert beacon so a *real published* detection fires on it (zero malware). Four JA3 families
  (Metasploit SSL/CCS scanners, Dridex, Gootkit) whose ClientHello trips a standalone ET Open
  `ja3.hash` rule, and four HTTP-C2 frameworks (Cobalt Strike, Sliver, Mythic, Havoc) rendered
  with their default URIs / User-Agents / marker headers. The proof requires the same real rule to
  fire on an inert reference *and* its independently-rebuilt analog. Vendored fingerprints are
  cited facts from CC0 / public threat intel.
- **Realism baselining** — `realism-audit` (C2ST vs a real reference) and
  [`scripts/baseline_panel.py`](../scripts/baseline_panel.py), which scores synthetic against a
  **panel of real public captures** and reports the honest real-vs-real floor. Method + current
  numbers: [`realism-baselining.md`](realism-baselining.md).
- **Cloud self-capture kit** — [`scripts/cloud-capture/`](../scripts/cloud-capture/): capture your
  own real cloud reference (IMDS SSRF / storage exfil / k8s overlay) to validate the cloud scenarios,
  since no public real cloud pcap exists.

See [`../samples/`](../samples/) for a 17-capture tour, and [`DESIGN.md`](DESIGN.md) for the
architecture and the consistency-by-construction validation gate.
