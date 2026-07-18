# PacketForge Roadmap — toward exceptional

**North star:** the tool a threat hunter would actually train on — broad protocol
coverage, realism that survives an expert eye *and* a blind LLM panel, coherent
ATT&CK-mapped incidents shipped with ground truth, all provably consistent with
EvidenceForge's logs, and a clean opt-in path into EvidenceForge itself.

> **Status — the phase A–E hardening plan is complete**
> (faithful Kerberos + AD roasting attacks; realistic-mess texture and
> evasion-robustness measurement; a detection lab v2 with coverage matrix,
> FP benchmark and Sigma-over-Zeek; a transfer proof with multi-tool
> cross-validation; and a tight `scripts/demo.sh`). The one carried-forward
> gap: the transfer proof needs a real *malware* sample to finish.

> **Update — the interim expansion is complete.** Beyond the A–E plan, an eight-phase
> capability expansion landed: multi-vantage capture, encrypted-DNS (DoH/DoT) + configurable
> ALPN, LLMNR/NBT-NS/mDNS poisoning (Responder AiTM), IPv6/dual-stack, cloud environments
> (AWS/Azure/GCP/OCI) with IMDS/exfil attacks, VXLAN traffic mirroring + a Kubernetes overlay,
> IP fragmentation, and self-contained detection-CI bundles. The current capability map is in
> [`capabilities.md`](capabilities.md).

## Done (phases 0–2)
Deterministic IR compiler + real-Zeek round-trip gate; 14 faithful protocols;
network-tap environments (office/home/cloud/ot, Ethernet vs Linux-SLL); concurrent
scenario composer; EvidenceForge log-ingest round-trip (all ~6.5k flows, clean,
~100% on IOC fields); realism basics (JA3, GREASE, TCP timestamps, TLS 1.2/1.3).

---

## Phase 3 — Protocol breadth ("everything a hunter meets")
One repeatable pattern per protocol: IR model + renderer + one Zeek-validated test.
Acceptance: the right Zeek analyzer log appears, zero malformed/weird. Ordered by
hunt value:

- **3a — Active Directory / Windows (do first — where intrusions live):**
  Kerberos (AS-REQ/TGS-REQ), LDAP (bind/search), SMB2/3 (negotiate/session/tree),
  MSRPC/DCE-RPC, NetBIOS-NS, RDP, WinRM.
- **3b — Common & legacy services:** Telnet, TFTP, POP3/IMAP, SIP/RTP (VoIP), IRC,
  MQTT, Redis, MySQL/MSSQL/PostgreSQL.
- **3c — Modern / encrypted:** QUIC, DoH, DoT, HTTP/2, WireGuard, IPsec/IKE.
- **3d — OT/ICS:** S7comm, DNP3, EtherNet/IP, BACnet (Modbus done).
- **3e — LAN discovery:** ARP, mDNS, LLMNR, SSDP, DHCPv6, ICMPv6/NDP.

## Phase 4 — Deep realism (survive the expert eye)
- **Fingerprint fidelity:** p0f-exact TCP option ordering per OS; a real JA3/JA4
  library (Chrome/Firefox/Edge/curl/python/Go + known malware families).
- **TCP dynamics:** retransmits, dup-acks, window scaling, out-of-order, realistic
  RTT/jitter, MSS clamping.
- **Timing:** diurnal/bursty ambient (Hawkes-like); C2 beacon cadence + jitter
  profiles.
- **TLS depth:** realistic certificate chains (CN/SAN/issuer), session resumption,
  ALPN; optional SSLKEYLOGFILE so a training TLS session can be decrypted on purpose.
- **Payload realism:** file transfers with real magic bytes + hashes; realistic
  HTTP bodies.
- **Blind-panel evaluation:** an LLM/heuristic "does this look synthetic?" panel
  (mirrors EvidenceForge's approach) plus a multi-tool cross-check
  (Zeek + Suricata + tshark expert + p0f + a JA3 tool + RITA). *Acceptance: the panel
  can't reliably separate ours from real captures; Suricata fires the expected alerts
  and no spurious malformed events.*

## Phase 5 — Scenarios & attack realism (the training value)
- **ATT&CK-mapped storylines:** recon → initial access → C2 → discovery → lateral
  movement → collection → exfil, each with the correct protocol footprint and
  high-pyramid signal (tool fingerprints, C2 behavior, not just atomic IOCs).
- **Scenario library:** ready-made, tunable incidents — APT beaconing, ransomware,
  data exfil, insider, OT attack.
- **Ground truth per capture:** a `GROUND_TRUTH` doc listing malicious flows, IOCs,
  ATT&CK IDs, and hunt hints — so every pcap is training-ready.
- **Scale & coherence:** multi-host, multi-segment, concurrent; the storyline
  derivable from the same scenario EvidenceForge uses, so logs and packets agree.

## Phase 6 — Quality, eval & the polished demo
- **Built-in quality score:** parseability / plausibility / consistency / timing —
  mirroring EvidenceForge's 4-pillar eval, so users know how good a capture is.
- **CI:** GitHub Actions running the Zeek/Suricata round-trip on every change.
- **The demo repo:** strong README; a gallery of downloadable example captures
  (`.pcap` + Zeek logs + ground truth + Wireshark screenshots); a 60-second
  quickstart; `pip`/`uv` install; clean docs.

## Phase 7 — EvidenceForge integration (endgame, gated on approval)
- A **tiny additive `FlowSpecEmitter`** in EvidenceForge: canonical event → flow IR.
  This closes the one real gap (exact payload volumetrics) that log-reconstruction
  can't.
- PacketForge wired as an **opt-in `pcap` artifact family** behind the existing
  `artifacts.mode`, gated by the Zeek round-trip in CI.
- Draft PR prepared **locally for review — never pushed without sign-off.**

---

## Recommended sequence
**3a (AD pack) → 5 (scenarios + ground truth) → 4 (realism + blind panel) →
6 (eval + demo repo) → 7 (integration).** Interleave: cut a first polished demo repo
(6) the moment 3a + 5 produce one compelling, coherent intrusion — don't wait for
completeness.

## "Exceptional" means, concretely
Broad coverage · survives a blind panel · coherent ATT&CK incidents with ground truth
· one-command usability · provably log-consistent · clean opt-in EvidenceForge path.
