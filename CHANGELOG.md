# Changelog

## Unreleased

### Added
- **RDP + WinRM breadth** — two of the top enterprise-risk protocols after SMB.
  **`rdp-bruteforce`** (T1110.001/T1021.001) renders an RDP username sweep: each attempt is an inert
  X.224 Connection Request carrying a candidate username in the `mstshash` cookie, which real Zeek
  reads into `rdp.log` (+ a valid Connection Confirm so the CR/CC pair logs). **`winrm-lateral`**
  (T1021.006) drives a WSMan shell as SOAP `POST /wsman` on 5985 with the `Microsoft WinRM Client`
  User-Agent (http.log). Adds `resp_literal_hex` to the opaque renderer (a response-side literal, for
  the RDP CC). Both are Zeek-round-trip clean and inert (no credentials, session, or command).
- **Detection-CI surface** (`detection_ci.py`, `packetforge suricata-verify`) — PacketForge as a
  unit-test fixture source for Detection-as-Code. `packetforge_fixture(attack)` renders a
  deterministic attack capture *plus* a benign-only twin (same env/seed, no attack), so a pytest
  test asserts a rule *fires* on the attack (`fx.fires(rules)`) and stays *quiet* on benign
  (`fx.quiet_on_benign(rules)`) — the two assertions every detection needs. `write_suricata_verify`
  / the `suricata-verify` CLI export a fixture as a standard suricata-verify test (`test.pcap` +
  `test.yaml` with a frozen golden alert set). Usage + a GitHub Action snippet in
  [`docs/detection-ci.md`](docs/detection-ci.md).
- **Validation trinity** (`trinity.py`, `packetforge trinity`) — scores a synthetic capture on the
  three axes the synthetic-data field uses instead of one scalar: **fidelity** (protocol conformance
  + the C2ST vs a real-vs-real floor), **utility** via **TSTR** (a flow→service classifier trained on
  the synthetic classifies *real* flows nearly as well as one trained on real — measured ~0.94 vs a
  ~0.98 train-on-real baseline; the "does it transfer?" leg the field says to lead with), and
  **non-leakage** via **DCR** (each synthetic flow's distance to the closest real flow, vs the
  real-internal distance — proving the traffic is generated, not replayed). Reuses the existing
  per-flow feature extraction; reports all three legs, never a single number.
- **Real-C2 fingerprint transfer proof** (`c2_fingerprints.py`) — an inert beacon can now
  reproduce a *real* malware family's observable network signal so a *real published* detection
  rule fires on it, with zero malware. Vendored, cited fingerprints (from CC0 / public threat
  intel): four JA3 families (Metasploit SSL/CCS scanners, Dridex, Gootkit) whose ClientHello JA3
  is MD5-verified to match a standalone ET Open `ja3.hash` rule, and four HTTP-C2 frameworks
  (Cobalt Strike, Sliver, Mythic, Havoc) with their default URIs, User-Agents, and marker headers
  (`X-Havoc`, Mythic `?q=`/`Server: NetDNA-cache/2.2`, Sliver's extension scheme, CS malleable
  paths + SMB pipe names). The transfer proof runs the same real ET rule on an inert reference
  *and* its independently-rebuilt analog and requires the same verdict (JA3 read back via
  Suricata, which — unlike tshark — computes it for TLS 1.0/1.1). Also fixes TLS-version fidelity:
  the ClientHello handshake version now honors the JA3's first field, so TLS-1.0/1.1 malware
  fingerprints hash correctly (`renderers/tls.py`), and `orig_literal_hex` support on the opaque
  renderers (shared with Phase 1). Inert by construction — reproduces the detection signal, never
  the capability.
- **Signature-conditioned benign surface** (`signatures.py`) — the benign false-positive surface
  can now reproduce a real reference's *specific* alert signatures, not just their rate. The engine
  parses the pinned ET Open ruleset and, for a target `{signature: count}` histogram, *inverts* the
  rules the reference trips — dispatching by predicate shape (http.user_agent / http.uri → an HTTP
  request; raw content on a port → an opaque literal prefix, via new `orig_literal_hex` on the
  opaque renderers; reputation IP-list → an inbound touch). `packetforge realism-detection` applies
  it automatically. Measured on `smallFlows`: **`alert_js` 1.0 → ~0.10** (5/5 signatures reproduced,
  zero collateral). Refuses to synthesise MALWARE/CNC triggers (would poison ground truth); unmatched
  signatures are surfaced, never silently dropped. Closes the last open realism gate.
- **NTLM capture in LLMNR poisoning** — a new inert `NtlmAuth` capability on `SmbL7` renders a real
  NTLMSSP session-setup exchange (NEGOTIATE → CHALLENGE → AUTHENTICATE) inside SMB2, so real Zeek
  reads the captured `domain\user` and workstation back into `ntlm.log`. `build_llmnr_poisoning` now
  wires it in, so the Responder-style flow delivers the credential-capture payoff (`CORP\jsmith` from
  `WKS-042`) rather than just the LLMNR answer. Inert by construction: the NT/LM responses are fixed
  filler, never an offline-crackable hash. The blob is raw NTLMSSP (not SPNEGO-wrapped), so every
  identity field populates while `ntlm.log` `success` stays honestly unset (it derives only from a
  SPNEGO `gssapi_neg_result`).
- **DCSync attack** (`dcsync`, T1003.006) — `build_dcsync` renders drsuapi `DRSGetNCChanges` from a
  non-DC host over `ncacn_ip_tcp`, the directory-replication credential-theft signal. Anchored
  field-for-field against a real Empire DCSync capture (OTRF `empire_dcsync`): the full real operation
  sequence (`DRSBind → DRSDomainControllerInfo → DRSCrackNames → DRSBind → DRSGetNCChanges →
  DRSUnbind`) now reproduces in `dce_rpc.log`, still inert (opaque replication stubs, no real secrets).
- **Reference-conditioned realism scorecard** — `realism-scorecard` + `scorecard.py` turn "realistic
  enough?" into a tracked artifact (`realism-scorecard.json`) scored against a real reference *and* a
  real-vs-real floor: a cross-validated C2ST AUC vs a measured `real_baseline_auc` (calibrated over
  multiple `bigFlows` windows, with a within-source `temporal_baseline_auc` as a stricter reference).
  A five-pass reference-conditioning ratchet drove the ambient C2ST from a trivially-separable 1.0 down
  to the real-vs-real floor (~0.974, kernel-MMD 0.17 → 0.077) by cloning each reference flow's
  bytes/packets/duration/conn_state jointly. Method + numbers in
  [`docs/realism-scorecard.md`](docs/realism-scorecard.md) and
  [`docs/realism-baselining.md`](docs/realism-baselining.md).
- **Self-contained detection-CI bundles** (Phase 8 of the interim roadmap) — `bundle.py`
  (`write_bundle`) and the `bundle` CLI write one directory with `capture.pcap`, the exact Zeek
  logs it produces, the ground-truth answer key, and a `manifest.json` recording a sha256 and the
  consistency result. A detection can be graded against the bundle without re-deriving anything.

### Fixed
- `validation.roundtrip._run_zeek` read the pcap by full path while setting `cwd=workdir`, so a
  relative `keep_dir` made Zeek look for the pcap inside the workdir and find nothing; it now reads
  the pcap by name relative to Zeek's cwd, so the detection lab works with relative output paths.

### Added (earlier)
- **IP fragmentation** (Phase 7 of the interim roadmap) — `compile/fragment.py`
  (`fragment_packets`) splits oversized IPv4 packets into fragments, forcing a sensor to
  reassemble before matching (a benign path-MTU artifact and the classic IDS-evasion
  primitive). Real Zeek reassembles to the same flows; the transform is deterministic and the
  reassembled stream is byte-identical. CLI: `scenario --fragment BYTES`.
- **Cloud simulation II — east-west / overlay** (Phase 6 of the interim roadmap) — VXLAN
  encapsulation in the vantage engine (`Vantage.vxlan_vni` + `mirror_vantage()`): a cloud
  traffic mirror (AWS VPC Traffic Mirroring / GCP Packet Mirroring / Azure vTAP) or a K8s
  VXLAN CNI overlay wraps each frame to a collector VTEP, and Zeek decapsulates it to the
  inner conn + a `tunnel.log` entry. CLI `scenario --mirror`. New `k8s` environment (pod
  CIDR, CoreDNS, CNI MACs) + `k8s-lateral` attack (T1613/T1021 — a compromised pod hits the
  API server then fans out mTLS across the mesh).
- **Cloud simulation I — environments + north-south** (Phase 5 of the interim roadmap) — four
  cloud environments (`aws-vpc`, `azure-vnet`, `gcp-vpc`, `oci-vcn`) with provider-accurate
  VPC ranges, resolvers, and NIC OUIs. New attacks `imds-ssrf` (T1552.005 — instance-metadata
  credential theft at 169.254.169.254, the Capital One shape, with the right per-provider path
  and headers) and `cloud-exfil` (T1567.002 — large HTTPS uploads to the provider's real
  storage SNI). The provider is inferred from the environment name.
- **IPv6 / dual-stack** (Phase 4 of the interim roadmap) — `build_tcp_flow` emits IPv6 when
  the endpoints are v6 (no IP-id, TTL as Hop Limit), so all ~15 TCP protocols work over IPv6;
  the measured summary is L3-version-aware. HTTP/TLS/SMB over IPv6 pass the full validation
  gate, and v4/v6 produce the same conn service+history. DNS AAAA answers carry v6 addresses.
  New attack `ipv6-c2` (T1071.001) — AAAA resolution + HTTPS beaconing over IPv6, which a
  v4-only detection misses.
- **LAN adversary-in-the-middle pack** (Phase 3 of the interim roadmap) — a `NameQueryL7`
  model + `renderers/namequery.py` render LLMNR (udp/5355), NBT-NS (udp/137), and mDNS
  (udp/5353) name-resolution queries with an optional *poisoned* reply; Zeek parses all
  three into `dns.log` (the poisoned LLMNR answer's rdata is the attacker's IP). New attack
  `llmnr-poisoning` (T1557.001) models the Responder flow — victim LLMNR lookups (incl.
  `wpad`), a rogue internal host poisons each, then the victim authenticates to it over SMB.
  A whole new ATT&CK tactic (Credential Access via AiTM).
- **Encrypted-DNS fixtures + configurable TLS ALPN** (Phase 2 of the interim roadmap) —
  `TlsL7.alpn` now controls the advertised ALPN (was hardcoded `h2`); the server echoes
  the selection so Zeek logs it as `ssl.log next_protocol`, and it feeds the JA4
  fingerprint. New attacks `doh-tunnel` (DNS-over-HTTPS to a public resolver's SNI on 443)
  and `dot-tunnel` (DNS-over-TLS on 853, `next_protocol=dot`) model encrypted-DNS C2/exfil
  (T1071.004 / T1572), where the detection is the resolver SNI/IP/port, not DNS content.
- **Multi-vantage-point capture** (`compile/vantage.py`) — render an incident once and
  project it through several sensor placements: an edge TAP (source-NAT of the internal
  subnet to one public IP + a router-hop TTL decrement), a core-switch SPAN (802.1Q VLAN
  tagging), and a host `tcpdump` (cooked Linux-SLL, only that host's flows). Each projection
  is a pure deterministic transform and an independent Zeek-clean pcap of the same event.
  CLI: `scenario --vantages` writes `<out>.<vantage>.pcap` per sensor. Answers "does my
  detection fire given where my sensors actually are." (Phase 1 of the interim roadmap.)

- **BZAR notice verification** — the pack's fixtures are validated against the real BZAR
  analytic (`test_builder_trips_expected_bzar_notice`, opt-in via `PF_BZAR_PATH`): each
  renders, runs Zeek + BZAR, and asserts its declared `ATTACK::*` notice fires. Fixtures were
  tuned so the notices actually trip — discovery issues ≥5 enumeration ops (Discovery
  SumStats), and `psexec-lateral` does an ADMIN$ SMB write + service creation to raise the
  combined `ATTACK::Lateral_Movement_and_Execution`. Ground-truth notices corrected to the
  verified values (svcctl/task/wmi → `Execution`; winreg → no BZAR notice, dce_rpc-only).
- **SMB2 write support** (`SmbL7.write_file`) — CREATE/WRITE/CLOSE pushing inert typed
  content originator→responder, logged by Zeek as `SMB::FILE_WRITE` (lateral tool transfer).

### Fixed
- SMB2 renderer now assigns a **tree id** (echoed on every request) and returns a valid
  **share type** on tree connect, so Zeek resolves the share mapping and records the share
  path (`smb_mapping.log`) — previously empty, which blinded share-name analytics.

### Added (prior)
- **BZAR lateral-movement pack** — a new DCE-RPC-over-SMB renderer (`renderers/dcerpc.py`)
  and `DceRpcL7` IR model, plus eight inert lateral-movement scenario builders
  (`remote-service`, `scheduled-task`, `wmi-exec`, `admin-share-transfer`,
  `share-discovery`, `account-discovery`, `remote-registry`, `psexec-lateral`). Each
  renders the SMB2 named-pipe + DCE-RPC bind + operation-opnum shape so real Zeek names the
  interface and each operation in `dce_rpc.log` — the signal BZAR keys on. Inert by
  construction: no operation-argument fields, opnum-only, zero-filler stubs, CI-enforced
  (`tests/test_bzar_pack.py`). See [`docs/inert-by-construction.md`](docs/inert-by-construction.md).

- Project scaffold and MIT license (merge-compatible with EvidenceForge).
- `docs/DESIGN.md` — design and implementation plan: three implementation methods
  evaluated, the recommended
  IR-compiler approach, V1 scope, the Zeek round-trip validation gate, repo
  structure, and a merge roadmap mapped to EvidenceForge issue #332.
- `docs/feasibility-evidence.md` + `poc/` — a proven proof-of-concept: a canonical
  event rendered to a valid `.pcap` that real Zeek 8.2.1 reads back field-for-field
  (history, conn_state, byte/packet counts, cross-record consistency) with zero
  weird/reporter/expert warnings, deterministically.

### Implemented (V1 core — the Method-C IR compiler)
- **Flow IR** (`models/flowspec.py`): typed, versioned pydantic contract; discriminated
  L7 union (dns/http/tls/icmp/opaque_tcp); transport/L7 consistency validation.
- **TCP core** (`compile/tcp.py`): deterministic SEQ/ACK, MSS segmentation, five
  `conn_state` shapes (SF/S0/REJ/RSTO/RSTR) with graceful + reset teardown, and Zeek
  `history` reconstruction from the emitted packets.
- **Renderers** (`renderers/`): DNS, cleartext HTTP, ICMP echo, and honest opaque-TCP
  shells for binary protocols. Each declares what a correct parser should read back.
- **Fingerprints** (`fingerprints/`): data-driven per-OS TCP profiles (windows_10,
  linux, macos) + resolver, keeping L2-L4 identity consistent with the host OS.
- **Timeline compiler** (`compile/timeline.py`): FlowSet -> per-flow deterministic
  seeding -> renderer dispatch -> time-ordered `.pcap`.
- **Round-trip validator** (`validation/roundtrip.py`): runs real Zeek + tshark and
  diffs their conn/dns/http output against the rendered expectations; the CI gate.
- **CLI**: `packetforge compile` and `packetforge validate`; example `flows/c2_beacon.yaml`.
- **Tests**: 16 passing, including the Zeek round-trip and a teeth-check that a
  deliberately wrong expectation fails the gate. Byte-for-byte deterministic output.

### Added — TLS and SMTP
- **TLS renderer** (`renderers/tls.py`): a real, Zeek-parseable TLS 1.2 handshake
  (ClientHello with SNI/ciphers/extensions, ServerHello, ChangeCipherSpec + opaque
  Finished, opaque application data). Zeek logs `service=ssl`, `established=T`, and the
  correct version/cipher/SNI. **JA3 is controllable** and computed from the same
  numeric client profile (`fingerprints/ja3/generic_browser.yaml`) the ClientHello is
  built from, so the fingerprint agrees with the bytes on the wire.
- **SMTP renderer** (`renderers/smtp.py`): a cleartext delivery conversation; Zeek
  logs mailfrom/rcptto/subject to smtp.log. Text-safe DATA bodies (no bare CR / NUL).
- Validator extended to diff `ssl.log` and `smtp.log`; 20 tests pass; ruff clean.

### Added — real EvidenceForge round-trip (hardening against product data)
- **EvidenceForge ingest** (`ingest/evidenceforge.py`): reads EF's NDJSON Zeek logs
  (conn/dns/http/ssl, correlated by uid) and builds a FlowSet carrying EF's own
  5-tuples, timing, services, and L7 detail. Round-robin sampling covers every
  traffic type; deferrals are reported (no silent truncation).
- **`opaque_udp` renderer** for non-DNS UDP; **per-flow TLS cipher override** so
  ingested TLS reproduces EF's negotiated cipher.
- **`ef-roundtrip` comparison** (`validation/ef_roundtrip.py` + CLI): renders the
  ingested FlowSet, runs real Zeek, and diffs our output against EF's ORIGINAL logs.
  On the branch-office scenario: **clean pcap** (0 weird/reporter/tshark errors) and
  field agreement of **proto 100%, service 100%, conn_state ~99%, DNS query/qtype/
  answers 100%, HTTP method/host/uri/status 100%, TLS version/cipher/SNI 100%,** and
  exact byte counts 100% for analyzer-free opaque flows.
- **Diagnostic findings**: the round-trip surfaced three places where EF's directly-
  synthesized log values differ in representation from what real Zeek emits from
  packets — ICMP conn_state (EF `SF` vs Zeek `OTH`), IPv6 answer form, and URI
  percent-encoding. PacketForge matches real Zeek; the harness reports the divergence.
- **Known limitation → next phase**: opaque random bytes on analyzer ports
  (DHCP/Kerberos/LDAP/NTP) are dissected as malformed, so those are rendered
  structure-only (TCP) or skipped (UDP). Faithful protocol renderers are Phase 2.

### Added — realism polish
- **GREASE** (RFC 8701) on the browser ClientHello (cipher/group/extension), emitted
  on the wire but excluded from JA3. **JA3 now computed from the actual wire lists.**
- **Second client profile** (`curl.yaml`) so JA3 is a real discriminator — the two
  profiles produce distinct JA3s.
- **Per-OS TCP Timestamps**: negotiated only when both endpoints advertise them
  (Linux/macOS on, Windows off), emitted on every segment with a ~1 kHz clock and
  correct peer echo. Verified present on Linux flows, absent on Windows, Zeek clean.
- **TLS 1.3**: real ClientHello/ServerHello `supported_versions` handshake with
  encrypted (opaque) flights; Zeek logs `TLSv13` + the 1.3 cipher + SNI, established.
  EvidenceForge ingest no longer downgrades 1.3 flows to opaque.
- Fixed a validator bug the work surfaced: ssl/http rows were matched by content
  (SNI) instead of the connection 5-tuple — ambiguous when flows share a value.

### Added — Phase 2: protocol library, network taps, scenario composer
- **Faithful protocol renderers** (all Zeek-validated, no malformed events): DHCP
  (dhcp.log), NTP (ntp.log), SSH (ssh.log), FTP (service=ftp), SNMP (snmp.log),
  Modbus/TCP (modbus.log — for OT/ICS), RADIUS (radius.log). 14 protocols total,
  plus opaque TCP/UDP shells. Validator gains a general "produces <log>" check.
- **Network-tap / environment feature**: profiles (office/home/cloud/ot) that shape
  address plan, default OS, ambient service mix, sensor vantage/NAT, and capture link
  type. Link type is a compile post-transform — Ethernet (SPAN/TAP) vs Linux SLL
  cooked-capture (host tcpdump). `packetforge list-envs`.
- **Scenario composer**: generates environment-appropriate benign background traffic
  across a time window (flows overlap and run concurrently) and weaves in an optional
  malicious storyline; deterministic. `packetforge scenario --env <name>`.
- Validator now matches Zeek rows on the full 5-tuple (source port included) so many
  concurrent flows sharing a server disambiguate; HTTP 204/304 carry no body.
- 40 tests, ruff clean. Kerberos/LDAP renderers are the next batch (scapy has the
  layers; heavier ASN.1).

### Notes
- Standalone repo (Method C). Empirically confirms the Method-A-vs-C thesis: log
  reconstruction recovers the story + IOCs, but not exact L7 volumetrics — motivating
  emitting the IR from EF's canonical event.
- Constraint of record: nothing is pushed to EvidenceForge and no issue comments are
  made there without the maintainer's explicit approval.
