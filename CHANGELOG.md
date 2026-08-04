# Changelog

Notable changes to PacketForge, in the shape of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project has no released versions, so entries are grouped by dated milestone, newest first.
Measured figures are not repeated here. They live in [docs/validation.md](docs/validation.md),
[docs/correspondence.md](docs/correspondence.md), and each sample's generated manifest.

## Unreleased

Nothing has landed since 2026-07-31. Planned work is in [docs/ROADMAP.md](docs/ROADMAP.md).

## 2026-07-31: Gate 4 and indicator hygiene

### Added

- `packetforge warrant`, the correspondence gate. It checks a rendered storyline against a claim set built from named sources, in both directions. Every flow must be licensed by a claim or declared illustrative. Every claim must be rendered or declared unmodelled with a reason.
- Field-level marking carrying an ICD 203 claim class, a NASA-STD-7009B pedigree level and a PAV derivation verb per field. An unmarked field defaults to fabricated, so a missed marking fails safe.
- A pcapng writer (`compile/pcapng.py`) that carries the warrant in per-packet comments, so a capture forwarded without its manifest still names the claim licensing each flow. Zeek derives byte-identical logs from it.
- Pre-registered predictions scored with a baseline log score, a Brier score and an exact Murphy decomposition, via `warrant --score-key`.
- A `gates.correspondence` section in the scorecard, with two CI regression metrics.
- Two allowlists holding every deliberate exception to the indicator policy, each entry carrying a written reason. Four tests enforce the policy, so the next addition is a decision rather than an accident.
- A private security contact and three report categories in [SECURITY.md](SECURITY.md), including one for any organisation named in a reconstruction.

### Changed

- External addresses now draw from RFC 5737 and RFC 3849, and invented C2 domains from RFC 2606 `.example`. Shipped samples had named real allocated addresses and registrable domains as command-and-control indicators.
- Every ground-truth answer key opens with a synthetic banner and a do-not-block instruction, and carries `"synthetic": true` in JSON.
- Reconstruction manifests were renamed from `GROUND_TRUTH.*` to `RECONSTRUCTION.*`, because a reconstruction of someone else's incident is not ground truth. No rendered bytes changed.
- Sample 18 was re-rendered because its invented hostnames sat on registrable namespaces. Its storyline, structure and every scored error are unchanged, and the edit is disclosed at the top of its narrative.
- CI declares `permissions: contents: read`.

### Fixed

- `.gitignore` no longer blanket-negates `samples/`, which had re-enabled every ignore rule in the one directory where a real capture would be staged.

## 2026-07-29: Sample 18 scored against the post-mortem

### Added

- [docs/exploitgym-postmortem-delta.md](docs/exploitgym-postmortem-delta.md), which scores sample 18 against the technical post-mortem published four days after that capture was frozen.
- Sample 19 (`flows/openai-hf-exploitgym-v2.yaml`), the rebuild from the post-mortem. It ships two captures: a 10-minute hunting window generated with identical knobs to sample 18 so only the storyline differs, and the whole campaign at its published timestamps with no ambient traffic at all.

### Changed

- Both reconstructions state their information cutoff in the storyline header, the manifest and the sample README.
- Sample 18 is kept frozen as the "before" half, its errors named rather than silently fixed.

## 2026-07-24: Gate enforcement and an inertness sweep

### Added

- `gate_pcap()` and a build sweep in `scripts/make-samples.sh`, so a capture that trips a weird, reporter or malformation finding fails the build. A pytest asserts that every committed sample capture passes the strict gate.
- An inert-by-construction test over every attack. Inertness had been asserted only for the eight fixtures targeting BZAR, the Zeek ATT&CK-based analytics package.

### Changed

- Zeek runs with `-D` in the sample and mirror paths, and the wall-clock `#open` and `#close` stamps are normalised, so a full regeneration produces an empty diff instead of uid churn.
- TCP retransmits are capped at one per direction per flow. Zeek re-arms its history letter per burst, so two bursts in one flow desynced the reconstructed `history`; the cap keeps it exact at every seed.
- `ruff` is pinned below 0.16 so the CI lint step is reproducible.

### Fixed

- The gate's filtered-trace suppression was a no-op. Zeek 8.x ignores the legacy `detect_filtered_trace` const, so all 16 call sites now set `FilteredTraceDetection::enable=F`. The `ddos-syn-flood` and `port-scan` attacks had failed the gate standalone.

## 2026-07-23: The ExploitGym reconstruction and a strict tshark clause

### Added

- Sample 18, a hand-authored Flow IR rebuilding the 2026-07-16 ExploitGym incident from the public disclosures alone. Those disclosures published no network indicators, so every address, domain and timestamp in it is invented.
- Ambient traffic, TLS 1.3 attack flows, and an internally consistent IMDSv2 exchange against the cloud instance metadata service (IMDS) in sample 18, in response to an analyst review that identified the capture as synthetic.

### Changed

- DCE-RPC stubs are sealed (RPC packet privacy, SPNEGO, `auth_level` 6), which is how real Windows drsuapi and lateral-movement RPC run. A tshark dissector now treats the stub as encrypted rather than NDR-decoding it as malformed, and Zeek still reads the interface and the opnum (the operation number identifying a DCE-RPC request) from the cleartext header. The stubs remain inert zero filler.
- TLS 1.2 leaf certificates chain to a synthetic issuing CA instead of being self-signed. `TlsL7` gained an optional `issuer`.

### Fixed

- `_run_tshark_expert` matched only the header "Warnings" while this tshark build prints "Warns", so the tshark clause of the gate silently read zero and never fired. It now matches both spellings and counts malformations and errors, excluding TCP RST and the Kerberos "cannot decrypt" notices that every real capture also carries.
- The VXLAN (Virtual Extensible LAN) mirror set a timestamp on a packet it then re-parsed, which dropped the assignment and left scapy to fill in wall-clock time. Mirrored captures are byte-reproducible again.

## 2026-07-20: Detection CI, the validation trinity, and the transfer proof

### Added

- `packetforge trinity`, which scores a capture on three axes and reports all three legs. Fidelity comes from a cross-validated C2ST (classifier two-sample test) against a real-vs-real floor, utility from TSTR (train on synthetic, test on real), and non-leakage from DCR (distance to closest record).
- `detection_ci.py` and `packetforge suricata-verify`. `packetforge_fixture(attack)` renders an attack capture plus a benign-only twin at the same environment and seed, so a pytest test asserts both that a rule fires and that it stays quiet. Usage is in [docs/detection-ci.md](docs/detection-ci.md).
- `c2_fingerprints.py`, holding vendored and cited fingerprints for four malware families identified by JA3 (a hash of the TLS ClientHello's numeric fields) and four HTTP C2 framework profiles. The transfer proof runs a real ET Open rule over an inert reference and its independently rebuilt analog and requires the same verdict.
- `signatures.py`, which parses the pinned ET Open ruleset and inverts the rules a real reference trips, so the benign false-positive surface reproduces that reference's specific signatures rather than only their rate. It refuses to synthesise MALWARE and CNC triggers, and surfaces unmatched signatures instead of dropping them.
- An inert `NtlmAuth` capability on `SmbL7` rendering an NTLMSSP session setup inside SMB2, so real Zeek reads the captured domain, user and workstation into `ntlm.log`. The NT and LM responses are fixed filler, never an offline-crackable hash.
- `rdp-bruteforce` (T1110.001, T1021.001). Each attempt is an inert X.224 connection request carrying a candidate username in the `mstshash` cookie, which real Zeek reads into `rdp.log`.
- `winrm-lateral` (T1021.006), a WS-Management shell rendered as a SOAP `POST /wsman` on 5985.
- `orig_literal_hex` and `resp_literal_hex` on the opaque renderers, for content rules and for the RDP connection confirm.

### Fixed

- The TLS ClientHello handshake version now honours the first field of the JA3 it is built from, so TLS 1.0 and 1.1 malware fingerprints hash correctly.

## 2026-07-19: Calibrated realism and the EvidenceForge seam

### Added

- `scripts/baseline_panel.py`, a pairwise C2ST matrix over a panel of public real captures. It sets the real-vs-real floor the realism gate scores against.
- `dcsync` (T1003.006): drsuapi `DRSGetNCChanges` from a non-DC host over `ncacn_ip_tcp`, anchored to a real Empire capture's Zeek operation multiset.
- A seeded non-stationary activity envelope for ambient traffic, so a capture varies across its own timespan the way a real one does, plus `realism.hurst_aggvar` as a measured signal.
- An optional `Flow.duration` that the compiler renders to by rescaling packet timestamps, so a rendered flow reproduces a reference's exact `conn.log` duration.
- `tests/test_ef_integration.py`, which proves the integration seam's consistency guarantee against duck-typed canonical events, with no EvidenceForge dependency.
- `scripts/cloud-capture/`, a kit for taking a real cloud reference in a throwaway account. No public real cloud capture exists, so the cloud environments stay unvalidated until one is taken.

### Changed

- The BZAR renderer emits `epmapper::ept_map` on 135 before the svcctl call, and issues the full service-install sequence, so its operation set matches a real PsExec capture.
- Ambient TLS and HTTP clients send realistic originator byte volumes instead of near zero.
- The analog's benign false-positive surface is conditioned on the reference's own measured alert rate rather than a hardcoded value, so a quiet reference no longer makes the analog over-alert.
- A traffic mirror never carries link-local 169.254/16, because cloud mirroring excludes it and the metadata service is host-terminated. IMDS traffic appears only on an on-host vantage, meaning a capture taken at that sensor placement.

### Fixed

- `realism-audit` resolves relative pcap paths, which previously yielded zero flows, and reports an underpowered comparison as inconclusive instead of a vacuous 0.5.

## 2026-07-18: Cloud, IPv6, and overlay capture

### Added

- Four cloud environments (`aws-vpc`, `azure-vnet`, `gcp-vpc`, `oci-vcn`) with provider VPC ranges, resolvers and NIC OUIs, plus a `k8s` pod network. New attacks `imds-ssrf` (T1552.005) and `cloud-exfil` (T1567.002) infer the provider from the environment name.
- Multi-vantage capture (`compile/vantage.py`). One incident projects through three sensor placements: an edge TAP with source NAT and a router-hop TTL decrement, a core-switch SPAN with 802.1Q tags, and a host tcpdump in cooked Linux SLL. A TAP is an inline passive splitter, a SPAN is a switch mirror port, and Linux SLL is the pseudo-link-layer libpcap writes when capturing on `any`. Each projection is a deterministic transform of the same incident. CLI: `scenario --vantages`.
- VXLAN encapsulation to a collector endpoint, modelling a cloud traffic mirror or a container-network overlay. Zeek decapsulates it to the inner connections plus a `tunnel.log` entry. CLI: `scenario --mirror`.
- IPv6 rendering for TCP flows, and the `ipv6-c2` attack (T1071.001).
- IPv4 fragmentation (`compile/fragment.py`), a benign path-MTU artifact and the classic IDS-evasion primitive. CLI: `scenario --fragment BYTES`.
- A `NameQueryL7` model and `renderers/namequery.py` rendering LLMNR, NBT-NS and mDNS queries with an optional poisoned reply, plus `llmnr-poisoning` (T1557.001), which models the Responder flow.
- Configurable TLS ALPN (`TlsL7.alpn`, previously hardcoded to h2) and the `doh-tunnel` and `dot-tunnel` attacks (T1071.004, T1572).
- `k8s-lateral` (T1613, T1021), a compromised pod reaching the API server and fanning out across the mesh.
- `packetforge bundle`, which writes a capture, the exact Zeek logs it produces, the answer key and a manifest into one directory, so a detection can be graded without re-deriving anything.
- [docs/capabilities.md](docs/capabilities.md) as the capability map.

### Changed

- The benign TLS ClientHello emits `key_share` and `psk_key_exchange_modes` alongside `supported_versions`, and ambient web traffic negotiates TLS 1.3 with ALPN h2. A TLS 1.2 minority remains so certificates still appear.
- Internet-facing services resolve to Linux servers, so a timestamp-capable client actually negotiates TCP timestamps.
- IP-ID is now per OS: Windows increments, modern Linux emits 0 with DF set, macOS randomises.
- The realism C2ST gained TCP-timestamp presence and ClientHello-shape features, so it covers the L7 axis.

## 2026-07-17: The BZAR pack and the C2ST calibration

### Added

- A DCE-RPC-over-SMB renderer (`renderers/dcerpc.py`), a `DceRpcL7` model, and eight inert lateral-movement builders: `remote-service`, `scheduled-task`, `wmi-exec`, `admin-share-transfer`, `share-discovery`, `account-discovery`, `remote-registry` and `psexec-lateral`. Each renders the named-pipe carrier, the bind and one request per operation, so real Zeek names the interface and each opnum in `dce_rpc.log`.
- BZAR notice verification, opt-in via `PF_BZAR_PATH`: each fixture renders, runs Zeek with the real BZAR analytic, and asserts that its declared `ATTACK::*` notice fires. Fixtures were tuned so the notices trip, and ground-truth notices were corrected to the verified values.
- `SmbL7.write_file`, a CREATE, WRITE and CLOSE sequence that Zeek logs as `SMB::FILE_WRITE`.
- [docs/inert-by-construction.md](docs/inert-by-construction.md).
- Joint per-flow reference conditioning: `synthesize_analog` clones each reference flow's bytes, packet counts, duration and `conn_state` together, so the joint distribution matches and not only each marginal. (`conn_state` is Zeek's summary code for how a connection began and ended.)
- A `conditioned` texture with lognormal data-phase inter-arrivals, and a per-flow `Flow.seg_bytes` set to the reference's bytes per packet, since real captures sit above NIC offload.
- Per-host OS populations, a realistic minority of failed connections, heavy-tailed transfer sizes, and a benign false-positive surface whose flows each carry the SIDs they are expected to trip as labelled ground truth.

### Changed

- The realism gate scores the C2ST against a measured real-vs-real floor instead of an absolute constant. An absolute 0.5 is reachable only by replaying the reference, so it was the wrong test. `--calibrate` takes several distinct real captures and reports the mean and the range. A within-source temporal baseline is always reported for context. The verdict is taken against the top of the range plus a tolerance, so it does not flip on run-to-run jitter.
- Kernel MMD (maximum mean discrepancy) is reported alongside the C2ST as the smoother convergence signal. The trajectory across the five conditioning passes is in [docs/appendix/realism-ratchet-history.md](docs/appendix/realism-ratchet-history.md).

### Fixed

- The SMB2 renderer assigns a tree id, echoed on every request, and returns a valid share type on tree connect, so Zeek resolves the share mapping and records the share path in `smb_mapping.log`. It had been empty, which blinded share-name analytics.
- `_pcap_duration` called `float()` unguarded on tshark's `frame.time_epoch` and crashed the scorecard on a malformed epoch. It now skips the bad frame.
- The inert guards were hardened: the DCE-RPC stub scan reassembles across segments and matches on ptype, and the transferred-file check bounds the PE optional header and requires the body to be the inert filler alphabet.

## 2026-07-16: First commit

The repository opens with prior development squashed into one commit, followed by four
commits the same day.

### Added

- The Flow IR (`models/flowspec.py`): a typed, versioned pydantic contract with a discriminated L7 union and transport/L7 consistency validation.
- The TCP core (`compile/tcp.py`): deterministic SEQ and ACK, MSS segmentation, five `conn_state` shapes with graceful and reset teardown, and Zeek `history` reconstructed from the emitted packets.
- Protocol renderers for DNS, HTTP, TLS 1.2 and 1.3, SMTP, ICMP, DHCP, NTP, SSH, FTP, SNMP, Modbus, RADIUS, Kerberos, LDAP, SIP and the line-oriented mail and chat protocols, plus opaque TCP and UDP shells for binary protocols.
- Data-driven fingerprints: per-OS TCP profiles, GREASE emitted on the wire but excluded from JA3, and a JA3 computed from the same numeric lists the ClientHello is built from, so the fingerprint agrees with the bytes.
- The timeline compiler (`compile/timeline.py`) and the round-trip validator (`validation/roundtrip.py`), which runs real Zeek and tshark and diffs their output against the rendered expectations.
- Network-tap environments shaping the address plan, default OS, ambient service mix, vantage and capture link type, plus a scenario composer that generates concurrent ambient traffic and weaves in an optional storyline.
- EvidenceForge log ingest (`ingest/evidenceforge.py`) and `packetforge ef-roundtrip`, which renders the ingested flows, runs real Zeek, and diffs the result against EvidenceForge's original logs.
- A detection lab: `detect`, `coverage`, `fp-benchmark`, `sigma`, `robustness`, `corpus-build`, `corpus-verify`, and `crossval` for multi-tool cross-validation.
- The realism suite: `realism-audit`, `realism-detection`, `blind-panel` and `realism-scorecard`, the last with a `--check` regression gate for CI. The committed scorecard recorded a gap verdict and named the tells.
- The proof of concept (`poc/`), [docs/DESIGN.md](docs/DESIGN.md), and a sample gallery shipping each capture with the Zeek logs it produces and a ground-truth answer key.

### Changed

- The supported Python floor is 3.9. CI installs from pyproject metadata so the dependency set cannot drift, installs Zeek, tshark and Suricata with version checks that fail fast, and runs the realism suite on 3.9 and 3.11.
- The CLI reports an unknown environment or attack name and a missing file as a clean error with exit code 2, rather than a traceback. `eval` and the realism gates refuse an empty or unparseable capture instead of scoring it.
- The documentation was rewritten in a third-person voice.

### Removed

- The `examples/` gallery, which duplicated `samples/`. The one capture it uniquely demonstrated, a Linux SLL cooked capture, was preserved as a sample.
