# Inert by construction

PacketForge renders synthetic network traffic to capture files so a detection can be tested against
it. Some of that traffic models malicious behaviour: command-and-control, DNS tunnelling, lateral
movement. This document states the property that makes those captures safe to run and to
redistribute, and names the tests that enforce it.

The property is this: **a malicious scenario reproduces the detection signal, never the offensive
capability.** Four facts support it, and they hold for every attack flow.

1. **No functional payload.** The bytes never contain a working command line, a real service binary
   or path, exploit bytes, shellcode, or malware. Where an operation's arguments would sit, the
   renderer emits inert filler. A remote service creation flow renders what an analytic keys on: a
   named-pipe open of `\svcctl` (the pipe carrying the Windows Service Control Manager's RPC
   interface), a bind to the svcctl interface, and the opnum for `CreateServiceW`. An opnum is the
   integer in a DCE-RPC request that names the method being called. The service name and the binary
   path are zero filler, so the flow contains nothing that could create a service.
2. **File-only, offline, no I/O.** The output is a capture file. PacketForge opens no sockets,
   contacts no host, transmits nothing, and executes nothing.
3. **Labelled ground truth.** Every malicious flow is tagged with its ATT&CK technique and the
   detection it is expected to trip: the Zeek log signal, plus the BZAR notice where one applies.
   [BZAR](https://github.com/mitre-attack/bzar) is MITRE's Zeek script package, which raises
   ATT&CK-labelled notices from Zeek logs.
4. **Deterministic.** Every field is a seeded function of the scenario, so the same input produces
   byte-identical output. Anyone can regenerate a shipped capture and check it themselves.

The result is strictly weaker than a red-team tool. Atomic Red Team and similar frameworks execute
techniques on real hosts, whereas PacketForge draws a picture of what the resulting traffic would
look like. The signal a defender needs is present, and the capability an attacker needs is absent.

The same construction runs through the other renderers. NTLM challenge responses are a fixed filler
byte repeated 24 times rather than a crackable hash, a malware family profile reproduces a
published JA3 (the hash over a TLS client hello's fields) and nothing else, and file bodies are
typed containers whose contents are filler.

## What the tests enforce

`tests/test_bzar_pack.py` checks the property mechanically, so a change that tried to smuggle a
real payload into a scenario fails CI.

| What is enforced | The test that enforces it |
|---|---|
| The DCE-RPC model carries no operation-argument field. | `test_dcerpc_model_has_no_argument_fields` |
| Operations are opnum integers, not named calls. | `test_operations_are_opnum_ints` |
| Every request and response stub on the wire is zero filler. | `test_dcerpc_stubs_are_inert_zero_filler` |
| No command or LOLBin token appears in any packet. | `test_no_capability_strings_on_the_wire` |
| Every transferred file is an inert shell. | `test_transferred_files_are_inert_shells` |
| Every malicious flow is one of two gated inert types. | `test_every_pack_flow_is_a_gated_inert_type` |
| Every malicious flow declares a technique and an expected detection. | `test_builder_declares_technique_and_expected_detection` |
| The same scenario renders byte-identical packets twice. | `test_pack_is_byte_deterministic` |

Three of those rows need a definition. A **LOLBin** is a living-off-the-land binary: a signed
system tool an attacker reuses instead of dropping their own. The forbidden-token list covers
`cmd.exe`, `powershell`, `rundll32`, `certutil`, `bitsadmin`, `mshta`, `wmic` and others, scanned
against the concatenated payload of every packet.

An **inert shell** is a valid container header over synthetic filler. A transferred `.exe` carries
an MZ/PE header whose section count is zero and whose optional header past the magic is all zero
bytes, then filler drawn from letters, digits and space only. Extraction tooling sees a file, there
is no section to map, and the filler alphabet excludes the characters a base64 payload would need.

The **two gated inert types** are a DCE-RPC operation-shape flow and an SMB file transfer. Any
other flow type, which is to say any path that could carry a real payload without one of the gates
above, fails the completeness test.

## Every framing layer is valid, and only the argument region is inert

The transport, the SMB2 named-pipe carrier, and the DCE-RPC control PDUs (bind and bind-ack) are
well-formed. Real Zeek reassembles the whole conversation with no `weird.log` and no
`reporter.log`, matches `conn.log` field-for-field against what the renderer emitted, and names the
interface and every operation in `dce_rpc.log`. That is the pack's validation gate
(`test_builder_is_zeek_clean_and_detectable`), and it runs under all three capture textures.

Only the stub region is inert. A real call's arguments would sit there in NDR, the Network Data
Representation encoding; PacketForge writes zeros instead. The stubs are sealed at RPC packet
privacy (auth level 6), the way real drsuapi and lateral-movement RPC traffic runs, so a deep
per-operation dissector treats the region as opaque rather than parsing it as NDR. Wireshark reads
the capture with no Malformed-Packet exception, and `tshark -z expert` reports zero errors.

What a dissector shows is the inert property made visible. Render a capture with
`packetforge scenario --env office --attack remote-service -o out.pcap`. Wireshark derives the
operation name from the opnum, and the argument region it prints is zeros:

```
$ tshark -r out.pcap -V -Y 'dcerpc.opnum == 12' \
    | grep -E 'Operation:|Auth level:|Encrypted stub' | head -3
        Auth level: Packet privacy (6)
    Operation: CreateServiceW (12)
    Encrypted stub data: 000000000000000000000000000000000000000000000000
```

The interface and the opnum an analytic detects on are valid and present. The 24 bytes that would
carry the capability are zeros.

## Reference: the lateral-movement pack

`packetforge list-attacks` includes eight inert MS-RPC fixtures, named below as the `scenario`
subcommand takes them. Each renders a bind to a well-known interface and one request per operation,
so real Zeek names the `endpoint` and each `operation` in `dce_rpc.log`, the field BZAR keys on. Two
of them also write a file to ADMIN$, the hidden administrative share that maps to a Windows host's
system directory.

The BZAR notice each fixture raises is verified rather than asserted: the test suite runs the real
analytic over each rendered capture and checks `notice.log` (`test_builder_trips_expected_bzar_notice`,
opt-in by setting `PF_BZAR_PATH`).

| Fixture | ATT&CK | Zeek signal | BZAR notice |
|---|---|---|---|
| `remote-service` | T1543.003, T1569.002 | svcctl `CreateServiceW`, `StartServiceW` | `ATTACK::Execution` |
| `scheduled-task` | T1053.005 | ITaskSchedulerService `SchRpcRegisterTask` | `ATTACK::Execution` |
| `wmi-exec` | T1047 | IWbemServices `ExecMethod` | `ATTACK::Execution` |
| `admin-share-transfer` | T1021.002, T1570 | `smb_files.log` write of `svc.exe` to ADMIN$ | `ATTACK::Lateral_Movement` |
| `share-discovery` | T1135 | srvsvc `NetrShareEnum`, `NetrShareGetInfo` | `ATTACK::Discovery` |
| `account-discovery` | T1087.002 | samr `Enumerate*` and `Lookup*` | `ATTACK::Discovery` |
| `remote-registry` | T1112 | winreg `BaseRegCreateKey`, `BaseRegSetValue` | none, see below |
| `psexec-lateral` | T1021.002, T1570, T1569.002 | ADMIN$ write plus svcctl creation, same host | `ATTACK::Lateral_Movement_and_Execution` |

Two notes on BZAR coverage. **Thresholds.** BZAR's Discovery detection is a SumStats analytic, using
Zeek's summary-statistics framework to aggregate events over an epoch, and it needs at least five
enumeration operations inside that epoch. The combined `Lateral_Movement_and_Execution` notice needs
an admin-share write and remote execution against the same host, scoring 1 plus 1000 against a
threshold of 1001. The discovery and PsExec fixtures cross those thresholds.

**Gaps.** Generic remote-registry writes (`winreg::BaseRegSetValue`) are in no BZAR detection set,
so `remote-registry` raises no notice. Its detection is the `dce_rpc.log` winreg operation itself,
which a defender's own rule keys on. Reproducing the thresholds and the gaps is why the pack is
validated against the real analytic rather than from memory.

One modelling note. Real WMI (T1047) rides DCOM, the Distributed COM object-activation layer, over
`ncacn_ip_tcp`, the DCE-RPC transport that runs directly on TCP rather than through an SMB named
pipe. The `wmi-exec` fixture renders the `IWbemServices` bind and the `ExecMethod` opnum over the
same SMB-pipe substrate as the rest of the pack. It is a fixture for the on-the-wire signal, not a
DCOM activation.

## Related

- [`validation.md`](validation.md) covers the gates these captures pass.
- [`detection-ci.md`](detection-ci.md) covers using them as test fixtures.
- [`../SECURITY.md`](../SECURITY.md) covers how to report a capture that is not inert.
