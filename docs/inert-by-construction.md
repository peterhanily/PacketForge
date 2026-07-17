# Inert by construction

PacketForge renders synthetic network traffic to `.pcap` files for detection engineering:
point Zeek, Suricata, or an analytic like [BZAR](https://github.com/mitre-attack/bzar) at
the output and confirm your detections fire. Some of that traffic models malicious
behaviour — C2, DNS tunnelling, lateral movement. This is the property that keeps that
safe: **a malicious scenario reproduces the detection *signal*, never the offensive
*capability*.**

For every attack flow:

1. **No functional payload.** The bytes never contain a working command line, a real
   service binary or path, exploit bytes, shellcode, or malware. Where an operation's
   arguments would sit, the renderer emits inert filler. A "remote service creation" flow
   renders exactly what an analytic keys on — an SMB write to `\svcctl`, a DCE-RPC bind to
   the svcctl interface, and the `CreateServiceW` operation number — and **nothing that
   could create a service**: the service name and binary path are zero filler.
2. **File-only, offline, no I/O.** Output is a capture file. PacketForge opens no sockets,
   contacts no host, transmits nothing, and executes nothing.
3. **Labelled ground truth.** Every malicious flow is tagged with its ATT&CK technique and
   the detection it is expected to trip (the Zeek log signal and the BZAR notice).
4. **Deterministic.** Every field is a seeded function of the scenario; the same input
   produces byte-identical output.

It is **strictly weaker than a red-team tool.** Atomic Red Team and similar frameworks
*execute* techniques on real hosts; PacketForge executes nothing — it draws a picture of
what the resulting traffic would look like. The signal a defender needs is present; the
capability an attacker would need is absent by construction.

## Checkable, not asserted

The test suite (`tests/test_bzar_pack.py`) enforces the inert property mechanically, so a
change that tried to smuggle a real payload into a scenario fails CI:

- The DCE-RPC L7 model (`DceRpcL7`) has **no operation-argument fields** — only protocol
  shape (pipe, interface, opnums, and human-readable operation labels). Adding a
  `service_binary` or `command` field breaks `test_dcerpc_model_has_no_argument_fields`.
- `operations` are DCE-RPC **opnum integers**; `op_names` are labels with no effect on the
  emitted bytes.
- Every DCE-RPC request/response **stub on the wire is zero filler**
  (`test_dcerpc_stubs_are_inert_zero_filler`), and no command/LOLBin token
  (`cmd.exe`, `powershell`, `rundll32`, …) appears in any packet
  (`test_no_capability_strings_on_the_wire`).
- Every **transferred file is an inert shell** — a valid container header over synthetic
  printable filler, with no executable section and no binary/shellcode bytes past the
  header (`test_transferred_files_are_inert_shells`, checked on the wire so it holds
  regardless of how the body is generated).
- Every malicious flow is one of the two gated inert types (a DCE-RPC operation-shape
  flow or an SMB file transfer) — a new builder emitting any other flow type fails
  (`test_every_pack_flow_is_a_gated_inert_type`).
- Every malicious flow declares an ATT&CK technique and an expected detection
  (`test_builder_declares_technique_and_expected_detection`).

## The lateral-movement pack

`packetforge list-attacks` includes eight inert MS-RPC-over-SMB fixtures. Each renders the
SMB2 named-pipe carrier + a DCE-RPC bind to a well-known interface + one request per
operation, so **real Zeek** names the interface (`endpoint`) and each `operation` in
`dce_rpc.log` — the exact field BZAR keys on.

The BZAR notice each fixture raises is **verified**, not asserted: the test suite runs the
real BZAR analytic over each rendered pcap and checks `notice.log`
(`test_builder_trips_expected_bzar_notice`, opt-in via `PF_BZAR_PATH`).

| Attack (`--attack`) | ATT&CK | Zeek signal | BZAR notice (verified) |
|---|---|---|---|
| `remote-service`      | T1543.003 / T1569.002 | `dce_rpc.log` svcctl `CreateServiceW` → `StartServiceW` | `ATTACK::Execution` |
| `scheduled-task`      | T1053.005             | `dce_rpc.log` ITaskSchedulerService `SchRpcRegisterTask` | `ATTACK::Execution` |
| `wmi-exec`            | T1047                 | `dce_rpc.log` IWbemServices `ExecMethod` | `ATTACK::Execution` |
| `admin-share-transfer`| T1021.002 / T1570     | `smb_files.log` `SMB::FILE_WRITE` to ADMIN$ (`svc.exe`, inert PE shell) | `ATTACK::Lateral_Movement` |
| `share-discovery`     | T1135                 | `dce_rpc.log` srvsvc `NetrShareEnum` + `NetrShareGetInfo` (≥5) | `ATTACK::Discovery` |
| `account-discovery`   | T1087.002             | `dce_rpc.log` samr `Enumerate*`/`Lookup*` (≥5) | `ATTACK::Discovery` |
| `remote-registry`     | T1112                 | `dce_rpc.log` winreg `BaseRegCreateKey` → `BaseRegSetValue` | *(none — see below)* |
| `psexec-lateral`      | T1021.002 / T1570 / T1569.002 | ADMIN$ SMB write **+** svcctl service creation, same host | `ATTACK::Lateral_Movement_and_Execution` |

Two honest notes on BZAR coverage. **Thresholds:** BZAR's Discovery detection is a SumStats
analytic that needs ≥5 enumeration operations in its epoch, and its combined
`Lateral_Movement_and_Execution` needs an admin-share write *and* remote execution against the
same host (score 1+1000 ≥ 1001) — so the discovery and PsExec fixtures issue the operations
that actually cross those thresholds. **Gaps:** generic remote-registry writes
(`winreg::BaseRegSetValue`) are in no BZAR detection set, so `remote-registry` raises no BZAR
notice; its detection is the `dce_rpc.log` winreg operation itself, which a defender's own rule
keys on. Reproducing those thresholds and gaps faithfully is the point of validating against the
real analytic rather than declaring expected notices from memory.

## Validation: the inert stub *is* the boundary

The SMB2 named-pipe carrier and the DCE-RPC control PDUs (bind / bind-ack) are fully
well-formed. Real Zeek reassembles the whole conversation with an **empty `weird.log` and
`reporter.log`**, matches `conn.log` field-for-field against what the renderer emitted, and
names the interface + every operation. That is the pack's validation gate
(`test_builder_is_zeek_clean_and_detectable`).

Wireshark's expert analysis behaves differently on the DCE-RPC operations, and the
difference is the point. Wireshark carries a deep per-operation dissector (svcctl, samr,
winreg, …) that expects each request's stub to be the operation's real NDR arguments. Our
stubs are deliberately **not** valid arguments — they are inert zero filler — so Wireshark
flags them as *malformed stub data*. That malformed-argument signal at the application
layer is exactly the inert property made visible: the interface and opnum an analytic
detects on are valid and present; the argument bytes that would carry the capability are
not there. (The transport, SMB, and DCE-RPC *header* layers are all valid — only the
intentionally-inert argument region is flagged.) The pack's gate therefore asserts Zeek
cleanliness and the `dce_rpc.log` endpoint/operation, not a zero Wireshark expert count on
the argument dissector.

One modelling note: real WMI (T1047) rides DCOM over `ncacn_ip_tcp`, not an SMB named pipe.
The `wmi-exec` fixture renders the `IWbemServices` bind + `ExecMethod` opnum — the
`dce_rpc.log` signal BZAR watches — over the same uniform SMB-pipe substrate as the rest of
the pack, with an inert stub in place of the method arguments. It is honest about being a
detection fixture for the on-the-wire signal, not a faithful DCOM activation.
