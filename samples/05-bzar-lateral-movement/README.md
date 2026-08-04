# PsExec-style lateral movement: the BZAR pack (T1021.002 / T1569.002)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/smb_files.log`.** 10.10.0.40 writes a 6,144-byte `svc.exe` to the ADMIN$ share on
  10.10.0.41. That is the tool drop, and it happens first.
- **`zeek/dce_rpc.log`.** An `epmapper::ept_map` endpoint lookup on port 135 follows, then ten
  svcctl operations on port 445 over a named pipe.
- **The sequence.** `OpenSCManagerW`, `CreateServiceW`, `QueryServiceStatus`,
  `OpenServiceW`, `StartServiceW`, `QueryServiceStatus`, then three `CloseServiceHandle`
  calls. It matches the operation order in a real PsExec capture.
- **Why BZAR fires.** The admin-share write and the remote service install together are what raises
  `ATTACK::Lateral_Movement_and_Execution`. Either one alone is common in an AD network.
- **Inert.** The RPC argument stubs are zero filler. No service binary and no command line is
  carried anywhere in the capture.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # remote service creation + admin-share tool drop
```
