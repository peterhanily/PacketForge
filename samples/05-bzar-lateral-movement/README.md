# PsExec-style lateral movement — the BZAR pack (T1021.002 / T1569.002)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/dce_rpc.log`: svcctl `CreateServiceW`/`StartServiceW` over a named pipe, plus an ADMIN$ file write in `smb_files.log` — the combination MITRE **BZAR** raises `ATTACK::Lateral_Movement_and_Execution` on. Inert: the RPC argument stubs are zero filler, never a service binary or command.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # remote service creation + admin-share tool drop
```
