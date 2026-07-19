# DCSync — directory replication credential theft (T1003.006)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/dce_rpc.log`: an `epmapper::ept_map` lookup then the full drsuapi sequence (`DRSBind` -> `DRSDomainControllerInfo` -> `DRSCrackNames` -> `DRSBind` -> `DRSGetNCChanges` -> `DRSUnbind`) over ncacn_ip_tcp — matching a real Empire DCSync capture field-for-field. The tell BZAR-style analytics key on: `drsuapi::DRSGetNCChanges` sourced from a host that is **not** a domain controller. Inert: zero-filler stubs, never a replicated secret.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # replicate secrets from a DC over drsuapi
```
