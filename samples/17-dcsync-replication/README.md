# DCSync: directory replication credential theft (T1003.006)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/dce_rpc.log`.** An `epmapper::ept_map` lookup on port 135 is followed by six drsuapi
  calls on port 49200 over ncacn_ip_tcp, the plain TCP transport for DCE/RPC.
- **The sequence.** `DRSBind`, `DRSDomainControllerInfo`, `DRSCrackNames`, `DRSBind`,
  `DRSGetNCChanges`, then `DRSUnbind`. It matches a real Empire DCSync capture field for field.
- **The tell.** `drsuapi::DRSGetNCChanges` is how domain controllers replicate secrets to each
  other. Here it comes from 10.10.0.40, a workstation, against the DC at 10.10.0.41 (T1003.006).
  That source is what BZAR-style analytics key on.
- **Inert.** The RPC stubs are zero filler. No replicated secret is present in the capture.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # replicate secrets from a DC over drsuapi
```
