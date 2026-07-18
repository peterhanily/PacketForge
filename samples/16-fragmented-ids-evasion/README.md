# IP fragmentation — a reassembly / IDS-evasion test

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- The same ransomware SMB sweep, IP-fragmented to 400-byte fragments. Real Zeek **reassembles** to the identical flows (`smb_files.log` unchanged) — a per-packet signature engine, or one with a different overlap policy, can be evaded. A test that a rule survives reassembly.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # the ransomware sweep, IP-fragmented
```
