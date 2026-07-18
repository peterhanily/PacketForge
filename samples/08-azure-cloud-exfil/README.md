# Exfiltration to Azure Blob storage (T1567.002)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/ssl.log`: large HTTPS uploads to `*.blob.core.windows.net` — data staged out through a trusted cloud endpoint (upload-heavy `orig_bytes` in `conn.log` is the signal).
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # azure-vnet: ~440 KB uploads to Blob storage
```
