# Exfiltration to Azure Blob storage (T1567.002)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/ssl.log`.** Six of the 118 TLS sessions reach `exfilstg.blob.core.windows.net` at
  203.0.113.90. The other 112 go to ordinary sites (T1567.002).
- **`zeek/conn.log`.** Those six carry between 230 KB and 436 KB of `orig_bytes` each, and under
  600 bytes back. Ordinary browsing has that ratio the other way round.
- **Why it is hard to catch.** The destination is a trusted cloud endpoint on port 443 and the
  content is encrypted. Direction and volume are the signal, not reputation.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # azure-vnet: ~440 KB uploads to Blob storage
```
