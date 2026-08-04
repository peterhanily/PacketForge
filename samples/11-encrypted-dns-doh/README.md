# Encrypted-DNS C2 over DoH (T1071.004 / T1572)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/ssl.log`.** 40 TLS 1.3 sessions reach `cloudflare-dns.com` at 1.1.1.1 on port 443,
  about one every three seconds (T1071.004, T1572).
- **What is missing.** No row in `zeek/dns.log` corresponds to any tunnelled query. The names went
  inside the TLS session, so a plaintext-DNS monitor sees nothing at all.
- **What to key on.** The resolver identity and the session cadence. 1.1.1.1 is a legitimate public
  resolver, so the finding is that this workstation is using it, not that it exists.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # a DoH tunnel in office noise
```
