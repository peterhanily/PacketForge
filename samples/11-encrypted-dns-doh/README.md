# Encrypted-DNS C2 over DoH (T1071.004 / T1572)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/ssl.log`: TLS 1.3 sessions to a public DoH resolver's SNI (`cloudflare-dns.com`) on :443 — encrypted-DNS that bypasses plaintext-DNS monitoring. The detection is the resolver SNI/IP + cadence, not DNS content.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # a DoH tunnel in office noise
```
