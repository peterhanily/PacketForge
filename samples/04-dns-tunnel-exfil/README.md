# DNS tunnelling exfiltration (T1048.003)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/dns.log`: dozens of long base32-encoded subdomains under one parent, NXDOMAIN — the query length + volume + entropy is the signal.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # a DNS-tunnel burst in office noise
```
