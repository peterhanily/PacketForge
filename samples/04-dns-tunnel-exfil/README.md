# DNS tunnelling exfiltration (T1048.003)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/dns.log`.** 60 A queries carry a 39-character base32 label under one parent,
  `exfil.evil.example`, and every one of them returns NXDOMAIN (T1048.003).
- **The burst takes 118 seconds.** The other 65 rows in the log are ordinary office lookups, so
  sorting the log by query length separates them in one pass.
- **What to measure.** Query length, query rate under a single parent, and label entropy. The
  parent domain is fictional, so a rule that matches the name proves nothing.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # a DNS-tunnel burst in office noise
```
