# DNS tunnelling exfiltration

A host emitting a burst of DNS lookups with long, high-entropy encoded subdomains under a
single parent domain — classic tunnelling / exfil over DNS.

**What to look for**
- `zeek/dns.log` — the `query` column: dozens of names like
  `pfbl34rba3yii53c6dz4wtlwjxdqoicrcwna7ci.exfil.evil.example` from one source. Volume +
  label length + one parent domain is the behavioural signature (T1048.003 in
  `GROUND_TRUTH.md`).

**Reproduce**
```
packetforge scenario --env office --volume normal --attack dns-exfil --seed 3 -o capture.pcap
```
