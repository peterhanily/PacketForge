# HTTPS C2 beaconing over IPv6 (T1071.001)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/dns.log`.** One AAAA lookup for `cdn.telemetry-sync.example` returns the IPv6 address
  2001:db8:c2::66.
- **`zeek/ssl.log`.** Six TLS sessions to that address follow, spaced 55 to 65 seconds apart
  (T1071.001). Their client hello hashes to JA3 `9ecbe6ca0f874f5886035b8b7f1ac001`, which is curl
  rather than a browser.
- **The point.** The behaviour is ordinary HTTPS beaconing. A sensor whose rules are written around
  IPv4 addresses records none of it and reports nothing wrong.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # a dual-stack network with an IPv6 C2 channel
```
