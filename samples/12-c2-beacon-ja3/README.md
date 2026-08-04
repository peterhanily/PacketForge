# C2 beacon JA3 reference (transfer-proof)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/ssl.log`.** Twelve of the 31 TLS sessions reach one beacon SNI,
  `static.cdn-telemetry.example`, across ten minutes.
- **Computing the JA3.** Zeek 8.2 does not log JA3, so take it from the client hello:
  `tshark -r capture.pcap -T fields -e tls.handshake.ja3` returns
  `98f4309baa6caf6ad70662b4ebcba90d` on all twelve.
- **Why this file exists.** It is the reference that `packetforge malware-transfer` profiles.
  Rebuild an analog beacon and the `ja3.hash` rule in
  [`detection/malware-ja3.rules`](../../detection/malware-ja3.rules) reaches the same verdict on
  both captures.

**Reproduce**
```
scripts/make-samples.sh   # the JA3 transfer-proof reference
```
