# HTTPS C2 beaconing over IPv6 (T1071.001)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/ssl.log`: AAAA resolution then HTTPS beacons to an IPv6 C2 with a curl JA3 at ~60s cadence — the identical C2 behaviour a v4-only detection silently misses.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # a dual-stack network with an IPv6 C2 channel
```
