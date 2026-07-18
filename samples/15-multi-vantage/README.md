# Multi-vantage capture — one incident, three sensors

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `capture.pcap` (core SPAN reference) plus `capture.edge-tap.pcap` (WAN TAP: every host **source-NAT'd** to one public IP, TTL -1 across the router hop), `capture.core-span.pcap` (802.1Q VLAN-tagged trunk), and `capture.host-*.pcap` (the victim's own tcpdump: its flows only, cooked SLL). Answers 'does my detection fire *given where my sensors are*.'
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # the same intrusion projected through edge/core/host sensors
```
