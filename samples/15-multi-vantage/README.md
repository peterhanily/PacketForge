# Multi-vantage capture: one incident, four sensors

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`capture.pcap`.** The core SPAN reference: 2,711 packets of the sample 05 PsExec intrusion on
  plain Ethernet.
- **`capture.edge-tap.pcap`.** The same 2,711 packets at the WAN TAP. Every internal host is
  source-NAT'd onto 203.0.113.10 and TTL drops by one across the router hop, so per-host
  attribution is gone.
- **`capture.core-span.pcap`.** The same 2,711 packets with an 802.1Q VLAN tag (id 10) on every
  frame. A rule that matches at a fixed byte offset breaks here.
- **`capture.host-10.10.0.40.pcap`.** The victim's own tcpdump: 154 packets in Linux SLL, its
  flows to 10.10.0.41 and nothing else on the network.
- **The question this answers.** Whether a detection fires given where the sensors actually sit.
  One rule can pass on one of these files and fail on another.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # the same intrusion projected through edge/core/host sensors
```
