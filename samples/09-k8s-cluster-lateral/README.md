# Kubernetes cluster lateral movement and a VXLAN traffic mirror (T1613 / T1021)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **The attack.** A compromised pod at 10.244.1.13 resolves cluster services through CoreDNS at
  10.96.0.10, reaches the API server at 10.96.0.1 on port 443, then fans out mutual TLS to four
  pods on 8443 across the service mesh (T1613, T1021).
- **`capture.pcap` and `zeek/`.** The direct view from the pod network, 247 connections.
- **`capture.mirror.pcap`.** The same packets as an AWS VPC Traffic Mirror or a GCP Packet Mirror
  delivers them, wrapped in VXLAN and sent to a collector endpoint.
- **`zeek-mirror/`.** What Zeek makes of that mirror. `tunnel.log` holds 1,622
  `Tunnel::VXLAN` entries, and `conn.log` holds the identical 247 inner connections alongside
  1,202 outer ones. Decapsulation recovers the incident intact.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # k8s pod-to-pod lateral, direct + VXLAN-mirrored
```
