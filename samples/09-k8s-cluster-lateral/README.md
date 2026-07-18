# Kubernetes cluster lateral movement + a VXLAN traffic mirror (T1613 / T1021)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/` (direct pod-network SPAN) plus `capture.mirror.pcap` — what an AWS VPC Traffic Mirror / GCP Packet Mirror sees: the same flows VXLAN-encapsulated to a collector VTEP. `zeek-mirror/` is what Zeek derives from that mirror: a `tunnel.log` (`Tunnel::VXLAN`, port 4789) **plus the identical inner conns** — decapsulation recovers the incident. The attack: a compromised pod hits the API server (10.96.0.1) then fans out mTLS across the mesh.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # k8s pod-to-pod lateral, direct + VXLAN-mirrored
```
