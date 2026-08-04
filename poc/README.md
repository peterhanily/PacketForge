# Proof of concept

`pcap_poc.py` renders one hand-authored canonical event (a DNS lookup and an HTTP C2 beacon) to
`beacon.pcap`. It is the evidence that the PacketForge thesis holds, not the production design.
For that, see [`../docs/DESIGN.md`](../docs/DESIGN.md). Kept here unchanged, as a runnable
reference.

```bash
python3 pcap_poc.py                    # -> beacon.pcap + a consistency report
zeek -r beacon.pcap                    # real Zeek: conn/dns/http logs, no weird.log
tshark -r beacon.pcap -q -z expert     # zero errors, warnings or malformed packets
```

Generating requires `scapy`. Validating requires `zeek` and `tshark` on the PATH. The measured
results are in [`../docs/appendix/feasibility-evidence.md`](../docs/appendix/feasibility-evidence.md).
