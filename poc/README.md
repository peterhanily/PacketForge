# PoC — reference feasibility proof

`pcap_poc.py` renders one hand-authored canonical event (DNS lookup + HTTP C2 beacon)
to `beacon.pcap`. It is the evidence that the PacketForge thesis holds; it is **not**
the production design (that is `../docs/DESIGN.md`). Kept here, unchanged, as a
runnable reference.

```bash
python3 pcap_poc.py                    # -> beacon.pcap + a consistency report
zeek -r beacon.pcap                     # real Zeek: conn/dns/http logs, no weird.log
tshark -r beacon.pcap -q -z expert      # zero errors/warnings/malformed
```

Requires `scapy` (generation). Validation requires `zeek` and `tshark` on PATH.
Full measured results: `../docs/feasibility-evidence.md`.
