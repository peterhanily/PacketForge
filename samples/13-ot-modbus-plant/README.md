# OT / ICS plant network — Modbus/TCP

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/modbus.log`: read/write function codes across a flat OT segment of legacy hosts, seen from a cell TAP.

**Reproduce**
```
scripts/make-samples.sh   # an OT/ICS plant's ambient Modbus traffic
```
