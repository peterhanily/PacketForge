# OT / Modbus plant network

An operational-technology environment: a different address plan, host mix, and link type,
with **Modbus/TCP** industrial traffic alongside the usual IT background.

**What to look for**
- `zeek/modbus.log` — read/write function-code traffic to the PLCs. `zeek/conn.log` shows
  the OT service mix. The `ot` environment shapes the whole capture (subnet, OS, ambient).

**Reproduce**
```
packetforge scenario --env ot --volume normal --seed 2 -o capture.pcap
```
