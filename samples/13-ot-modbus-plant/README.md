# OT and ICS plant network: Modbus/TCP

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/modbus.log`.** 94 request and response pairs, every one function code 3
  (`READ_HOLDING_REGISTERS`), which is the poll a control system runs against a PLC's registers.
- **The topology.** Twelve hosts between 192.168.0.20 and 192.168.0.31 poll each other in both
  directions on port 502. The segment is flat, which is what an ICS cell TAP normally shows.
- **`zeek/conn.log`.** 35 connections on port 102 and 33 on port 20000 carry no `service` value.
  Those are S7comm and DNP3 rendered as opaque TCP shells, because PacketForge does not invent
  protocol bodies it has no renderer for.

**Reproduce**
```
scripts/make-samples.sh   # an OT/ICS plant's ambient Modbus traffic
```
