# IP fragmentation: a reassembly and IDS-evasion test

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **What changed.** This is the sample 03 ransomware SMB sweep with every IP datagram split into
  400-byte fragments. The packet count rises from 10,200 to 27,766, and 23,493 of those packets are
  fragments.
- **`zeek/smb_files.log`.** Zeek reassembles and produces the same 80 file rows as sample 03,
  field for field. The flows are unchanged.
- **What this tests.** An engine that matches per packet, or one with a different fragment-overlap
  policy, can miss what Zeek still sees. Run your rules over both files and compare the verdicts.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # the ransomware sweep, IP-fragmented
```
