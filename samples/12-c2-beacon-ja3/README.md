# C2 beacon JA3 reference (transfer-proof)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/ssl.log`: a recurring beacon SNI with a stable **JA3**. This is the reference `packetforge malware-transfer` profiles: rebuild an analog and a `ja3.hash` rule reaches the same verdict on both — realism that transfers.

**Reproduce**
```
scripts/make-samples.sh   # the JA3 transfer-proof reference
```
