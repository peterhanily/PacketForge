# LLMNR/NBT-NS poisoning into NTLM capture (Responder-style, T1557.001)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/dns.log`.** LLMNR is the multicast name lookup Windows falls back to when DNS fails,
  and Zeek records it in this log. Three names, `wpad` among them, are answered by 10.10.0.41
  with its own address.
- **The tell.** A workstation address returned as an LLMNR answer by a host that is not a DNS
  server, followed by SMB from the victim to that same host (T1557.001).
- **`zeek/ntlm.log`.** The victim authenticates to the rogue host as
  `username=jsmith domainname=CORP hostname=WKS-042`, against a server calling itself
  `WPAD-SRV`.
- **Inert.** The NTLMSSP framing and the identity fields are real, so the log populates correctly.
  The LM and NT response bytes are fixed filler, so nothing here can be cracked offline.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # a broadcast-name poisoning + SMB auth capture
```
