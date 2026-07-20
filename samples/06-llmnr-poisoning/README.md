# LLMNR/NBT-NS poisoning -> NTLM (Responder-style, T1557.001)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/dns.log`: LLMNR queries (incl. `wpad`) answered by a rogue host claiming **its own IP** — then the victim authenticates to that host over SMB. The tell is an LLMNR answer of a workstation IP from a non-DNS host, followed by SMB to it.
- `zeek/ntlm.log`: the captured credential — `username=jsmith domainname=CORP hostname=WKS-042` handed to the rogue host. Inert by construction: the NTLMSSP framing and identity are real, but the LM/NT responses are fixed filler, never an offline-crackable hash.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # a broadcast-name poisoning + SMB auth capture
```
