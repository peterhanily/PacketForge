# Cloud VPC intrusion (Linux SLL capture)

The same phishing → C2 → discovery → lateral → exfil kill chain as
[02-phishing-to-exfil](../02-phishing-to-exfil/), captured from a different vantage: a
host-side agent inside a cloud VPC. The link type is **Linux SLL** ("cooked" capture, as
`tcpdump` records it on a host with no single capture interface), not the Ethernet of a
SPAN or TAP. The environment (`cloud`) also shapes the address plan and host mix.

**What to look for**
- **Link type.** The capture is SLL, not Ethernet — there is no Ethernet header, and each
  packet carries a cooked-capture pseudo-header instead. Zeek and tshark read it the same
  way; `conn.log` and the L7 logs have the same shape as an Ethernet capture, so a detection
  written against one vantage works against the other.
- `GROUND_TRUTH.md` — the five ATT&CK stages and the exact malicious flows.
- `zeek/smtp.log` — the phishing delivery. `zeek/ssl.log` — the C2 beacon (SNI + JA3).
  `zeek/ldap.log` / `ldap_search.log` — account discovery. `zeek/http.log` — the exfil POST.

**Reproduce**
```
packetforge scenario --env cloud --volume normal --texture realistic \
  --attack phishing-intrusion --seed 8 -o capture.pcap
```
