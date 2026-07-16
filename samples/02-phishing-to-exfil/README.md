# Phishing to exfiltration

A complete intrusion woven through a busy office capture: an inbound phishing email, a
DNS lookup and HTTPS **C2 beacon** (non-browser JA3, regular cadence), LDAP/SMB
**discovery**, SMB **lateral movement**, and a large HTTP **exfil** POST.

**What to look for**
- `GROUND_TRUTH.md` — the whole kill chain, five ATT&CK stages, with the exact flows.
- `zeek/smtp.log` — the phishing sender. `zeek/ssl.log` — the C2 beacon SNI + JA3.
  `zeek/ldap.log` / `ldap_search.log` — account enumeration. `zeek/http.log` — the exfil.
- `zeek/conn.log` — everything, with `history` and byte counts, as a hunter would triage.

**Reproduce**
```
packetforge scenario --env office --volume normal --texture realistic \
  --attack phishing-intrusion --seed 7 -o capture.pcap
```
