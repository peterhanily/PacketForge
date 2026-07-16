# GROUND TRUTH — Phishing to exfiltration in cloud

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Initial Access — T1566.001 Spearphishing Attachment
- Phishing email delivered to the victim's mailbox.
- Flows: atk-01-phish
- IOCs: sender=hr-updates@evil.example

### Command and Control — T1071.001/.004 Web + DNS C2
- Beaconing to cdn.telemetry-sync.example every ~60s over HTTPS (non-browser JA3).
- Flows: atk-02-c2dns, atk-02-beacon-00, atk-02-beacon-01, atk-02-beacon-02, atk-02-beacon-03, atk-02-beacon-04, atk-02-beacon-05
- IOCs: c2_domain=cdn.telemetry-sync.example, c2_ip=203.0.113.66, cadence_s=60, ja3_profile=curl

### Discovery — T1087 Account / T1135 Network Share Discovery
- LDAP account enumeration against the DC and SMB share listing.
- Flows: atk-03-ldap, atk-03-smbenum
- IOCs: dc=10.0.0.2, fileserver=10.0.0.42

### Lateral Movement — T1021.002 SMB/Windows Admin Shares
- Lateral movement to a peer over the ADMIN$ share.
- Flows: atk-04-lateral
- IOCs: peer=10.0.0.41

### Exfiltration — T1048 Exfiltration Over Alternative Protocol
- 45 KB HTTP POST to an external drop server.
- Flows: atk-05-exfil
- IOCs: exfil_ip=198.51.100.44, bytes=45000

## Indicators of compromise

- `c2_domain`: cdn.telemetry-sync.example
- `c2_ip`: 203.0.113.66
- `exfil_ip`: 198.51.100.44
- `victim`: 10.0.0.40
- `sender`: hr-updates@evil.example
