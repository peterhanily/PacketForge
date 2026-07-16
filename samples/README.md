# Sample captures

A tour of PacketForge output — each folder holds a generated `capture.pcap`, the **real
Zeek logs** it produces (`zeek/`), and (for attacks) a `GROUND_TRUTH.md` answer key. Every
capture is deterministic and opens cleanly in Wireshark. Regenerate any of them with the
commands in each folder's README.

| Sample | What it shows |
|---|---|
| [01-kerberoasting-in-ad](01-kerberoasting-in-ad/) | RC4 service-ticket roasting hiding in benign AES Kerberos — the downgrade is visible in `kerberos.log` |
| [02-phishing-to-exfil](02-phishing-to-exfil/) | A full phishing → C2 → discovery → lateral → exfil kill chain, ATT&CK-mapped |
| [03-artifact-extraction](03-artifact-extraction/) | Pull a real EXE, PDF, XLSX and an X.509 cert out of one capture (HTTP/SMB/FTP/TLS) |
| [04-ransomware-smb-theft](04-ransomware-smb-theft/) | Mass SMB document theft — 80 files carved to `smb_files.log`, all extractable |
| [05-dns-tunnel-exfil](05-dns-tunnel-exfil/) | DNS tunnelling: a burst of long encoded subdomains under one parent |
| [06-c2-beacon-ja3](06-c2-beacon-ja3/) | An inert C2 beacon with a stable JA3 fingerprint at a fixed cadence |
| [07-ot-modbus-plant](07-ot-modbus-plant/) | An OT/ICS plant network — Modbus/TCP traffic in `modbus.log` |
| [08-cloud-vpc-sll](08-cloud-vpc-sll/) | The 02 kill chain captured host-side in a cloud VPC — the Linux SLL (cooked-capture) link type |

Everything here is synthetic and inert — fake traffic with true labels, no real hosts,
credentials, malware, or documents.
