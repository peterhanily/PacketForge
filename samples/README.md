# Sample captures — a tour of what PacketForge renders

Each folder holds a generated `capture.pcap`, the **real Zeek 8.2 logs** it produces (`zeek/`),
a short README, and — for attacks — a `GROUND_TRUTH` answer key. Every capture is deterministic
and opens cleanly in Wireshark. Regenerate the whole gallery with `scripts/make-samples.sh`.

### Attack storylines — ATT&CK-mapped kill chains
| Sample | What it shows |
|---|---|
| [01-kerberoasting-in-ad](01-kerberoasting-in-ad/) | RC4 service-ticket roasting hiding in benign AES Kerberos — the downgrade is visible in `kerberos.log` (T1558.003) |
| [02-phishing-kill-chain](02-phishing-kill-chain/) | A full phishing → C2 → discovery → lateral → exfil kill chain, ATT&CK-mapped end to end |
| [03-ransomware-smb-theft](03-ransomware-smb-theft/) | Mass SMB document theft — ~80 files carved to `smb_files.log`, all extractable (T1486) |
| [04-dns-tunnel-exfil](04-dns-tunnel-exfil/) | DNS tunnelling: a burst of long encoded subdomains under one parent (T1048.003) |
| [05-bzar-lateral-movement](05-bzar-lateral-movement/) | PsExec-style remote service creation over `\svcctl` + ADMIN$ drop — the MITRE **BZAR** combined notice (T1021.002/T1569.002) |
| [06-llmnr-poisoning](06-llmnr-poisoning/) | Responder-style LLMNR poisoning → an inert NTLM capture real Zeek reads into `ntlm.log` (`CORP\jsmith`) — a machine-in-the-middle tactic (T1557.001) |
| [17-dcsync-replication](17-dcsync-replication/) | **DCSync** — `drsuapi::DRSGetNCChanges` from a non-DC host, the full Empire sequence matched to a real capture (T1003.006) |

### Cloud & modern — AWS / Azure / Kubernetes, IPv6, encrypted DNS
| Sample | What it shows |
|---|---|
| [07-aws-imds-ssrf](07-aws-imds-ssrf/) | AWS instance-metadata credential theft via SSRF — the Capital One shape (T1552.005) |
| [08-azure-cloud-exfil](08-azure-cloud-exfil/) | Exfiltration to Azure Blob storage — large HTTPS uploads to a trusted cloud endpoint (T1567.002) |
| [09-k8s-cluster-lateral](09-k8s-cluster-lateral/) | Kubernetes pod-to-pod lateral movement — **plus the same incident as a VXLAN traffic mirror sees it**, decapsulated |
| [10-ipv6-c2-beacon](10-ipv6-c2-beacon/) | HTTPS C2 beaconing over **IPv6** — the behaviour a v4-only detection misses (T1071.001) |
| [11-encrypted-dns-doh](11-encrypted-dns-doh/) | Encrypted-DNS C2 over **DoH** to a public resolver — bypasses plaintext-DNS monitoring (T1071.004) |

### Capabilities & techniques
| Sample | What it shows |
|---|---|
| [12-c2-beacon-ja3](12-c2-beacon-ja3/) | An inert C2 beacon with a stable **JA3** fingerprint — the transfer-proof reference |
| [13-ot-modbus-plant](13-ot-modbus-plant/) | An OT/ICS plant network — Modbus/TCP traffic in `modbus.log` |
| [14-artifact-extraction](14-artifact-extraction/) | Pull a real (inert) EXE, PDF, XLSX and an X.509 cert out of one capture (HTTP/SMB/FTP/TLS) |
| [15-multi-vantage](15-multi-vantage/) | **One incident, three sensors** — edge TAP (NAT), core SPAN (VLAN), and host tcpdump, side by side |
| [16-fragmented-ids-evasion](16-fragmented-ids-evasion/) | The ransomware sweep **IP-fragmented** — Zeek reassembles to the same flows; a reassembly/IDS-evasion test |

Everything here is synthetic and inert — fake traffic with true labels, no real hosts,
credentials, malware, or documents.
