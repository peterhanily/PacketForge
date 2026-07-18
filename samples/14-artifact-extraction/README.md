# Forensic artifact extraction (HTTP / SMB / FTP / TLS)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/files.log` + `x509.log`: pull a real (inert) EXE, PDF, XLSX and an X.509 certificate out of one capture — valid containers with synthetic content, recognised by `file(1)` and Wireshark 'Export Objects'.

**Reproduce**
```
scripts/make-samples.sh   # one capture carrying extractable typed files
```
