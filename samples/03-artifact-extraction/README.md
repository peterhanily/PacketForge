# Artifact extraction

One capture, five real artifacts a forensic toolchain can pull straight off the wire —
over HTTP, SMB, FTP, and TLS.

**What to look for**
- `zeek/pe.log` — Zeek recognised a Windows **PE executable** downloaded over HTTP
  (`installer.exe`). `zeek/x509.log` — a real **X.509 certificate** (`CN=portal.corp.example`),
  `openssl`-valid. `zeek/files.log` / `smb_files.log` / `ftp.log` — the carved transfers.
- Pull the objects out yourself:
  ```
  tshark -r capture.pcap --export-objects http,/tmp/http   # installer.exe (PE32), report.pdf
  tshark -r capture.pcap --export-objects smb,/tmp/smb      # salaries.xlsx (zip)
  # FTP: follow the ftp-data stream -> database.zip
  ```
- These are valid **containers with benign filler** — inert by design, real enough for
  extraction/scanning tooling, not real documents.

**Reproduce**
```
packetforge compile flows/extraction.yaml -o capture.pcap
```
