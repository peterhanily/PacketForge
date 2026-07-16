# Ransomware SMB document theft

Human-operated ransomware: a C2 check-in, then a rapid sweep reading **80 documents** off
a file share over SMB2 — the "encryption"/staging phase, with every file recoverable.

**What to look for**
- `zeek/smb_files.log` — 80 file operations (xlsx/docx/pdf/zip). `GROUND_TRUTH.md` maps it
  to T1486. Export them: `tshark -r capture.pcap --export-objects smb,/tmp/smb`.
- The rapid same-host → file-server SMB fan-out in `zeek/conn.log` is the behavioural tell.

**Reproduce**
```
packetforge scenario --env office --volume normal --attack ransomware --seed 5 -o capture.pcap
```
