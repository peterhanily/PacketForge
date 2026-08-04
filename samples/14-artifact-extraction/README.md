# Forensic artifact extraction (HTTP / SMB / FTP / TLS)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/files.log`.** Four files cross the wire: a 24,576-byte Windows executable and a
  16,384-byte PDF over HTTP, `salaries.xlsx` at 20,480 bytes off the Finance share on FILESRV
  over SMB, and `database.zip` pulled over FTP.
- **`zeek/pe.log`.** Zeek parses the executable as a real i386 PE, so the container is a genuine
  Windows binary format rather than a renamed blob.
- **`zeek/x509.log`.** Two certificates are recorded: `CN=portal.corp.example` and the
  `PacketForge Synthetic CA` that issued it.
- **Get them out.** Wireshark's File > Export Objects recovers all four, and `file(1)` identifies
  each one correctly.
- **Inert.** The containers are valid formats and the bytes inside them are synthetic filler.
  Nothing here executes or opens onto real data.

**Reproduce**
```
scripts/make-samples.sh   # one capture carrying extractable typed files
```
