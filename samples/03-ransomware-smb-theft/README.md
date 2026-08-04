# Ransomware mass SMB document theft (T1486)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/smb_files.log`.** 80 documents are read off the file server 10.10.0.41 in one rapid
  sweep, one row per file (T1486).
- **Carve them out.** Wireshark's File > Export Objects > SMB lists all 80. The containers are real
  file formats and the bytes inside them are inert filler.
- **`zeek/ssl.log`.** One HTTPS check-in to `update.evil.example` at 203.0.113.66 precedes the
  sweep (T1071.001).
- **Sample 16 is this capture fragmented.** Compare the two to test whether a rule survives IP
  reassembly.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # office noise + a mass-SMB encryption sweep
```
