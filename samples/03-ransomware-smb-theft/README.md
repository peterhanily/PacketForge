# Ransomware mass SMB document theft (T1486)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/smb_files.log`: ~80 documents read off the share in a rapid sweep — each carved and extractable via Wireshark 'Export Objects > SMB' (inert filler content in real containers).
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # office noise + a mass-SMB encryption sweep
```
