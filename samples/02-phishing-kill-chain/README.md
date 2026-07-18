# Phishing to exfiltration — a full kill chain (T1566 -> T1048)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- The `atk-*` flows across `smtp/dns/ssl/ldap/smb/http` logs: phishing email -> HTTPS C2 beacons (non-browser JA3, fixed cadence) -> LDAP/SMB discovery -> ADMIN$ lateral -> a 45 KB HTTP POST exfil.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # the reference intrusion woven into office noise
```
