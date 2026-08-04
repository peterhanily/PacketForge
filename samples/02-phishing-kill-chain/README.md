# Phishing to exfiltration: a full kill chain (T1566 to T1048)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **Five stages, one victim.** 10.10.0.40 runs the whole chain inside ordinary office traffic. The
  answer key names each attack flow with an `atk-` prefix; everything unnamed is ambient.
- **`zeek/smtp.log`.** One mail from `hr-updates@evil.example` to `victim@corp.local` is the
  initial access (T1566.001).
- **`zeek/ssl.log`.** Six HTTPS beacons reach `cdn.telemetry-sync.example` at 203.0.113.66 on a
  60-second cadence, with a curl JA3 rather than a browser's (T1071.001).
- **`zeek/ldap_search.log`.** The victim then runs base searches against `DC=corp,DC=local` on
  the domain controller 10.10.0.10 (T1087).
- **`zeek/smb_mapping.log`.** It maps a named pipe on the file server 10.10.0.42, then a disk
  share on the peer 10.10.0.41 (T1135, T1021.002).
- **`zeek/http.log`.** A single 45,000-byte POST to `upload.evil.example/dropbox` at
  198.51.100.44 closes the chain (T1048).
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # the reference intrusion woven into office noise
```
