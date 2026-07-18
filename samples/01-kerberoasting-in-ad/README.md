# Kerberoasting in Active Directory (T1558.003)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/kerberos.log`: a normal AES TGT, then a burst of TGS-REQs each forcing **RC4** (`cipher=rc4-hmac`) for distinct SPNs — the offline-crackable downgrade. The fingerprint + burst is the tell, not any IOC.
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # office AD noise + a Kerberoasting burst
```
