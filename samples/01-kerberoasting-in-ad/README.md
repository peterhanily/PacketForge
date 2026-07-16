# Kerberoasting in benign AD

An office network humming with normal Kerberos authentication, into which one principal
runs a **Kerberoasting** burst: a run of TGS requests for service SPNs, each forcing
**RC4-HMAC** so the tickets are offline-crackable.

**What to look for**
- `zeek/kerberos.log` — the tell is the `cipher` column. Benign auth is
  `aes256-cts-hmac-sha1-96`; the roast stands out as **`rc4-hmac`** on TGS requests
  (here: 8 RC4 TGS among 66 benign AES exchanges). No IOC needed — it's the enctype.
- `GROUND_TRUTH.md` — the malicious flows and the ATT&CK technique (T1558.003).
- `zeek/x509.log`, `ssl.log`, `smb_mapping.log`, `ldap.log` — the ambient AD noise a
  hunter has to separate the roast from.

**Reproduce**
```
packetforge scenario --env office --volume normal --texture realistic \
  --attack kerberoasting --seed 11 -o capture.pcap
```
