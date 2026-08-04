# Kerberoasting in Active Directory (T1558.003)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/kerberos.log`.** The account `svc-analyst` takes a normal AES ticket-granting ticket,
  then makes eight TGS requests in a row that each force `cipher=rc4-hmac`.
- **Why the downgrade.** A service ticket encrypted under RC4 can be cracked offline against the
  service account's password. AES tickets cost far more to attack, so the client asks for RC4.
- **The tell is the burst.** Eight distinct SPNs (service principal names, the Kerberos identity of
  a service) are roasted by one account in 10.5 seconds. The other 18 rows in the log are ambient
  AES ticket requests from ordinary users.
- **Nothing here is blockable.** The cipher choice and the burst shape are the signal. Every host
  and realm name in this capture is fictional.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # office AD noise + a Kerberoasting burst
```
