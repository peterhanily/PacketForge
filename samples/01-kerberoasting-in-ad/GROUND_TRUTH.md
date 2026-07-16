# GROUND TRUTH — Kerberoasting from 10.10.0.40 in office

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Credential Access — T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting
- svc-analyst@10.10.0.40 requested 8 RC4 service tickets across distinct SPNs in a burst.
- Flows: atk-krb-tgt, atk-krb-roast-00, atk-krb-roast-01, atk-krb-roast-02, atk-krb-roast-03, atk-krb-roast-04, atk-krb-roast-05, atk-krb-roast-06, atk-krb-roast-07
- IOCs: principal=svc-analyst, victim=10.10.0.40, dc=10.10.0.10, spn_count=8, enctype=rc4-hmac

## Indicators of compromise

- `principal`: svc-analyst
- `victim`: 10.10.0.40
- `dc`: 10.10.0.10
- `enctype`: rc4-hmac
