# GROUND TRUTH — IPv6 C2 beaconing in office

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Command and Control — T1071.001 Application Layer Protocol: Web Protocols (over IPv6)
- HTTPS beaconing to cdn.telemetry-sync.example (2606:4700:8ac0::66) over IPv6 — a v4-only detection misses it.
- Flows: atk-6-dns, atk-6-beacon-00, atk-6-beacon-01, atk-6-beacon-02, atk-6-beacon-03, atk-6-beacon-04, atk-6-beacon-05
- IOCs: victim=2001:db8:1::40, c2_domain=cdn.telemetry-sync.example, c2_ip=2606:4700:8ac0::66, family=ipv6, expected_signal=ssl.log to 2606:4700:8ac0::66 (IPv6) with a curl JA3 at ~60s cadence

## Indicators of compromise

- `victim`: 2001:db8:1::40
- `c2_domain`: cdn.telemetry-sync.example
- `c2_ip`: 2606:4700:8ac0::66
