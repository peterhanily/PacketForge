# GROUND TRUTH — DoH tunnel from 10.10.0.40 in office

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Command and Control — T1071.004 Application Layer Protocol: DNS / T1572 Protocol Tunneling
- 40 DoH sessions to cloudflare-dns.com (1.1.1.1) — encrypted-DNS C2/exfil that bypasses plaintext-DNS monitoring.
- Flows: atk-doh-000, atk-doh-001, atk-doh-002, atk-doh-003, atk-doh-004, atk-doh-005, atk-doh-006, atk-doh-007, atk-doh-008, atk-doh-009, atk-doh-010, atk-doh-011, atk-doh-012, atk-doh-013, atk-doh-014, atk-doh-015, atk-doh-016, atk-doh-017, atk-doh-018, atk-doh-019, atk-doh-020, atk-doh-021, atk-doh-022, atk-doh-023, atk-doh-024, atk-doh-025, atk-doh-026, atk-doh-027, atk-doh-028, atk-doh-029, atk-doh-030, atk-doh-031, atk-doh-032, atk-doh-033, atk-doh-034, atk-doh-035, atk-doh-036, atk-doh-037, atk-doh-038, atk-doh-039
- IOCs: victim=10.10.0.40, resolver=cloudflare-dns.com, resolver_ip=1.1.1.1, channel=doh, expected_signal=ssl.log server_name=cloudflare-dns.com to :443 (known DoH provider)

## Indicators of compromise

- `victim`: 10.10.0.40
- `resolver`: cloudflare-dns.com
- `channel`: doh
