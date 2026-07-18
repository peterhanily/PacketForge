# GROUND TRUTH — DNS-tunnel exfiltration in office

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Exfiltration — T1048.003 Exfiltration Over Unencrypted Non-C2 (DNS)
- 60 DNS lookups with long encoded subdomains under exfil.evil.example — tunneling.
- Flows: atk-dnsx-000, atk-dnsx-001, atk-dnsx-002, atk-dnsx-003, atk-dnsx-004, atk-dnsx-005, atk-dnsx-006, atk-dnsx-007, atk-dnsx-008, atk-dnsx-009, atk-dnsx-010, atk-dnsx-011, atk-dnsx-012, atk-dnsx-013, atk-dnsx-014, atk-dnsx-015, atk-dnsx-016, atk-dnsx-017, atk-dnsx-018, atk-dnsx-019, atk-dnsx-020, atk-dnsx-021, atk-dnsx-022, atk-dnsx-023, atk-dnsx-024, atk-dnsx-025, atk-dnsx-026, atk-dnsx-027, atk-dnsx-028, atk-dnsx-029, atk-dnsx-030, atk-dnsx-031, atk-dnsx-032, atk-dnsx-033, atk-dnsx-034, atk-dnsx-035, atk-dnsx-036, atk-dnsx-037, atk-dnsx-038, atk-dnsx-039, atk-dnsx-040, atk-dnsx-041, atk-dnsx-042, atk-dnsx-043, atk-dnsx-044, atk-dnsx-045, atk-dnsx-046, atk-dnsx-047, atk-dnsx-048, atk-dnsx-049, atk-dnsx-050, atk-dnsx-051, atk-dnsx-052, atk-dnsx-053, atk-dnsx-054, atk-dnsx-055, atk-dnsx-056, atk-dnsx-057, atk-dnsx-058, atk-dnsx-059
- IOCs: exfil_domain=exfil.evil.example, query_count=60

## Indicators of compromise

- `exfil_domain`: exfil.evil.example
- `victim`: 10.10.0.40
