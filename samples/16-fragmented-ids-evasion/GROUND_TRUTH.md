# GROUND TRUTH — Ransomware sweep in office

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Command and Control — T1071.001 Web C2
- Ransomware C2 check-in over HTTPS.
- Flows: atk-rw-c2
- IOCs: c2_ip=170.130.183.204

### Impact — T1486 Data Encrypted for Impact (mass SMB access)
- 80 rapid SMB sessions to 10.10.0.41 — file encryption sweep.
- Flows: atk-rw-smb-000, atk-rw-smb-001, atk-rw-smb-002, atk-rw-smb-003, atk-rw-smb-004, atk-rw-smb-005, atk-rw-smb-006, atk-rw-smb-007, atk-rw-smb-008, atk-rw-smb-009, atk-rw-smb-010, atk-rw-smb-011, atk-rw-smb-012, atk-rw-smb-013, atk-rw-smb-014, atk-rw-smb-015, atk-rw-smb-016, atk-rw-smb-017, atk-rw-smb-018, atk-rw-smb-019, atk-rw-smb-020, atk-rw-smb-021, atk-rw-smb-022, atk-rw-smb-023, atk-rw-smb-024, atk-rw-smb-025, atk-rw-smb-026, atk-rw-smb-027, atk-rw-smb-028, atk-rw-smb-029, atk-rw-smb-030, atk-rw-smb-031, atk-rw-smb-032, atk-rw-smb-033, atk-rw-smb-034, atk-rw-smb-035, atk-rw-smb-036, atk-rw-smb-037, atk-rw-smb-038, atk-rw-smb-039, atk-rw-smb-040, atk-rw-smb-041, atk-rw-smb-042, atk-rw-smb-043, atk-rw-smb-044, atk-rw-smb-045, atk-rw-smb-046, atk-rw-smb-047, atk-rw-smb-048, atk-rw-smb-049, atk-rw-smb-050, atk-rw-smb-051, atk-rw-smb-052, atk-rw-smb-053, atk-rw-smb-054, atk-rw-smb-055, atk-rw-smb-056, atk-rw-smb-057, atk-rw-smb-058, atk-rw-smb-059, atk-rw-smb-060, atk-rw-smb-061, atk-rw-smb-062, atk-rw-smb-063, atk-rw-smb-064, atk-rw-smb-065, atk-rw-smb-066, atk-rw-smb-067, atk-rw-smb-068, atk-rw-smb-069, atk-rw-smb-070, atk-rw-smb-071, atk-rw-smb-072, atk-rw-smb-073, atk-rw-smb-074, atk-rw-smb-075, atk-rw-smb-076, atk-rw-smb-077, atk-rw-smb-078, atk-rw-smb-079
- IOCs: fileserver=10.10.0.41, session_count=80

## Indicators of compromise

- `victim`: 10.10.0.40
- `fileserver`: 10.10.0.41
- `c2_ip`: 170.130.183.204
