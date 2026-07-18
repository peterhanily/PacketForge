# GROUND TRUTH — LLMNR poisoning in office

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Credential Access — T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay
- 10.10.0.40 broadcast LLMNR lookups (incl. wpad); 10.10.0.41 poisoned each with its own IP, then 10.10.0.40 authenticated to 10.10.0.41 over SMB — a Responder-style NTLM capture.
- Flows: atk-llmnr-00, atk-llmnr-01, atk-llmnr-02, atk-llmnr-smb
- IOCs: victim=10.10.0.40, attacker=10.10.0.41, expected_signal=dns.log LLMNR answer=10.10.0.41 (a workstation) from a non-DNS host, then SMB 10.10.0.40->10.10.0.41

## Indicators of compromise

- `victim`: 10.10.0.40
- `attacker`: 10.10.0.41
