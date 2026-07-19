# GROUND TRUTH — DCSync against 10.10.0.41

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Credential Access — T1003.006 OS Credential Dumping: DCSync
- DCSync against DC 10.10.0.41: an epmapper lookup then drsuapi DRSGetNCChanges from non-DC host 10.10.0.40 — directory replication of secrets. Inert (zero stubs, no secrets).
- Flows: atk-dcsync-epm, atk-dcsync-drs
- IOCs: attacker=10.10.0.40, target=10.10.0.41, dce_rpc={"endpoint": "drsuapi", "operations": ["DRSGetNCChanges"]}

## Indicators of compromise

- `attacker`: 10.10.0.40
- `target`: 10.10.0.41
