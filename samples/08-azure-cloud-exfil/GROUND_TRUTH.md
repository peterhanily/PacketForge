# GROUND TRUTH — Cloud-storage exfil in azure-vnet

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Exfiltration — T1567.002 Exfiltration to Cloud Storage
- 6 large HTTPS uploads from 10.1.0.40 to AZURE cloud storage (exfilstg.blob.core.windows.net) — data staged out through a trusted cloud endpoint.
- Flows: atk-cx-dns, atk-cx-00, atk-cx-01, atk-cx-02, atk-cx-03, atk-cx-04, atk-cx-05
- IOCs: victim=10.1.0.40, provider=azure, storage=exfilstg.blob.core.windows.net, expected_signal=ssl.log server_name=exfilstg.blob.core.windows.net with large orig_bytes (upload-heavy)

## Indicators of compromise

- `victim`: 10.1.0.40
- `provider`: azure
- `storage`: exfilstg.blob.core.windows.net
