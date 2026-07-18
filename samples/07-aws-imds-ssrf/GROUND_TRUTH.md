# GROUND TRUTH — IMDS SSRF credential theft in aws-vpc

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Credential Access — T1552.005 Unsecured Credentials: Cloud Instance Metadata API
- 172.31.0.40 queried the instance metadata service (169.254.169.254) for AWS IAM credentials — SSRF-to-IMDS theft (the Capital One pattern).
- Flows: atk-imds-0, atk-imds-1
- IOCs: victim=172.31.0.40, provider=aws, metadata_ip=169.254.169.254, cred_path=/latest/meta-data/iam/security-credentials/ec2-app-role, expected_signal=http.log to 169.254.169.254 uri=/latest/meta-data/iam/security-credentials/ec2-app-role

## Indicators of compromise

- `victim`: 172.31.0.40
- `provider`: aws
- `metadata_ip`: 169.254.169.254
