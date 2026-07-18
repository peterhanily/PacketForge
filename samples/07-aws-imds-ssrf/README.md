# AWS IMDS credential theft via SSRF (T1552.005 — the Capital One shape)

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the `zeek/` logs are what real Zeek 8.2 derives.

**What to look for**
- `zeek/http.log`: HTTP to the link-local metadata service **169.254.169.254** on `/latest/meta-data/iam/security-credentials/...` — instance-role credential theft. Captured host-side (Linux SLL, the realistic cloud vantage).
- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth

**Reproduce**
```
scripts/make-samples.sh   # aws-vpc: an instance pulling its IAM credentials off IMDS
```
