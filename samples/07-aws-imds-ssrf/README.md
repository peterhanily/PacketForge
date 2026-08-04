# AWS IMDS credential theft via SSRF (T1552.005, the Capital One shape)

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and `zeek/` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

**What to look for**
- **`zeek/http.log`.** Two GETs reach 169.254.169.254 from the instance 172.31.0.40:
  `/latest/meta-data/`, then `/latest/meta-data/iam/security-credentials/ec2-app-role`. The
  second returns the instance role's temporary credentials (T1552.005).
- **SSRF.** Server-side request forgery makes an application fetch a URL the attacker supplies.
  Pointed at the link-local metadata address, it becomes credential theft.
- **Vantage.** The capture is host-side on the instance in Linux SLL. A VPC has no switch to span,
  so this is where a cloud sensor usually sits.
- **The address is real infrastructure.** 169.254.169.254 is AWS's metadata service. The request
  path is the finding, not the destination.
- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.

**Reproduce**
```
scripts/make-samples.sh   # aws-vpc: an instance pulling its IAM credentials off IMDS
```
