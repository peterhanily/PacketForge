# Cloud self-capture kit — a real reference for the cloud scenarios

PacketForge renders cloud attacks (`aws-imds-ssrf`, `cloud-exfil`, `k8s-lateral`) but there is
**no public real pcap** of VPC east-west traffic, IMDS credential theft, storage-API exfil, or a
Kubernetes overlay to baseline them against — this is the one gap the dataset survey couldn't fill.
This kit lets you capture your **own** real reference in a throwaway cloud account, so the cloud
scenarios can be scored with `scripts/baseline_panel.py` / `packetforge realism-audit` like every other env.

Until you run this, treat cloud realism as **UNVALIDATED against real traffic** (inconclusive), not
passed — that's the honest status.

## Ground rules
- **Use a throwaway account and a throwaway VPC/instance you own.** Everything here is authorized
  testing against your own infrastructure. The "attack" traffic is inert-by-signal: hitting *your
  own* instance's IMDS returns *your own* short-lived role creds; the storage exfil uploads benign
  filler to *your own* bucket. Tear the account down afterwards.
- **Never commit the captured pcaps.** They may contain your account IDs, IPs, and short-lived
  tokens. Capture into a gitignored dir (the scripts default to `../../realcap/cloud/`), feed them
  to the scorer locally, and delete. The repo's `.gitignore` already excludes `/realcap/`.
- The captures are the input to the *realism* baseline, not a redistributable artifact.

## What you get, and what it baselines

| Script | Captures | Baselines |
|---|---|---|
| `aws-imds-exfil-capture.sh` | instance-side tcpdump of IMDS SSRF + S3 exfil + ambient | `aws-imds-ssrf`, `cloud-exfil` |
| `k8s-overlay-capture.sh` | pod-to-pod over a kind/k3s VXLAN CNI overlay | `k8s-lateral`, the `--mirror` overlay path |

Azure/GCP: the AWS script is the template — swap IMDS host (`169.254.169.254` is the same on
Azure/GCP, but Azure needs the `Metadata:true` header and GCP `Metadata-Flavor: Google`) and the
storage endpoint (blob / GCS). Notes inline in the script.

## Run it (AWS example)

```bash
# On a throwaway EC2 instance (Amazon Linux/Ubuntu), with an instance role + a throwaway S3 bucket:
sudo ./aws-imds-exfil-capture.sh --bucket my-throwaway-bucket --seconds 180
# -> writes realcap/cloud/aws-imds-exfil.pcap  (instance-side)
```

Then, back on your workstation with the pcap copied to `realcap/cloud/`:

```bash
export PYTHONPATH=src
# render the matching synthetic and score it against your real capture:
.venv/bin/python -m packetforge scenario --env aws-vpc --attack imds-ssrf --duration 180 -o /tmp/syn-imds.pcap
.venv/bin/python -m packetforge realism-audit --real realcap/cloud/aws-imds-exfil.pcap --synthetic /tmp/syn-imds.pcap
# for a real-vs-real floor, capture a SECOND instance/session and use scripts/baseline_panel.py:
.venv/bin/python scripts/baseline_panel.py --real realcap/cloud/aws-imds-exfil.pcap realcap/cloud/aws-imds-exfil-2.pcap --synth /tmp/syn-imds.pcap
```

Read the number the way the rest of the calibration does: **compare synth-vs-real to the
real-vs-real floor, not to 0.5.** Capture at least two independent real cloud references so a floor
exists; a single one is reported INCONCLUSIVE by design.

## VPC Traffic Mirroring (optional, for the `--mirror` path)
The scripts capture host-side (tcpdump on the instance), which matches PacketForge's cloud env
(per-instance agent, Linux SLL). To also baseline the **mirrored** view (`scenario --mirror`, the
VXLAN-encapsulated collector capture), set up AWS VPC Traffic Mirroring from the instance ENI to a
collector ENI and tcpdump UDP/4789 there — see `aws-imds-exfil-capture.sh --mirror-notes`.
