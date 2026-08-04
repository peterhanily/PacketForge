# Cloud self-capture kit

PacketForge renders three cloud attacks: `imds-ssrf`, `cloud-exfil` and `k8s-lateral`. No public packet capture shows
credential theft from a cloud instance metadata service (IMDS), storage-API exfiltration, or east-west traffic inside
a virtual private cloud. [`../../docs/appendix/cloud-baselines.md`](../../docs/appendix/cloud-baselines.md) catalogues
the real cloud capture that exists and the cases where none can. This kit captures your own reference in a throwaway
cloud account, so the cloud scenarios can be scored with `scripts/baseline_panel.py` and `packetforge realism-audit`.
Until you run it, cloud realism is unvalidated against real traffic. Report it as inconclusive, not passed.

## Ground rules

- **Use a throwaway account, network and instance you own.** This is authorized testing against your own
  infrastructure. Your instance's IMDS returns your own short-lived role credentials, and the exfil step uploads benign
  filler to your own bucket. Tear the account down afterwards.
- **Never commit the captured pcaps.** They may contain your account IDs, addresses and short-lived tokens. Capture
  into a gitignored directory (the scripts default to `../../realcap/cloud/`), feed them to the scorer locally, then
  delete them. The repo `.gitignore` already excludes `/realcap/`.
- **The captures are scoring input.** They are not a redistributable artifact.

## What each script captures

`aws-imds-exfil-capture.sh` runs tcpdump on the instance and drives two signals in a loop: an IMDS server-side request
forgery (SSRF) against the link-local metadata address, and an S3 upload standing in for exfiltration.
`k8s-overlay-capture.sh` needs no cloud account. It drives pod-to-pod HTTP on a local kind or k3s cluster and captures
the node's overlay interface, which is the Virtual Extensible LAN (VXLAN) tunnel endpoint, or VTEP.

| Script | Captures | Baselines |
|---|---|---|
| `aws-imds-exfil-capture.sh` | IMDS SSRF, S3 exfil, ambient chatter | `imds-ssrf`, `cloud-exfil` |
| `k8s-overlay-capture.sh` | pod-to-pod over a container network interface (CNI) overlay | `k8s-lateral`, the `--mirror` path |

The AWS script is the template for Azure and GCP. Swap the IMDS host and the storage endpoint. The address
`169.254.169.254` is the same on all three providers, but Azure needs the `Metadata:true` header and GCP needs
`Metadata-Flavor: Google`. Notes are inline in the script.

## Run it (AWS example)

```bash
# On a throwaway EC2 instance (Amazon Linux or Ubuntu), with an instance role and a throwaway bucket:
sudo ./aws-imds-exfil-capture.sh --bucket my-throwaway-bucket --seconds 180
# writes realcap/cloud/aws-imds-exfil.pcap (instance-side)
```

Then, back on your workstation with the pcap copied to `realcap/cloud/`:

```bash
export PYTHONPATH=src
# render the matching synthetic and score it against your real capture:
.venv/bin/python -m packetforge scenario --env aws-vpc --attack imds-ssrf --duration 180 -o /tmp/syn-imds.pcap
.venv/bin/python -m packetforge realism-audit --real realcap/cloud/aws-imds-exfil.pcap --synthetic /tmp/syn-imds.pcap
# for a real-vs-real floor, capture a SECOND instance or session and use scripts/baseline_panel.py:
.venv/bin/python scripts/baseline_panel.py --real realcap/cloud/aws-imds-exfil.pcap realcap/cloud/aws-imds-exfil-2.pcap --synth /tmp/syn-imds.pcap
```

Read the score the way the rest of the calibration does. Compare synthetic-versus-real to the real-versus-real floor,
not to 0.5. Capture at least two independent real references so a floor exists. A single reference is reported
INCONCLUSIVE by design.

## A Kubernetes reference without a cloud account

For the `k8s` environment, a real container-network reference already exists: the eBPF and XDP veth capture corpus
from arXiv 2410.18332, in a Google Drive folder linked from the paper. It anchors the overlay substrate only, since
its attacks are denial of service and Heartbleed, not the techniques here. Decode its outer encapsulation to pin the
CNI. Flannel uses VXLAN on UDP/8472 and cilium uses Generic Network Virtualization Encapsulation (Geneve) on UDP/6081.
Match the result against `k8s.yaml`, then compute a real-vs-real floor for `build_k8s_lateral` with
`scripts/baseline_panel.py`.

The AWS, Azure and GCP virtual machine environments have no real public attack capture. The absence is structural:
providers expose only flow logs, and native mirroring excludes 169.254/16, an exclusion PacketForge enforces as a
generator invariant. Validate those environments structurally and capture the rest here.

## VPC traffic mirroring (optional)

The scripts capture host-side, with tcpdump on the instance. That matches PacketForge's cloud environment, which
models a per-instance agent writing Linux cooked-capture (SLL) frames. The mirrored view is the VXLAN-encapsulated
collector capture that `scenario --mirror` renders. To baseline that too, set up AWS VPC traffic mirroring from the
instance's elastic network interface (ENI) to a collector ENI, then tcpdump UDP/4789 there. Run
`aws-imds-exfil-capture.sh --mirror-notes` for the steps.
