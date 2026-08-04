# Cloud baselining

A catalogue of the real packet captures that exist for validating PacketForge's cloud
environments, and an argument about the ones that cannot exist. The method for using a reference
capture is in [`../validation.md`](../validation.md).

Cloud is the hardest environment to baseline. Most cloud network data is published as flow logs,
which carry the 5-tuple and nothing else, and never as packets. A survey and direct fetch found
what real cloud pcap does exist, and established where none can.

None of these captures are redistributed here. Real references are ingested for local scoring
only, pinned by URL, and staged in the gitignored `realcap/`.

## What real cloud capture exists

| Reference | Real capture of | What it baselines | Access |
|---|---|---|---|
| COHP `k3s-443` (Spahn et al., RAID 2023) | Kubernetes cryptojacking, k3s API decrypted by PolarProxy | the `k8s-lateral` attack shape | Netresec share |
| redhat-scholars `capture1.pcap` | an Istio and Envoy sidecar exchange | the Kubernetes mesh layer-7 fingerprint | raw GitHub, ungated |
| OTRF Security-Datasets `*_network` | Azure VM east-west traffic, via Netsh and Network Watcher | `azure-vnet` transport, Windows lateral movement | GitHub, archive password `infected` |
| OTRF `empire_dcsync` | a real Empire DCSync over drsuapi | `dcsync`, field for field | GitHub, archive password `infected` |
| CSE-CIC-IDS2018 | an AWS-hosted lab, with real intra-VPC timing, MTU and RTT | `aws-vpc` flow shapes | AWS Open Data, about 450 GB |
| CloudShark EC2 ENI | a real EC2 interface seeing internet background radiation | the `aws-vpc` ingress noise floor | CloudShark community, ungated |
| Stratosphere IoT-23 and CTU-13 | real malicious TLS beaconing and exfiltration | `cloud-exfil` cadence, not its SNI or content | ungated, archive password `infected` |

One nuance decides how much weight the Kubernetes anchor can carry. The COHP capture is HTTP that
PolarProxy decrypted, while a real cluster's API traffic is opaque mTLS, which is what PacketForge
renders. COHP therefore confirms that the attack shape is right. It is a structural anchor, not a
byte-level floor. DCSync is the one clean field-for-field anchor in this table.

## What has no real capture, and cannot

These are structural absences rather than a search that came up empty.

- **`imds-ssrf`, on every provider.** The instance metadata service is link-local
  (`169.254.169.254`, or `100.100.100.200` on Alibaba), terminated by the hypervisor, and
  explicitly excluded from AWS, GCP and Azure traffic mirroring. It never crosses a path a capture
  device sees, which independently corroborates PacketForge's own mirror invariant. Only an on-host
  capture sees it, and none is published. Validation is structural: the IMDSv2 PUT token exchange,
  Azure's `Metadata:true` header and `oauth2/token` path, GCP's `Metadata-Flavor: Google`, and
  OCI's `/opc/v2` bearer flow.
- **`cloud-exfil` content.** Storage endpoints are opaque TLS, and providers log flows rather than
  payloads. Only the TLS record cadence has a real analog. The single observable is the SNI.
- **`oci-vcn`.** No real captures, tools or honeypots exist for Oracle Cloud. It is fully
  synthetic, validated structurally.
- **The VXLAN mirror and CNI overlay envelopes.** VXLAN on 4789, CNI overlay VXLAN on 8472, Geneve
  on 6081, and mesh mTLS are specified in RFC 7348 and provider documentation, with no public
  sample. The decap path has to be generated locally.

## Getting a reference

Ungated and already fetched into `realcap/cloud/`: COHP `k3s-443`, the redhat-scholars Istio
capture, the OTRF network captures including `empire_dcsync`, the CloudShark EC2 ENI capture, and
Stratosphere IoT-23 and CTU-13. Between them they cover `k8s-lateral`, the mesh layer-7
fingerprint, the Azure and AWS substrate, and DCSync.

A cloud account is the only source for the on-host attack flows. Azure Network Watcher produces a
guest-side `.cap`, which is the only real Azure cloud-native attack source. CloudGoat's `ec2_ssrf`
scenario or T-Pot on EC2, captured with on-host `tcpdump`, gives real AWS IMDS-SSRF and cloud
exfiltration. `GoogleCloudPlatform/pcap-sidecar` gives GCS exfiltration TLS and pod egress.

Without cloud spend, `kind` or `k3s` with Cilium's Hubble Recorder or pwru produces a real CNI
overlay and mesh mTLS, and `salrashid123/gce_metadata_server` run locally produces a byte-accurate
GCP metadata service. The kit in [`../../scripts/cloud-capture/`](../../scripts/cloud-capture/)
covers that shape.

## Scope

`k8s-lateral`, the Kubernetes, Azure and AWS east-west substrate, the mesh layer-7 fingerprint and
`dcsync` have real anchors. `imds-ssrf`, `cloud-exfil` content, `oci-vcn` and the mirror and
overlay envelopes structurally cannot, so they stay validated at the level of Zeek log fields and
distributions rather than a byte-level round trip, or they are captured on-host with the kit above
where a real diff is needed.
