# Cloud baselining — real reference captures for the cloud envs

The cloud scenarios (`aws-vpc`, `azure-vnet`, `gcp-vpc`, `oci-vcn`, `k8s` + the IMDS-SSRF /
cloud-exfil / k8s-lateral attacks) are the hardest to validate against real traffic, because most
cloud network data is exposed only as **flow logs** (5-tuple metadata), never packets. A wide survey
+ direct fetch found what real cloud pcap does exist, and — just as importantly — proved where none
can. This is the catalog. Method for *using* a reference is in [`realism-baselining.md`](realism-baselining.md).

None of these captures are redistributed. Real references are ingested for **local scoring only**,
pinned by URL, staged in the gitignored `realcap/` (never committed or pushed).

## What real cloud pcap exists (verified, downloadable)

| Reference | Real capture of | Baselines | Access |
|---|---|---|---|
| **COHP** `k3s-443` (Spahn et al., RAID'23) | Real k8s cryptojacking — PolarProxy-decrypted k3s API (`/apis/apps` DaemonSet → `kube-system` → miner C2) | **k8s-lateral** attack shape | Netresec share (per-file GET works) |
| **redhat-scholars `capture1.pcap`** | Real Istio/Envoy sidecar exchange (`istio-envoy`, `x-envoy-peer-metadata`) | **k8s mesh** L7 fingerprint | raw GitHub, ungated |
| **OTRF/Security-Datasets** `*_network` | Real Azure-VM VNet east-west (Netsh + Network Watcher) | **azure-vnet** transport + Windows lateral | GitHub, pw `infected` |
| **OTRF `empire_dcsync`** | Real Empire DCSync (drsuapi, Zeek logs the ops) | **`dcsync`** — field-for-field anchor | GitHub, pw `infected` |
| **CSE-CIC-IDS2018** | AWS-hosted lab — authentic intra-VPC TCP/HTTP/TLS timing/MTU/RTT | **aws-vpc** flow shapes | AWS Open Data, ~450GB |
| **CloudShark EC2 ENI** | Real EC2 interface — internet scan/background radiation | **aws-vpc** ingress noise floor | CloudShark community, ungated |
| **Stratosphere IoT-23/CTU-13** | Real malicious-TLS beacon/exfil | **cloud-exfil** *cadence* analog (not SNI/content) | ungated, pw `infected` |

The nuance that matters: the k8s/COHP capture is PolarProxy-**decrypted** HTTP, while a real cluster's
API traffic is **opaque mTLS** — which PacketForge renders. So COHP confirms the *attack shape* is
right; it is a structural anchor, not a byte-level C2ST floor. DCSync is the one clean field-for-field
cloud-adjacent anchor.

## What has NO real pcap (structural — not a search failure)

- **`imds-ssrf` (every cloud)** — IMDS is link-local (`169.254.169.254`, Alibaba `100.100.100.200`),
  hypervisor-terminated, and **explicitly excluded from AWS/GCP/Azure mirroring**. It never crosses a
  path a capture device sees. This *corroborates* PacketForge's mirror-excludes-link-local invariant.
  Only an on-host capture sees it, and none is published. Validate structurally (IMDSv2 PUT-token,
  Azure `Metadata:true` + `oauth2/token`, GCP `Metadata-Flavor: Google`, OCI `/opc/v2` Bearer).
- **`cloud-exfil` content** — opaque TLS to storage endpoints; providers log flows, never payloads.
  Only the TLS-record *cadence* has a real analog. The one observable is the SNI (`bucket.s3…` etc.).
- **`oci-vcn`** — zero real captures, tools, or honeypots for Oracle Cloud. Fully synthetic; structural
  validation only.
- **VXLAN mirror (4789) + CNI overlay (VXLAN 8472 / Geneve 6081) + mesh mTLS** — spec-only (RFC 7348 +
  provider docs); no public sample. Self-generate the decap path.

## Acquisition plan

**Download now (ungated, real):** COHP `k3s-443` · redhat-scholars istio · OTRF network pcaps (incl.
`empire_dcsync`) · CloudShark EC2 ENI · Stratosphere IoT-23/CTU-13. These cover k8s-lateral, mesh-L7,
azure/aws substrate, and DCSync with real data. (PacketForge already fetched and verified these into
`realcap/cloud/`.)

**Gated (a cloud account — the only source for the on-host attack flows):**
- **Azure Network Watcher** guest-side `.cap` → the only real Azure cloud-native attack source.
- **CloudGoat `ec2_ssrf` / T-Pot on EC2** + on-host tcpdump → real aws imds-ssrf / cloud-exfil.
- **`GoogleCloudPlatform/pcap-sidecar`** → canonical real GCS-exfil TLS + pod egress.

**Self-capture, no cloud spend:** `kind`/`k3s` + **Cilium Hubble Recorder / pwru** → real CNI overlay
(VXLAN 8472 / Geneve 6081) + mesh mTLS; **`salrashid123/gce_metadata_server`** locally → byte-accurate
GCP IMDS. The [`scripts/cloud-capture/`](../scripts/cloud-capture/) kit covers this shape.

**Build-only (structural):** IMDS schemas + the VXLAN mirror byte format from provider docs.

## Honest scope
`k8s-lateral`, the k8s/azure/aws east-west *substrate*, mesh-L7, and `dcsync` have real ground truth.
`imds-ssrf`, `cloud-exfil` content, `oci-vcn`, and the mirror/overlay envelopes structurally cannot,
and stay validated at the Zeek-log / field-distribution level — never a byte-level round-trip — or
minted on-host with the capture kit where a diff is genuinely needed.
