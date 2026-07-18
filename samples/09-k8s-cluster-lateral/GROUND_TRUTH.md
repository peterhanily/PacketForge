# GROUND TRUTH — K8s cluster lateral movement in k8s

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Lateral Movement — T1613 Container/Cluster Discovery / T1021 Remote Services (in-cluster)
- A compromised pod (10.244.1.13) discovered cluster services via CoreDNS, reached the API server (10.96.0.1), then fanned out mTLS to 4 pods across the service mesh.
- Flows: atk-k8s-dns-0, atk-k8s-dns-1, atk-k8s-api, atk-k8s-lat-0, atk-k8s-lat-1, atk-k8s-lat-2, atk-k8s-lat-3
- IOCs: attacker_pod=10.244.1.13, api_server=10.96.0.1, pod_count=4, expected_signal=a pod talking to 10.96.0.1:443 then mTLS fan-out to many pods (VXLAN-decapped)

## Indicators of compromise

- `attacker_pod`: 10.244.1.13
- `api_server`: 10.96.0.1
