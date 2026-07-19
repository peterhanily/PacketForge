#!/usr/bin/env bash
# Capture a REAL reference for the k8s-lateral scenario: pod-to-pod traffic over a CNI overlay.
# Runs a local throwaway kind/k3s cluster (no cloud account needed) and captures the node's
# overlay interface, so you get the real VXLAN-encapsulated pod network PacketForge models.
# Authorized: your own local cluster, benign in-cluster HTTP between two pods.
#
#   sudo ./k8s-overlay-capture.sh [--seconds 180] [--out DIR]
#
# Output: <out>/k8s-overlay.pcap  (gitignored; never commit). Needs: kind OR k3s, kubectl, tcpdump.
set -uo pipefail

SECS=180; OUT="../../realcap/cloud"
while [ $# -gt 0 ]; do case "$1" in
  --seconds) SECS=$2; shift 2;;
  --out) OUT=$2; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done
mkdir -p "$OUT"; printf '*\n' > "$OUT/.gitignore"
PCAP="$OUT/k8s-overlay.pcap"

command -v kubectl >/dev/null || { echo "ERROR: need kubectl" >&2; exit 2; }
echo "assuming a running kind/k3s cluster (kubectl get nodes must work):"
kubectl get nodes || { echo "start one: 'kind create cluster' or install k3s" >&2; exit 2; }

# two pods: a server (nginx) and a client that curls it across the pod network (lateral movement shape)
kubectl run pf-victim --image=nginx --restart=Never >/dev/null 2>&1 || true
kubectl wait --for=condition=Ready pod/pf-victim --timeout=90s >/dev/null 2>&1 || true
VIP=$(kubectl get pod pf-victim -o jsonpath='{.status.podIP}' 2>/dev/null)
echo "victim pod IP (overlay): ${VIP:-<none>}"

# capture the overlay interface on the node. kind uses a docker bridge; k3s flannel uses flannel.1
# (VXLAN). Capture UDP/8472 (flannel VXLAN) or the veth bridge; 'any' is the safe catch-all.
IFACE=any
tcpdump -i "$IFACE" -s0 -w "$PCAP" '(udp port 8472) or (udp port 4789) or net 10.0.0.0/8' &
TCPD=$!; sleep 2

END=$(( SECONDS + SECS ))
while [ "$SECONDS" -lt "$END" ]; do
  # in-cluster lateral movement shape: a client pod repeatedly reaching the victim + the API server
  kubectl run pf-attacker --rm -i --restart=Never --image=curlimages/curl --command -- \
    sh -c "for i in 1 2 3 4 5; do curl -s -o /dev/null http://$VIP/ ; \
           curl -sk -o /dev/null https://kubernetes.default.svc/ ; sleep 2; done" >/dev/null 2>&1 || true
done

sleep 2; kill "$TCPD" 2>/dev/null; wait "$TCPD" 2>/dev/null
kubectl delete pod pf-victim --now >/dev/null 2>&1 || true
echo "done -> $PCAP"
command -v zeek >/dev/null && { D=$(mktemp -d); ( cd "$D" && zeek -C -r "$OLDPWD/$PCAP" 2>/dev/null ); \
  echo "  conns: $(grep -vc '^#' "$D/conn.log" 2>/dev/null); tunnel.log: $([ -f "$D/tunnel.log" ] && echo yes || echo no)"; \
  rm -rf "$D"; }
echo "Score vs:  packetforge scenario --env k8s --attack k8s-lateral --mirror -o /tmp/syn-k8s.pcap"
echo "then scripts/baseline_panel.py --real $PCAP <second-capture> --synth /tmp/syn-k8s.pcap"
echo "REMINDER: never commit this pcap."
