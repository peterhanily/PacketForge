#!/usr/bin/env bash
# Capture a REAL reference for the aws-imds-ssrf + cloud-exfil scenarios, instance-side.
# Run ON a throwaway EC2 instance you own (instance role attached, a throwaway S3 bucket).
# Authorized testing against your own infra only: IMDS returns THIS instance's own short-lived
# role creds; the exfil uploads benign filler to YOUR bucket. Tear down the account after.
#
#   sudo ./aws-imds-exfil-capture.sh --bucket my-throwaway-bucket [--seconds 180] [--out DIR]
#
# Output: <out>/aws-imds-exfil.pcap  (gitignored; NEVER commit — contains account IDs/tokens).
set -uo pipefail

SECS=180; BUCKET=""; OUT="../../realcap/cloud"
while [ $# -gt 0 ]; do case "$1" in
  --seconds) SECS=$2; shift 2;;
  --bucket) BUCKET=$2; shift 2;;
  --out) OUT=$2; shift 2;;
  --mirror-notes) cat <<'N'; exit 0;;
VPC Traffic Mirroring (mirrored/collector view for `scenario --mirror`):
  1. Create a mirror target = the collector instance's ENI (or an NLB).
  2. Create a mirror filter allowing the traffic you care about (or all).
  3. Create a mirror session from THIS instance's ENI -> target. Traffic arrives
     VXLAN-encapsulated on UDP/4789 at the collector.
  4. On the collector:  sudo tcpdump -i any -s0 -w mirror.pcap 'udp port 4789'
  5. Zeek decapsulates it to inner conns + a tunnel.log (Tunnel::VXLAN), exactly like
     PacketForge's --mirror output. Score mirror.pcap the same way.
N
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done
[ -n "$BUCKET" ] || { echo "ERROR: --bucket <throwaway-bucket> required" >&2; exit 2; }

mkdir -p "$OUT"; printf '*\n' > "$OUT/.gitignore"   # self-ignore; never commit cloud captures
PCAP="$OUT/aws-imds-exfil.pcap"
IFACE=$(ip route | awk '/default/{print $5; exit}')
echo "instance capture on ${IFACE:-eth0} for ${SECS}s -> $PCAP"

# capture everything except SSH (avoid recording your own admin session)
tcpdump -i "${IFACE:-eth0}" -s0 -w "$PCAP" 'not (tcp port 22)' &
TCPD=$!; sleep 2

IMDS=169.254.169.254
END=$(( SECONDS + SECS ))
while [ "$SECONDS" -lt "$END" ]; do
  # --- the IMDS SSRF signal (T1552.005): IMDSv2 token dance then the creds path -----
  TOK=$(curl -sf -X PUT "http://$IMDS/latest/api/token" \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' --max-time 3 || true)
  H=(); [ -n "$TOK" ] && H=(-H "X-aws-ec2-metadata-token: $TOK")
  curl -sf --max-time 3 "${H[@]}" "http://$IMDS/latest/meta-data/iam/security-credentials/" >/dev/null || true
  ROLE=$(curl -sf --max-time 3 "${H[@]}" "http://$IMDS/latest/meta-data/iam/security-credentials/" || true)
  [ -n "$ROLE" ] && curl -sf --max-time 3 "${H[@]}" \
        "http://$IMDS/latest/meta-data/iam/security-credentials/$ROLE" >/dev/null || true

  # --- the cloud-storage exfil signal (T1567.002): benign filler uploaded to YOUR bucket --
  head -c $(( (RANDOM % 400 + 50) * 1024 )) /dev/urandom > /tmp/_exfil.bin 2>/dev/null || true
  aws s3 cp --quiet /tmp/_exfil.bin "s3://$BUCKET/exfil-$RANDOM.bin" >/dev/null 2>&1 || true

  # --- ambient: normal instance chatter (package metadata, time) --------------------
  curl -sf --max-time 4 https://amazonlinux.repo.example.com/ >/dev/null 2>&1 || true
  curl -sf --max-time 4 https://sts.amazonaws.com/ >/dev/null 2>&1 || true
  sleep 3
done
rm -f /tmp/_exfil.bin

sleep 2; kill "$TCPD" 2>/dev/null; wait "$TCPD" 2>/dev/null
echo "done. flows Zeek sees:"
command -v zeek >/dev/null && { D=$(mktemp -d); ( cd "$D" && zeek -C -r "$OLDPWD/$PCAP" 2>/dev/null ); \
  echo "  $(grep -vc '^#' "$D/conn.log" 2>/dev/null) conns"; rm -rf "$D"; } || echo "  (install zeek to count)"
echo "Copy $PCAP to your workstation's realcap/cloud/ and score with realism-audit / scripts/baseline_panel.py."
echo "REMINDER: never commit this pcap; delete the throwaway account when finished."
