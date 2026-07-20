#!/usr/bin/env bash
# Real-vs-synthetic packet comparison harness.
# Run from the PacketForge repo root:  bash real-vs-synth.sh
# Needs sudo (for tcpdump) and network. Captures ONLY web+DNS, to a self-ignoring dir.
# Paste the whole "===== SUMMARY =====" block back for assessment. The .pcap stays local.
set -uo pipefail

DIR=realcap
mkdir -p "$DIR"
printf '*\n' > "$DIR/.gitignore"          # dir ignores itself; nothing here is committed
REAL="$DIR/real.pcap"
SYN="$DIR/synthetic.pcap"

IFACE=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
echo "interface: ${IFACE:-<none>}  (capturing tcp 443/80 + udp 53 only)"

# --- 1. start a filtered capture in the background (full snaplen for TLS) -----
sudo tcpdump -i "${IFACE:-en0}" -s0 -w "$REAL" \
     '(tcp port 443 or tcp port 80 or udp port 53)' 2>/dev/null &
TCPD=$!
sleep 2

# --- 2. generate REAL traffic: DNS + TLS to diverse servers + one plain HTTP --
SITES=( https://example.com https://www.google.com https://www.cloudflare.com
        https://en.wikipedia.org https://github.com https://www.microsoft.com
        https://www.amazon.com https://duckduckgo.com )
for s in "${SITES[@]}"; do curl -s -o /dev/null --max-time 8 "$s" || true; done
curl -s -o /dev/null --max-time 8 http://neverssl.com || true      # real port-80 HTTP
for h in example.com google.com cloudflare.com github.com azure.com; do
    nslookup "$h" >/dev/null 2>&1 || true
done
sleep 2

# --- 3. stop capture ----------------------------------------------------------
sudo kill "$TCPD" 2>/dev/null || true; wait "$TCPD" 2>/dev/null || true
sudo chown "$(id -un)" "$REAL" 2>/dev/null || true

# --- 4. generate the SYNTHETIC equivalent (same knobs I used) -----------------
if [ -d src/packetforge ]; then
  export PYTHONPATH=src
  PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
  "$PY" -m packetforge scenario --env office --volume normal --duration 120 --seed 7 \
        -o "$SYN" >/dev/null 2>&1 || echo "(synthetic gen skipped)"
fi

# --- 5. identical dissection of both ------------------------------------------
sumup() {  # $1 pcap  $2 label
  local P=$1 L=$2
  [ -f "$P" ] || { echo "## $L: (no pcap)"; return; }
  echo "########## $L : $P ##########"
  echo "-- protocol hierarchy --";  tshark -r "$P" -q -z io,phs 2>/dev/null | sed -n '6,40p'
  echo "-- IP TTLs (count) --";     tshark -r "$P" -T fields -e ip.ttl 2>/dev/null | sort | uniq -c | sort -rn | head
  echo -n "-- IP.id sample: ";      tshark -r "$P" -T fields -e ip.id 2>/dev/null | grep -v '^$' | head -10 | tr '\n' ' '; echo
  echo "-- client-SYN tcp.options (uniq) --"
  tshark -r "$P" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.options 2>/dev/null | sort | uniq -c
  echo "-- client-SYN  win | mss | tsval | wscale (uniq) --"
  tshark -r "$P" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields \
     -e tcp.window_size_value -e tcp.options.mss_val -e tcp.options.timestamp.tsval -e tcp.options.wscale.shift 2>/dev/null | sort | uniq -c | head
  echo -n "-- pkts w/ TCP timestamp: "; tshark -r "$P" -Y "tcp.options.timestamp.tsval" 2>/dev/null | wc -l | tr -d ' '
  echo -n " | retransmits: ";          tshark -r "$P" -Y "tcp.analysis.retransmission" 2>/dev/null | wc -l | tr -d ' '
  echo -n " | dup-acks: ";             tshark -r "$P" -Y "tcp.analysis.duplicate_ack" 2>/dev/null | wc -l | tr -d ' '; echo
  echo "-- ClientHello: version | ciphers | exts | groups | ecpf (uniq) --"
  tshark -r "$P" -Y "tls.handshake.type==1" -T fields \
     -e tls.handshake.version -e tls.handshake.ciphersuite -e tls.handshake.extension.type \
     -e tls.handshake.extensions_supported_group -e tls.handshake.extensions_ec_point_format 2>/dev/null | sort -u
  echo -n "-- hellos w/ ALPN(16): ";               tshark -r "$P" -Y "tls.handshake.type==1 && tls.handshake.extension.type==16" 2>/dev/null | wc -l | tr -d ' '
  echo -n " | supported_versions(43): ";           tshark -r "$P" -Y "tls.handshake.type==1 && tls.handshake.extension.type==43" 2>/dev/null | wc -l | tr -d ' '
  echo -n " | key_share(51): ";                    tshark -r "$P" -Y "tls.handshake.type==1 && tls.handshake.extension.type==51" 2>/dev/null | wc -l | tr -d ' '
  echo -n " | session_ticket(35): ";               tshark -r "$P" -Y "tls.handshake.type==1 && tls.handshake.extension.type==35" 2>/dev/null | wc -l | tr -d ' '; echo
  echo
}

echo "===== SUMMARY (paste everything from here down) ====="
echo "host OS: $(uname -sr) | tshark: $(tshark -v 2>/dev/null | head -1)"
sumup "$REAL" REAL
sumup "$SYN"  SYNTHETIC
echo "===== END SUMMARY ====="
