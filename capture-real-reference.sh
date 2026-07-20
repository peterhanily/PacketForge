#!/usr/bin/env bash
# Capture a LARGER real reference for the realism audit, then print the audit command.
# The first harness grabbed ~20s of web+DNS (~15 flows) — too few to train the C2ST.
# This one captures all traffic for a few minutes AND generates a diverse burst, so the
# real side clears the >=20-flow bar (aim for 100+). Run from the repo root:
#     bash capture-real-reference.sh            # ~180s
#     CAPTURE_SECS=120 bash capture-real-reference.sh
# Privacy: writes to realcap/ (gitignored, never pushed); you only paste aggregate audit
# numbers back. Browse/work normally during the window to add real app diversity.
set -uo pipefail

SECS=${CAPTURE_SECS:-180}
DIR=realcap
mkdir -p "$DIR"; printf '*\n' > "$DIR/.gitignore"       # self-ignore
REAL="$DIR/real.pcap"; SYN="$DIR/synthetic.pcap"

IFACE=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
echo "interface: ${IFACE:-en0}  |  capturing ALL traffic for ${SECS}s -> $REAL"

# --- start a full capture (all traffic, full snaplen) in the background --------
sudo tcpdump -i "${IFACE:-en0}" -s0 -w "$REAL" 2>/dev/null &
TCPD=$!
sleep 2

# --- generate a diverse real-traffic burst for the whole window ----------------
SITES=( example.com www.google.com www.cloudflare.com en.wikipedia.org github.com
        api.github.com www.microsoft.com www.amazon.com duckduckgo.com www.apple.com
        www.mozilla.org www.wikipedia.org news.ycombinator.com www.reddit.com
        www.bbc.co.uk www.nytimes.com cdn.jsdelivr.net fonts.googleapis.com
        www.debian.org archive.org stackoverflow.com www.python.org pypi.org
        registry.npmjs.org ubuntu.com )
END=$(( SECONDS + SECS ))
round=0
while [ "$SECONDS" -lt "$END" ]; do
  round=$((round+1))
  for s in "${SITES[@]}"; do
    [ "$SECONDS" -lt "$END" ] || break
    curl -s -o /dev/null --max-time 6 "https://$s" &            # real TLS 1.3 / HTTP2
    nslookup "$s" >/dev/null 2>&1 &                             # real DNS
  done
  wait
  curl -s -o /dev/null --max-time 6 http://neverssl.com || true # a real port-80 flow
done
echo "generated $round round(s) of diverse traffic"
sleep 2

# --- stop capture --------------------------------------------------------------
sudo kill "$TCPD" 2>/dev/null || true; wait "$TCPD" 2>/dev/null || true
sudo chown "$(id -un)" "$REAL" 2>/dev/null || true

# --- how many flows did Zeek actually see? (this is the gate) ------------------
ZDIR=$(mktemp -d); ( cd "$ZDIR" && zeek -C -r "$OLDPWD/$REAL" 2>/dev/null )
FLOWS=$(grep -vc '^#' "$ZDIR/conn.log" 2>/dev/null || echo 0)
rm -rf "$ZDIR"
echo "real capture: $FLOWS flows in conn.log"
if [ "${FLOWS:-0}" -lt 40 ]; then
  echo "  ! still light — re-run with a longer CAPTURE_SECS, or browse during the window."
fi

# --- a synthetic reference to compare against (home = single-LAN, closest mix) --
if [ -d src/packetforge ]; then
  export PYTHONPATH=src; PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
  "$PY" -m packetforge scenario --env home --volume normal --duration 300 --seed 7 \
        -o "$SYN" >/dev/null 2>&1 && echo "synthetic reference: $SYN"
fi

echo
echo "Now run the audit and paste its output:"
echo "  .venv/bin/python -m packetforge realism-audit --real $REAL --synthetic $SYN"
