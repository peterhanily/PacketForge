#!/usr/bin/env bash
# PacketForge — the whole story in one run (Phases A–D).
#
#   A synthetic AD intrusion where a detection catches a real network TTP, stays
#   silent on realistic background, measurably weakens under evasion, is confirmed by
#   independent tools, and reproduces a real capture. Everything below is generated,
#   validated against real Zeek, and scored against ground truth PacketForge itself made.
#
# Usage:  scripts/demo.sh            (needs: python venv; zeek+tshark for the gates;
#                                      suricata for detection; p0f+pyja3 for cross-val)
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-.venv/bin/python}"
export PYTHONPATH="src"
export PATH="$(brew --prefix 2>/dev/null)/sbin:$PATH"   # p0f lives in sbin
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PCAP="$WORK/incident.pcap"
have() { command -v "$1" >/dev/null 2>&1; }
rule() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }

rule "Phase A · faithful Kerberos + an AD attack"
$PY -m packetforge scenario --env office --volume normal --texture realistic \
    --attack kerberoasting --seed 7 -o "$PCAP" | sed 's/^/  /'
echo "  A Kerberoasting burst (RC4 service tickets) woven into benign AES AD auth."

if have zeek && have tshark; then
  rule "Consistency gate · real Zeek parses it cleanly (realism score)"
  $PY -m packetforge eval "$PCAP" | sed 's/^/  /'
fi

if have suricata; then
  rule "Phase A/C · does a detection catch it — and stay silent on benign AD?"
  $PY -m packetforge detect "$PCAP" --rules detection/example.rules | sed 's/^/  /'

  rule "Phase B · the same rule under evasion (rule robustness, measured)"
  $PY -m packetforge robustness --env office --attack phishing-intrusion \
      --evasion domain-fronting --seed 7 | sed 's/^/  /'

  rule "Phase C · ATT&CK coverage matrix (your rules × the attack library)"
  $PY -m packetforge coverage --env office --rules detection/example.rules \
      --attacks kerberoasting,asrep-roasting,dns-exfil,phishing-intrusion | sed 's/^/  /'
fi

if have zeek && have tshark; then
  rule "Phase C · Sigma over the Zeek logs (his logs, his rule language)"
  $PY -m packetforge sigma "$PCAP" --rules-dir detection/sigma | sed 's/^/  /'

  rule "Phase D · independent tools agree it's real"
  $PY -m packetforge crossval "$PCAP" | sed 's/^/  /'

  if have suricata; then
    rule "Phase D · does a detection transfer? (inert 'real fake malware' → analog)"
    $PY -m packetforge malware-transfer --family shadowbeacon --env office | sed 's/^/  /'
  fi

  rule "Phase D · transfer to a real capture (if one is provided)"
  if [ "${REAL_PCAP:-}" ] && [ -f "${REAL_PCAP:-}" ]; then
    $PY -m packetforge transfer-proof "$REAL_PCAP" --env office | sed 's/^/  /'
  else
    echo "  (set REAL_PCAP=/path/to/real.pcap to also see the benign-capture transfer proof)"
  fi

  rule "Artifact · a self-contained forensic report"
  $PY -m packetforge report "$PCAP" -o incident.html | sed 's/^/  /'
  echo "  open incident.html"
fi

rule "Done"
echo "  One capture. Generated, Zeek-validated, detection-scored against its own"
echo "  ground truth, weakened under evasion on cue, and confirmed by tools we didn't write."
