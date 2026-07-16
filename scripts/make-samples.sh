#!/usr/bin/env bash
# Regenerate the sample captures under samples/ (deterministic). Needs zeek + tshark.
#
# Each sample folder keeps its hand-written README.md; this script regenerates the data:
# capture.pcap, the real Zeek logs it produces (zeek/), and — for attacks — GROUND_TRUTH.*.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
PY="${PYTHON:-.venv/bin/python}"

zeek_of() {  # dir -> regenerate its zeek/ logs from capture.pcap (traffic logs only)
  local dir=$1
  rm -rf "$dir/zeek"; mkdir -p "$dir/zeek"
  ( cd "$dir/zeek" && zeek -C -r ../capture.pcap detect_filtered_trace=F )
  # drop Zeek's diagnostic logs — they carry no traffic and analyzer.log embeds Zeek's
  # own build path. Keep only the protocol logs a hunter reads.
  rm -f "$dir/zeek/analyzer.log" "$dir/zeek/packet_filter.log" "$dir/zeek/reporter.log"
}

tidy_ground_truth() {  # scenario writes <base>.GROUND_TRUTH.*; samples want GROUND_TRUTH.*
  local dir=$1
  for ext in md json; do
    if [ -f "$dir/capture.GROUND_TRUTH.$ext" ]; then
      mv -f "$dir/capture.GROUND_TRUTH.$ext" "$dir/GROUND_TRUTH.$ext"
    fi
  done  # note: an `&& mv` one-liner returns 1 for no-attack samples and trips `set -e`
}

scenario() {  # dir, env, args...
  local dir=$1 env=$2; shift 2
  mkdir -p "samples/$dir"
  "$PY" -m packetforge scenario --env "$env" "$@" -o "samples/$dir/capture.pcap"
  tidy_ground_truth "samples/$dir"
  zeek_of "samples/$dir"
}

compile() {  # dir, flowspec
  local dir=$1 spec=$2
  mkdir -p "samples/$dir"
  "$PY" -m packetforge compile "$spec" -o "samples/$dir/capture.pcap"
  zeek_of "samples/$dir"
}

beacon_reference() {  # dir -> the JA3-fingerprinted C2 reference (office noise + beacons)
  local dir=$1
  mkdir -p "samples/$dir"
  "$PY" - "$dir" <<'PY'
import sys
from packetforge.compile.timeline import write_pcap
from packetforge.environments import load_environment
from packetforge.malware_transfer import build_reference
fs = build_reference("shadowbeacon", load_environment("office"), seed=0)
write_pcap(fs, f"samples/{sys.argv[1]}/capture.pcap")
PY
  zeek_of "samples/$dir"
}

scenario 01-kerberoasting-in-ad office --volume normal --texture realistic --attack kerberoasting --seed 11
scenario 02-phishing-to-exfil   office --volume normal --texture realistic --attack phishing-intrusion --seed 7
compile  03-artifact-extraction flows/extraction.yaml
scenario 04-ransomware-smb-theft office --volume normal --attack ransomware --seed 5
scenario 05-dns-tunnel-exfil    office --volume normal --attack dns-exfil --seed 3
beacon_reference 06-c2-beacon-ja3
scenario 07-ot-modbus-plant     ot --volume normal --seed 2
scenario 08-cloud-vpc-sll       cloud --volume normal --texture realistic --attack phishing-intrusion --seed 8

echo "samples regenerated:"
for d in samples/0*/; do
  printf "  %-26s %8sB pcap\n" "$(basename "$d")" "$(wc -c < "$d/capture.pcap")"
done
