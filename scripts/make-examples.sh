#!/usr/bin/env bash
# Regenerate the committed example captures (deterministic). Needs zeek + tshark.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
PY="${PYTHON:-.venv/bin/python}"
mkdir -p examples

gen() {  # env, flows, seed, name, [--attack]
  local env=$1 flows=$2 seed=$3 name=$4; shift 4
  "$PY" -m packetforge scenario --env "$env" --flows "$flows" --seed "$seed" \
        -o "examples/$name.pcap" "$@"
  "$PY" -m packetforge report "examples/$name.pcap" -o "examples/$name.html"
  "$PY" -m packetforge eval "examples/$name.pcap" | head -1
}

gen office 60 101 office-intrusion --attack
gen home   50 102 home-baseline
gen cloud  60 103 cloud-intrusion --attack     # Linux SLL (host-capture) link type
gen ot     50 104 ot-plc-traffic

echo "examples written:"
ls -la examples/*.pcap | awk '{print "  "$NF, $5"B"}'
