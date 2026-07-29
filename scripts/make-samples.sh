#!/usr/bin/env bash
# Regenerate the sample gallery under samples/ (deterministic). Needs zeek + tshark.
#
# Each sample folder holds a generated capture.pcap, the real Zeek logs it produces (zeek/),
# a short README, and — for attacks — a GROUND_TRUTH answer key. The gallery is a tour of what
# PacketForge can render: classic AD/OT attacks, the lateral-movement and AiTM packs, cloud
# (AWS/Azure + Kubernetes), IPv6, encrypted-DNS, multi-vantage capture, VXLAN mirroring, and
# IDS-evasion fragmentation.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
PY="${PYTHON:-.venv/bin/python}"

rm -rf samples/[0-9]*        # renumbered gallery — clear the old set first

zeek_into() {  # outdir pcap_relative_to_outdir -> deterministic, byte-reproducible zeek logs
  local outdir=$1 pcap=$2
  rm -rf "$outdir"; mkdir -p "$outdir"
  # -D (deterministic): fixed random seeds, so connection uids and log ordering reproduce
  # byte-for-byte across runs instead of churning on every regen.
  ( cd "$outdir" && zeek -D -C -r "$pcap" FilteredTraceDetection::enable=F )
  rm -f "$outdir/analyzer.log" "$outdir/packet_filter.log" "$outdir/reporter.log"
  # Normalize the wall-clock log-generation stamp (the only remaining per-run difference).
  perl -i -pe 's/^(#(?:open|close))\t.*/$1\t0000-00-00-00-00-00/' "$outdir"/*.log 2>/dev/null || true
}

zeek_of() {  # dir [pcap] -> regenerate dir/zeek from a capture (traffic logs only)
  local dir=$1 pcap=${2:-capture.pcap}
  zeek_into "$dir/zeek" "../$pcap"
}

tidy_gt() {  # <base>.GROUND_TRUTH.* -> GROUND_TRUTH.*
  local dir=$1
  for ext in md json; do
    [ -f "$dir/capture.GROUND_TRUTH.$ext" ] && mv -f "$dir/capture.GROUND_TRUTH.$ext" "$dir/GROUND_TRUTH.$ext" || true
  done
}

readme() {  # dir title lookfor reproduce
  local dir=$1 title=$2 lookfor=$3 repro=$4 gt=""
  [ -f "samples/$dir/GROUND_TRUTH.md" ] && gt=$'\n- Answer key: [`GROUND_TRUTH.md`](GROUND_TRUTH.md) — the labelled ATT&CK ground truth'
  cat > "samples/$dir/README.md" <<EOF
# $title

Synthetic, inert, deterministic — fake traffic with true labels; no real hosts, credentials,
malware, or documents. Opens in Wireshark; the \`zeek/\` logs are what real Zeek 8.2 derives.

**What to look for**
$lookfor$gt

**Reproduce**
\`\`\`
$repro
\`\`\`
EOF
}

scenario() {  # dir env args...
  local dir=$1 env=$2; shift 2
  mkdir -p "samples/$dir"
  "$PY" -m packetforge scenario --env "$env" --duration 200 "$@" -o "samples/$dir/capture.pcap" >/dev/null
  tidy_gt "samples/$dir"; zeek_of "samples/$dir"
}

# --------------------------------------------------------------------------- #
# 1. Attack storylines — the classic ATT&CK-mapped kill chains.               #
# --------------------------------------------------------------------------- #
scenario 01-kerberoasting-in-ad office --volume normal --texture realistic --attack kerberoasting --seed 11
readme 01-kerberoasting-in-ad "Kerberoasting in Active Directory (T1558.003)" \
"- \`zeek/kerberos.log\`: a normal AES TGT, then a burst of TGS-REQs each forcing **RC4** (\`cipher=rc4-hmac\`) for distinct SPNs — the offline-crackable downgrade. The fingerprint + burst is the tell, not any IOC." \
"scripts/make-samples.sh   # office AD noise + a Kerberoasting burst"

scenario 02-phishing-kill-chain office --volume normal --texture realistic --attack phishing-intrusion --seed 7
readme 02-phishing-kill-chain "Phishing to exfiltration — a full kill chain (T1566 -> T1048)" \
"- The \`atk-*\` flows across \`smtp/dns/ssl/ldap/smb/http\` logs: phishing email -> HTTPS C2 beacons (non-browser JA3, fixed cadence) -> LDAP/SMB discovery -> ADMIN\$ lateral -> a 45 KB HTTP POST exfil." \
"scripts/make-samples.sh   # the reference intrusion woven into office noise"

scenario 03-ransomware-smb-theft office --volume normal --attack ransomware --seed 5
readme 03-ransomware-smb-theft "Ransomware mass SMB document theft (T1486)" \
"- \`zeek/smb_files.log\`: ~80 documents read off the share in a rapid sweep — each carved and extractable via Wireshark 'Export Objects > SMB' (inert filler content in real containers)." \
"scripts/make-samples.sh   # office noise + a mass-SMB encryption sweep"

scenario 04-dns-tunnel-exfil office --volume normal --attack dns-exfil --seed 3
readme 04-dns-tunnel-exfil "DNS tunnelling exfiltration (T1048.003)" \
"- \`zeek/dns.log\`: dozens of long base32-encoded subdomains under one parent, NXDOMAIN — the query length + volume + entropy is the signal." \
"scripts/make-samples.sh   # a DNS-tunnel burst in office noise"

scenario 05-bzar-lateral-movement office --volume normal --attack psexec-lateral --seed 6
readme 05-bzar-lateral-movement "PsExec-style lateral movement — the BZAR pack (T1021.002 / T1569.002)" \
"- \`zeek/dce_rpc.log\`: an \`epmapper::ept_map\` endpoint lookup on 135, then the full svcctl service-install sequence (\`OpenSCManagerW\` -> \`CreateServiceW\` -> \`QueryServiceStatus\` -> \`OpenServiceW\` -> \`StartServiceW\` -> \`CloseServiceHandle\`) over a named pipe — matching a real PsExec capture — plus an ADMIN\$ file write in \`smb_files.log\`. The combination MITRE **BZAR** raises \`ATTACK::Lateral_Movement_and_Execution\` on. Inert: the RPC argument stubs are zero filler, never a service binary or command." \
"scripts/make-samples.sh   # remote service creation + admin-share tool drop"

scenario 06-llmnr-poisoning office --volume normal --attack llmnr-poisoning --seed 4
readme 06-llmnr-poisoning "LLMNR/NBT-NS poisoning -> NTLM (Responder-style, T1557.001)" \
"- \`zeek/dns.log\`: LLMNR queries (incl. \`wpad\`) answered by a rogue host claiming **its own IP** — then the victim authenticates to that host over SMB. The tell is an LLMNR answer of a workstation IP from a non-DNS host, followed by SMB to it.
- \`zeek/ntlm.log\`: the captured credential — \`username=jsmith domainname=CORP hostname=WKS-042\` handed to the rogue host. Inert by construction: the NTLMSSP framing and identity are real, but the LM/NT responses are fixed filler, never an offline-crackable hash." \
"scripts/make-samples.sh   # a broadcast-name poisoning + SMB auth capture"

# --------------------------------------------------------------------------- #
# 2. Cloud & modern — AWS/Azure, Kubernetes, IPv6, encrypted DNS.             #
# --------------------------------------------------------------------------- #
scenario 07-aws-imds-ssrf aws-vpc --volume normal --attack imds-ssrf --seed 6
readme 07-aws-imds-ssrf "AWS IMDS credential theft via SSRF (T1552.005 — the Capital One shape)" \
"- \`zeek/http.log\`: HTTP to the link-local metadata service **169.254.169.254** on \`/latest/meta-data/iam/security-credentials/...\` — instance-role credential theft. Captured host-side (Linux SLL, the realistic cloud vantage)." \
"scripts/make-samples.sh   # aws-vpc: an instance pulling its IAM credentials off IMDS"

scenario 08-azure-cloud-exfil azure-vnet --volume normal --attack cloud-exfil --seed 6
readme 08-azure-cloud-exfil "Exfiltration to Azure Blob storage (T1567.002)" \
"- \`zeek/ssl.log\`: large HTTPS uploads to \`*.blob.core.windows.net\` — data staged out through a trusted cloud endpoint (upload-heavy \`orig_bytes\` in \`conn.log\` is the signal)." \
"scripts/make-samples.sh   # azure-vnet: ~440 KB uploads to Blob storage"

# Kubernetes: the inner pod traffic, plus the same incident as a VXLAN traffic mirror sees it.
mkdir -p samples/09-k8s-cluster-lateral
"$PY" -m packetforge scenario --env k8s --duration 200 --volume normal --attack k8s-lateral --seed 6 --mirror \
  -o samples/09-k8s-cluster-lateral/capture.pcap >/dev/null
tidy_gt samples/09-k8s-cluster-lateral
zeek_of samples/09-k8s-cluster-lateral
# ship the mirror's decapsulated logs too, so the VXLAN-decap claim is proven in-artifact
zeek_into samples/09-k8s-cluster-lateral/zeek-mirror ../capture.mirror.pcap
readme 09-k8s-cluster-lateral "Kubernetes cluster lateral movement + a VXLAN traffic mirror (T1613 / T1021)" \
"- \`zeek/\` (direct pod-network SPAN) plus \`capture.mirror.pcap\` — what an AWS VPC Traffic Mirror / GCP Packet Mirror sees: the same flows VXLAN-encapsulated to a collector VTEP. \`zeek-mirror/\` is what Zeek derives from that mirror: a \`tunnel.log\` (\`Tunnel::VXLAN\`, port 4789) **plus the identical inner conns** — decapsulation recovers the incident. The attack: a compromised pod hits the API server (10.96.0.1) then fans out mTLS across the mesh." \
"scripts/make-samples.sh   # k8s pod-to-pod lateral, direct + VXLAN-mirrored"

scenario 10-ipv6-c2-beacon office --volume normal --attack ipv6-c2 --seed 5
readme 10-ipv6-c2-beacon "HTTPS C2 beaconing over IPv6 (T1071.001)" \
"- \`zeek/ssl.log\`: AAAA resolution then HTTPS beacons to an IPv6 C2 with a curl JA3 at ~60s cadence — the identical C2 behaviour a v4-only detection silently misses." \
"scripts/make-samples.sh   # a dual-stack network with an IPv6 C2 channel"

scenario 11-encrypted-dns-doh office --volume normal --attack doh-tunnel --seed 3
readme 11-encrypted-dns-doh "Encrypted-DNS C2 over DoH (T1071.004 / T1572)" \
"- \`zeek/ssl.log\`: TLS 1.3 sessions to a public DoH resolver's SNI (\`cloudflare-dns.com\`) on :443 — encrypted-DNS that bypasses plaintext-DNS monitoring. The detection is the resolver SNI/IP + cadence, not DNS content." \
"scripts/make-samples.sh   # a DoH tunnel in office noise"

# --------------------------------------------------------------------------- #
# 3. Capabilities & techniques — extraction, fingerprints, OT, vantage, evasion.
# --------------------------------------------------------------------------- #
mkdir -p samples/12-c2-beacon-ja3
"$PY" - <<'PY'
from packetforge.compile.timeline import write_pcap
from packetforge.environments import load_environment
from packetforge.malware_transfer import build_reference
write_pcap(build_reference("shadowbeacon", load_environment("office"), seed=0),
           "samples/12-c2-beacon-ja3/capture.pcap")
PY
zeek_of samples/12-c2-beacon-ja3
readme 12-c2-beacon-ja3 "C2 beacon JA3 reference (transfer-proof)" \
"- \`zeek/ssl.log\`: a recurring beacon SNI with a stable **JA3**. This is the reference \`packetforge malware-transfer\` profiles: rebuild an analog and a \`ja3.hash\` rule reaches the same verdict on both — realism that transfers." \
"scripts/make-samples.sh   # the JA3 transfer-proof reference"

scenario 13-ot-modbus-plant ot --volume normal --seed 2
readme 13-ot-modbus-plant "OT / ICS plant network — Modbus/TCP" \
"- \`zeek/modbus.log\`: read/write function codes across a flat OT segment of legacy hosts, seen from a cell TAP." \
"scripts/make-samples.sh   # an OT/ICS plant's ambient Modbus traffic"

mkdir -p samples/14-artifact-extraction
"$PY" -m packetforge compile flows/extraction.yaml -o samples/14-artifact-extraction/capture.pcap >/dev/null
zeek_of samples/14-artifact-extraction
readme 14-artifact-extraction "Forensic artifact extraction (HTTP / SMB / FTP / TLS)" \
"- \`zeek/files.log\` + \`x509.log\`: pull a real (inert) EXE, PDF, XLSX and an X.509 certificate out of one capture — valid containers with synthetic content, recognised by \`file(1)\` and Wireshark 'Export Objects'." \
"scripts/make-samples.sh   # one capture carrying extractable typed files"

# Multi-vantage: one incident, three sensor placements.
mkdir -p samples/15-multi-vantage
"$PY" -m packetforge scenario --env office --duration 200 --volume normal --attack psexec-lateral --seed 6 --vantages \
  -o samples/15-multi-vantage/capture.pcap >/dev/null
tidy_gt samples/15-multi-vantage
zeek_of samples/15-multi-vantage
readme 15-multi-vantage "Multi-vantage capture — one incident, three sensors" \
"- \`capture.pcap\` (core SPAN reference) plus \`capture.edge-tap.pcap\` (WAN TAP: every host **source-NAT'd** to one public IP, TTL -1 across the router hop), \`capture.core-span.pcap\` (802.1Q VLAN-tagged trunk), and \`capture.host-*.pcap\` (the victim's own tcpdump: its flows only, cooked SLL). Answers 'does my detection fire *given where my sensors are*.'" \
"scripts/make-samples.sh   # the same intrusion projected through edge/core/host sensors"

scenario 16-fragmented-ids-evasion office --volume normal --attack ransomware --seed 5 --fragment 400
readme 16-fragmented-ids-evasion "IP fragmentation — a reassembly / IDS-evasion test" \
"- The same ransomware SMB sweep, IP-fragmented to 400-byte fragments. Real Zeek **reassembles** to the identical flows (\`smb_files.log\` unchanged) — a per-packet signature engine, or one with a different overlap policy, can be evaded. A test that a rule survives reassembly." \
"scripts/make-samples.sh   # the ransomware sweep, IP-fragmented"

scenario 17-dcsync-replication office --volume normal --attack dcsync --seed 6
readme 17-dcsync-replication "DCSync — directory replication credential theft (T1003.006)" \
"- \`zeek/dce_rpc.log\`: an \`epmapper::ept_map\` lookup then the full drsuapi sequence (\`DRSBind\` -> \`DRSDomainControllerInfo\` -> \`DRSCrackNames\` -> \`DRSBind\` -> \`DRSGetNCChanges\` -> \`DRSUnbind\`) over ncacn_ip_tcp — matching a real Empire DCSync capture field-for-field. The tell BZAR-style analytics key on: \`drsuapi::DRSGetNCChanges\` sourced from a host that is **not** a domain controller. Inert: zero-filler stubs, never a replicated secret." \
"scripts/make-samples.sh   # replicate secrets from a DC over drsuapi"

# ExploitGym: a PCAP conjured from a news summary, woven into aws-vpc ambient — provenance demo.
mkdir -p samples/18-openai-hf-exploitgym
"$PY" -m packetforge scenario --env aws-vpc --start 1784168100 --duration 600 \
  --volume quiet --texture realistic --storyline flows/openai-hf-exploitgym.yaml \
  --seed 2026 -o samples/18-openai-hf-exploitgym/capture.pcap >/dev/null
cp flows/openai-hf-exploitgym.GROUND_TRUTH.md   samples/18-openai-hf-exploitgym/GROUND_TRUTH.md
cp flows/openai-hf-exploitgym.GROUND_TRUTH.json samples/18-openai-hf-exploitgym/GROUND_TRUTH.json
zeek_of samples/18-openai-hf-exploitgym
readme 18-openai-hf-exploitgym "\"ExploitGym\" — synthetic OpenAI/Hugging Face incident (2026-07-16)" \
"- **Information cutoff: 2026-07-23 — built from prose, and never revised.** On that date the entire public record of this incident was two short posts: Hugging Face's initial disclosure (2026-07-16) and OpenAI's (2026-07-21). Neither published **a single network indicator** — no IP, domain, port, hash, User-Agent, fingerprint or timestamp. Every indicator here was therefore **invented from prose**, realistic enough to pass an analyst's smell test, to show that a Zeek/tshark-clean PCAP is not by itself proof.
- **Four days later the answer key arrived.** Hugging Face published a full technical post-mortem on 2026-07-27. This capture is kept frozen as the **'before' half** of a comparison: [\`docs/exploitgym-postmortem-delta.md\`](../../docs/exploitgym-postmortem-delta.md) scores it against that ground truth, and [sample 19](../19-openai-hf-exploitgym-v2/) is the rebuild with the **opposite cutoff** — using only what became public *after* this one was frozen.
- **The attack (16 flows) is a needle in ~260 benign flows** — captured host-side (\`linux_sll\`) on patient-zero, woven into \`aws-vpc\` ambient (DNS/TLS/SSH/NTP + a realistic minority of failed/reset connections and the benign false-positive DNS a real sensor trips on). The compromised worker also carries its own benign baseline.
- \`zeek/http.log\`: an **internally-consistent IMDSv2** credential theft off **169.254.169.254** — PUT token → list role → GET credentials, with the PUT's token echoed in the GET headers and a real IMDS JSON body carrying AWS's inert **\`…EXAMPLE\`** keys.
- Two **honesty markers kept on purpose** so a bare pcap still reveals itself as synthetic: every external attacker IP sits in RFC 5737 documentation ranges (\`192.0.2/24\`, \`203.0.113/24\`), and the stolen AWS keys are AWS's published EXAMPLE values. Attack TLS is all 1.3 (certs encrypted). See [\`GROUND_TRUTH.md\`](GROUND_TRUTH.md) for the kill chain, ATT&CK mapping, and the honest list of residual tells.
- **Its errors are kept too**, including the date in this title: 2026-07-16 was Hugging Face's initial disclosure, the OpenAI post appeared 2026-07-21, and the intrusion itself ran 07-09 to 07-13. Scored in the delta, not silently fixed." \
"scripts/make-samples.sh   # a PCAP conjured from a news summary, woven into ambient"

# ExploitGym, take two: the same incident rebuilt from the 2026-07-27 technical post-mortem.
# Two captures, because one cannot carry both properties that matter — the hunt needs ambient
# noise around a short window, the timeline needs the whole 2.3-day arc.
mkdir -p samples/19-openai-hf-exploitgym-v2
# The hunting window is a strict time-slice of the campaign storyline, derived here so the two
# can never drift apart. 1783764720..1783765320 = 2026-07-11 10:12:00..10:22:00 UTC.
"$PY" - <<'PYWIN'
import yaml
d = yaml.safe_load(open("flows/openai-hf-exploitgym-v2.yaml"))
d["flows"] = [f for f in d["flows"] if 1783764720 <= f["start_time"] <= 1783765320]
yaml.safe_dump(d, open("samples/19-openai-hf-exploitgym-v2/.window.yaml", "w"), sort_keys=False)
PYWIN
# (a) the hunt — identical generator knobs to sample 18, so the two are directly comparable
"$PY" -m packetforge scenario --env aws-vpc --start 1783764720 --duration 600 \
  --volume quiet --texture realistic --storyline samples/19-openai-hf-exploitgym-v2/.window.yaml \
  --seed 2027 -o samples/19-openai-hf-exploitgym-v2/capture.pcap >/dev/null
# (b) the timeline — the whole campaign at its published times, no ambient at all
"$PY" -m packetforge compile flows/openai-hf-exploitgym-v2.yaml \
  -o samples/19-openai-hf-exploitgym-v2/capture.campaign.pcap >/dev/null
rm -f samples/19-openai-hf-exploitgym-v2/.window.yaml
cp flows/openai-hf-exploitgym-v2.GROUND_TRUTH.md   samples/19-openai-hf-exploitgym-v2/GROUND_TRUTH.md
cp flows/openai-hf-exploitgym-v2.GROUND_TRUTH.json samples/19-openai-hf-exploitgym-v2/GROUND_TRUTH.json
zeek_of samples/19-openai-hf-exploitgym-v2
zeek_into samples/19-openai-hf-exploitgym-v2/zeek-campaign ../capture.campaign.pcap
readme 19-openai-hf-exploitgym-v2 "The same incident, rebuilt from the technical post-mortem (2026-07-27)" \
"- **Information cutoff: 2026-07-29 — the mirror image of sample 18.** That capture was frozen on 2026-07-23 using only what was public by then: two disclosure posts with **no network indicators at all**. This one is built from precisely what became public *afterwards* — Hugging Face's technical timeline and interactive replay (2026-07-27), JFrog's advisory (2026-07-27), OpenAI's update block (2026-07-28) and Modal's note (2026-07-29). Same incident, same generator, same environment, same host vantage; **only the source material moved**, which is what makes the two comparable. [\`docs/exploitgym-postmortem-delta.md\`](../../docs/exploitgym-postmortem-delta.md) measures the difference.
- **Two captures.** \`capture.pcap\` is the **hunt**: 10 minutes of the Kubernetes and cloud-enumeration burst (07-11 10:12–10:22 UTC) woven into \`aws-vpc\` ambient, generated with **exactly the same knobs as sample 18** so only the storyline differs. \`capture.campaign.pcap\` (+ \`zeek-campaign/\`) is the **timeline**: all 104 attack flows across 07-11 08:07 → 07-13 14:14, with no ambient at all. Named events sit at their published times; the spacing between them is invented, because no event-level timing was ever published (the replay's counters interpolate between six checkpoints).
- **A quarter of the attack traffic is the agent failing** — \`S0\` (SYN, no reply) against the allow-listed production database, \`REJ\` as egress was cut, and 15 flows that establish cleanly and are then denied at the application layer. That last group is *invisible* under TLS 1.3 except by response size, and is rendered that way rather than given an invented signal. The post-mortem's central finding is that the successful path hid inside the noise of thousands of failed ones.
- **What changed from sample 18:** Kubernetes API on **443** (not 6443) with a **curl** JA3; **no SSH anywhere**; the internal database is **MongoDB/27017**, read-only; the Hub production database is **never reached** (\`mongodb+srv\` SRV/TXT lookups then \`conn_state=S0\`, twice); initial access is **ordinary Hub API traffic** carrying an inline payload, not a stage-2 pull from a third party; C2 results leave over a **raw-socket \`POST /<uuid>\` on cleartext :80 with no User-Agent**; plus the whole mesh-VPN pivot, the service-connector catalog read, PyPI from a prod pod, an \`8.8.8.8\` resolver rewrite, and TLS to a host that was never resolved." \
"scripts/make-samples.sh   # the post-mortem-informed rebuild: hunt + timeline"

# Gate: every generated capture must pass the zeek+tshark validation contract (DESIGN.md §7).
# This is what keeps the gallery green from silently rotting — a sample that trips a weird or a
# tshark malformation fails the build here, not months later.
echo "validating every capture against the zeek+tshark gate ..."
"$PY" - <<'PYGATE'
import glob, sys
from packetforge.validation.roundtrip import gate_pcap, validators_available
if not validators_available():
    print("  (skipped: zeek/tshark not on PATH)"); sys.exit(0)
caps = sorted(glob.glob("samples/*/capture*.pcap"))
bad = [(p, gate_pcap(p)) for p in caps]
bad = [(p, r) for p, r in bad if not r["ok"]]
if bad:
    print("GATE FAILED:")
    for p, r in bad:
        print(f"  {p}: weird={r['zeek_weird']} reporter={r['zeek_reporter']} "
              f"tshark_err={r['tshark_errors']} tshark_warn={r['tshark_warnings']}")
    sys.exit(1)
print(f"  gate: all {len(caps)} captures pass (0 weird/reporter/errors/non-benign-warns)")
PYGATE

echo "samples regenerated:"
for d in samples/[0-9]*/; do
  printf "  %-28s %8sB pcap\n" "$(basename "$d")" "$(wc -c < "$d/capture.pcap")"
done
