#!/usr/bin/env bash
# Regenerate the sample gallery under samples/ (deterministic). Needs zeek + tshark.
#
# Each sample folder holds a generated capture.pcap, the real Zeek logs it produces (zeek/) and
# a short README. Executed attacks also get a GROUND_TRUTH answer key. Reconstructions of real
# incidents get a RECONSTRUCTION narrative plus a generated CLAIMS warranting layer instead.
# The gallery is a tour of what PacketForge can render: classic AD/OT attacks, the
# lateral-movement and AiTM packs, cloud (AWS/Azure + Kubernetes), IPv6, encrypted-DNS,
# multi-vantage capture, VXLAN mirroring, and IDS-evasion fragmentation.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
PY="${PYTHON:-.venv/bin/python}"

rm -rf samples/[0-9]*        # renumbered gallery: clear the old set first

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
  # Emulation-mode samples have ground truth, because something was executed against a plan.
  # Reconstruction-mode samples do not: the referent is someone else's incident, so they ship a
  # warranted claim set instead. The file names say which is which.
  [ -f "samples/$dir/GROUND_TRUTH.md" ] && gt=$'\n- **Answer key.** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) labels every attack flow with its ATT&CK technique.'
  [ -f "samples/$dir/RECONSTRUCTION.md" ] && gt="$gt"$'\n- **Narrative.** [`RECONSTRUCTION.md`](RECONSTRUCTION.md) gives the vantage, the kill chain and the residual synthetic tells.'
  [ -f "samples/$dir/CLAIMS.md" ] && gt="$gt"$'\n- **Warranting.** [`CLAIMS.md`](CLAIMS.md), from `packetforge warrant`, records which source claim licenses each flow and what is left unmodelled.'
  cat > "samples/$dir/README.md" <<EOF
# $title

The traffic here is synthetic and inert: fake packets with true labels, and no real host,
credential, malware sample or document. Generation is deterministic, so the same inputs rebuild
these bytes exactly. The captures open in Wireshark with no errors, and \`zeek/\` holds the logs
real Zeek 8.2 derives from them. The [gallery](../README.md) indexes all nineteen samples.

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
# 1. Attack storylines: the classic ATT&CK-mapped kill chains.                #
# --------------------------------------------------------------------------- #
scenario 01-kerberoasting-in-ad office --volume normal --texture realistic --attack kerberoasting --seed 11
readme 01-kerberoasting-in-ad "Kerberoasting in Active Directory (T1558.003)" \
"- **\`zeek/kerberos.log\`.** The account \`svc-analyst\` takes a normal AES ticket-granting ticket,
  then makes eight TGS requests in a row that each force \`cipher=rc4-hmac\`.
- **Why the downgrade.** A service ticket encrypted under RC4 can be cracked offline against the
  service account's password. AES tickets cost far more to attack, so the client asks for RC4.
- **The tell is the burst.** Eight distinct SPNs (service principal names, the Kerberos identity of
  a service) are roasted by one account in 10.5 seconds. The other 18 rows in the log are ambient
  AES ticket requests from ordinary users.
- **Nothing here is blockable.** The cipher choice and the burst shape are the signal. Every host
  and realm name in this capture is fictional." \
"scripts/make-samples.sh   # office AD noise + a Kerberoasting burst"

scenario 02-phishing-kill-chain office --volume normal --texture realistic --attack phishing-intrusion --seed 7
readme 02-phishing-kill-chain "Phishing to exfiltration: a full kill chain (T1566 to T1048)" \
"- **Five stages, one victim.** 10.10.0.40 runs the whole chain inside ordinary office traffic. The
  answer key names each attack flow with an \`atk-\` prefix; everything unnamed is ambient.
- **\`zeek/smtp.log\`.** One mail from \`hr-updates@evil.example\` to \`victim@corp.local\` is the
  initial access (T1566.001).
- **\`zeek/ssl.log\`.** Six HTTPS beacons reach \`cdn.telemetry-sync.example\` at 203.0.113.66 on a
  60-second cadence, with a curl JA3 rather than a browser's (T1071.001).
- **\`zeek/ldap_search.log\`.** The victim then runs base searches against \`DC=corp,DC=local\` on
  the domain controller 10.10.0.10 (T1087).
- **\`zeek/smb_mapping.log\`.** It maps a named pipe on the file server 10.10.0.42, then a disk
  share on the peer 10.10.0.41 (T1135, T1021.002).
- **\`zeek/http.log\`.** A single 45,000-byte POST to \`upload.evil.example/dropbox\` at
  198.51.100.44 closes the chain (T1048)." \
"scripts/make-samples.sh   # the reference intrusion woven into office noise"

scenario 03-ransomware-smb-theft office --volume normal --attack ransomware --seed 5
readme 03-ransomware-smb-theft "Ransomware mass SMB document theft (T1486)" \
"- **\`zeek/smb_files.log\`.** 80 documents are read off the file server 10.10.0.41 in one rapid
  sweep, one row per file (T1486).
- **Carve them out.** Wireshark's File > Export Objects > SMB lists all 80. The containers are real
  file formats and the bytes inside them are inert filler.
- **\`zeek/ssl.log\`.** One HTTPS check-in to \`update.evil.example\` at 203.0.113.66 precedes the
  sweep (T1071.001).
- **Sample 16 is this capture fragmented.** Compare the two to test whether a rule survives IP
  reassembly." \
"scripts/make-samples.sh   # office noise + a mass-SMB encryption sweep"

scenario 04-dns-tunnel-exfil office --volume normal --attack dns-exfil --seed 3
readme 04-dns-tunnel-exfil "DNS tunnelling exfiltration (T1048.003)" \
"- **\`zeek/dns.log\`.** 60 A queries carry a 39-character base32 label under one parent,
  \`exfil.evil.example\`, and every one of them returns NXDOMAIN (T1048.003).
- **The burst takes 118 seconds.** The other 65 rows in the log are ordinary office lookups, so
  sorting the log by query length separates them in one pass.
- **What to measure.** Query length, query rate under a single parent, and label entropy. The
  parent domain is fictional, so a rule that matches the name proves nothing." \
"scripts/make-samples.sh   # a DNS-tunnel burst in office noise"

scenario 05-bzar-lateral-movement office --volume normal --attack psexec-lateral --seed 6
readme 05-bzar-lateral-movement "PsExec-style lateral movement: the BZAR pack (T1021.002 / T1569.002)" \
"- **\`zeek/smb_files.log\`.** 10.10.0.40 writes a 6,144-byte \`svc.exe\` to the ADMIN\$ share on
  10.10.0.41. That is the tool drop, and it happens first.
- **\`zeek/dce_rpc.log\`.** An \`epmapper::ept_map\` endpoint lookup on port 135 follows, then ten
  svcctl operations on port 445 over a named pipe.
- **The sequence.** \`OpenSCManagerW\`, \`CreateServiceW\`, \`QueryServiceStatus\`,
  \`OpenServiceW\`, \`StartServiceW\`, \`QueryServiceStatus\`, then three \`CloseServiceHandle\`
  calls. It matches the operation order in a real PsExec capture.
- **Why BZAR fires.** The admin-share write and the remote service install together are what raises
  \`ATTACK::Lateral_Movement_and_Execution\`. Either one alone is common in an AD network.
- **Inert.** The RPC argument stubs are zero filler. No service binary and no command line is
  carried anywhere in the capture." \
"scripts/make-samples.sh   # remote service creation + admin-share tool drop"

scenario 06-llmnr-poisoning office --volume normal --attack llmnr-poisoning --seed 4
readme 06-llmnr-poisoning "LLMNR/NBT-NS poisoning into NTLM capture (Responder-style, T1557.001)" \
"- **\`zeek/dns.log\`.** LLMNR is the multicast name lookup Windows falls back to when DNS fails,
  and Zeek records it in this log. Three names, \`wpad\` among them, are answered by 10.10.0.41
  with its own address.
- **The tell.** A workstation address returned as an LLMNR answer by a host that is not a DNS
  server, followed by SMB from the victim to that same host (T1557.001).
- **\`zeek/ntlm.log\`.** The victim authenticates to the rogue host as
  \`username=jsmith domainname=CORP hostname=WKS-042\`, against a server calling itself
  \`WPAD-SRV\`.
- **Inert.** The NTLMSSP framing and the identity fields are real, so the log populates correctly.
  The LM and NT response bytes are fixed filler, so nothing here can be cracked offline." \
"scripts/make-samples.sh   # a broadcast-name poisoning + SMB auth capture"

# --------------------------------------------------------------------------- #
# 2. Cloud and modern: AWS/Azure, Kubernetes, IPv6, encrypted DNS.            #
# --------------------------------------------------------------------------- #
scenario 07-aws-imds-ssrf aws-vpc --volume normal --attack imds-ssrf --seed 6
readme 07-aws-imds-ssrf "AWS IMDS credential theft via SSRF (T1552.005, the Capital One shape)" \
"- **\`zeek/http.log\`.** Two GETs reach 169.254.169.254 from the instance 172.31.0.40:
  \`/latest/meta-data/\`, then \`/latest/meta-data/iam/security-credentials/ec2-app-role\`. The
  second returns the instance role's temporary credentials (T1552.005).
- **SSRF.** Server-side request forgery makes an application fetch a URL the attacker supplies.
  Pointed at the link-local metadata address, it becomes credential theft.
- **Vantage.** The capture is host-side on the instance in Linux SLL. A VPC has no switch to span,
  so this is where a cloud sensor usually sits.
- **The address is real infrastructure.** 169.254.169.254 is AWS's metadata service. The request
  path is the finding, not the destination." \
"scripts/make-samples.sh   # aws-vpc: an instance pulling its IAM credentials off IMDS"

scenario 08-azure-cloud-exfil azure-vnet --volume normal --attack cloud-exfil --seed 6
readme 08-azure-cloud-exfil "Exfiltration to Azure Blob storage (T1567.002)" \
"- **\`zeek/ssl.log\`.** Six of the 118 TLS sessions reach \`exfilstg.blob.core.windows.net\` at
  203.0.113.90. The other 112 go to ordinary sites (T1567.002).
- **\`zeek/conn.log\`.** Those six carry between 230 KB and 436 KB of \`orig_bytes\` each, and under
  600 bytes back. Ordinary browsing has that ratio the other way round.
- **Why it is hard to catch.** The destination is a trusted cloud endpoint on port 443 and the
  content is encrypted. Direction and volume are the signal, not reputation." \
"scripts/make-samples.sh   # azure-vnet: ~440 KB uploads to Blob storage"

# Kubernetes: the inner pod traffic, plus the same incident as a VXLAN traffic mirror sees it.
mkdir -p samples/09-k8s-cluster-lateral
"$PY" -m packetforge scenario --env k8s --duration 200 --volume normal --attack k8s-lateral --seed 6 --mirror \
  -o samples/09-k8s-cluster-lateral/capture.pcap >/dev/null
tidy_gt samples/09-k8s-cluster-lateral
zeek_of samples/09-k8s-cluster-lateral
# ship the mirror's decapsulated logs too, so the VXLAN-decap claim is proven in-artifact
zeek_into samples/09-k8s-cluster-lateral/zeek-mirror ../capture.mirror.pcap
readme 09-k8s-cluster-lateral "Kubernetes cluster lateral movement and a VXLAN traffic mirror (T1613 / T1021)" \
"- **The attack.** A compromised pod at 10.244.1.13 resolves cluster services through CoreDNS at
  10.96.0.10, reaches the API server at 10.96.0.1 on port 443, then fans out mutual TLS to four
  pods on 8443 across the service mesh (T1613, T1021).
- **\`capture.pcap\` and \`zeek/\`.** The direct view from the pod network, 247 connections.
- **\`capture.mirror.pcap\`.** The same packets as an AWS VPC Traffic Mirror or a GCP Packet Mirror
  delivers them, wrapped in VXLAN and sent to a collector endpoint.
- **\`zeek-mirror/\`.** What Zeek makes of that mirror. \`tunnel.log\` holds 1,622
  \`Tunnel::VXLAN\` entries, and \`conn.log\` holds the identical 247 inner connections alongside
  1,202 outer ones. Decapsulation recovers the incident intact." \
"scripts/make-samples.sh   # k8s pod-to-pod lateral, direct + VXLAN-mirrored"

scenario 10-ipv6-c2-beacon office --volume normal --attack ipv6-c2 --seed 5
readme 10-ipv6-c2-beacon "HTTPS C2 beaconing over IPv6 (T1071.001)" \
"- **\`zeek/dns.log\`.** One AAAA lookup for \`cdn.telemetry-sync.example\` returns the IPv6 address
  2001:db8:c2::66.
- **\`zeek/ssl.log\`.** Six TLS sessions to that address follow, spaced 55 to 65 seconds apart
  (T1071.001). Their client hello hashes to JA3 \`9ecbe6ca0f874f5886035b8b7f1ac001\`, which is curl
  rather than a browser.
- **The point.** The behaviour is ordinary HTTPS beaconing. A sensor whose rules are written around
  IPv4 addresses records none of it and reports nothing wrong." \
"scripts/make-samples.sh   # a dual-stack network with an IPv6 C2 channel"

scenario 11-encrypted-dns-doh office --volume normal --attack doh-tunnel --seed 3
readme 11-encrypted-dns-doh "Encrypted-DNS C2 over DoH (T1071.004 / T1572)" \
"- **\`zeek/ssl.log\`.** 40 TLS 1.3 sessions reach \`cloudflare-dns.com\` at 1.1.1.1 on port 443,
  about one every three seconds (T1071.004, T1572).
- **What is missing.** No row in \`zeek/dns.log\` corresponds to any tunnelled query. The names went
  inside the TLS session, so a plaintext-DNS monitor sees nothing at all.
- **What to key on.** The resolver identity and the session cadence. 1.1.1.1 is a legitimate public
  resolver, so the finding is that this workstation is using it, not that it exists." \
"scripts/make-samples.sh   # a DoH tunnel in office noise"

# --------------------------------------------------------------------------- #
# 3. Capabilities and techniques: extraction, fingerprints, OT, vantage, evasion.
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
"- **\`zeek/ssl.log\`.** Twelve of the 31 TLS sessions reach one beacon SNI,
  \`static.cdn-telemetry.example\`, across ten minutes.
- **Computing the JA3.** Zeek 8.2 does not log JA3, so take it from the client hello:
  \`tshark -r capture.pcap -T fields -e tls.handshake.ja3\` returns
  \`98f4309baa6caf6ad70662b4ebcba90d\` on all twelve.
- **Why this file exists.** It is the reference that \`packetforge malware-transfer\` profiles.
  Rebuild an analog beacon and the \`ja3.hash\` rule in
  [\`detection/malware-ja3.rules\`](../../detection/malware-ja3.rules) reaches the same verdict on
  both captures." \
"scripts/make-samples.sh   # the JA3 transfer-proof reference"

scenario 13-ot-modbus-plant ot --volume normal --seed 2
readme 13-ot-modbus-plant "OT and ICS plant network: Modbus/TCP" \
"- **\`zeek/modbus.log\`.** 94 request and response pairs, every one function code 3
  (\`READ_HOLDING_REGISTERS\`), which is the poll a control system runs against a PLC's registers.
- **The topology.** Twelve hosts between 192.168.0.20 and 192.168.0.31 poll each other in both
  directions on port 502. The segment is flat, which is what an ICS cell TAP normally shows.
- **\`zeek/conn.log\`.** 35 connections on port 102 and 33 on port 20000 carry no \`service\` value.
  Those are S7comm and DNP3 rendered as opaque TCP shells, because PacketForge does not invent
  protocol bodies it has no renderer for." \
"scripts/make-samples.sh   # an OT/ICS plant's ambient Modbus traffic"

mkdir -p samples/14-artifact-extraction
"$PY" -m packetforge compile flows/extraction.yaml -o samples/14-artifact-extraction/capture.pcap >/dev/null
zeek_of samples/14-artifact-extraction
readme 14-artifact-extraction "Forensic artifact extraction (HTTP / SMB / FTP / TLS)" \
"- **\`zeek/files.log\`.** Four files cross the wire: a 24,576-byte Windows executable and a
  16,384-byte PDF over HTTP, \`salaries.xlsx\` at 20,480 bytes off the Finance share on FILESRV
  over SMB, and \`database.zip\` pulled over FTP.
- **\`zeek/pe.log\`.** Zeek parses the executable as a real i386 PE, so the container is a genuine
  Windows binary format rather than a renamed blob.
- **\`zeek/x509.log\`.** Two certificates are recorded: \`CN=portal.corp.example\` and the
  \`PacketForge Synthetic CA\` that issued it.
- **Get them out.** Wireshark's File > Export Objects recovers all four, and \`file(1)\` identifies
  each one correctly.
- **Inert.** The containers are valid formats and the bytes inside them are synthetic filler.
  Nothing here executes or opens onto real data." \
"scripts/make-samples.sh   # one capture carrying extractable typed files"

# Multi-vantage: one incident, three sensor placements.
mkdir -p samples/15-multi-vantage
"$PY" -m packetforge scenario --env office --duration 200 --volume normal --attack psexec-lateral --seed 6 --vantages \
  -o samples/15-multi-vantage/capture.pcap >/dev/null
tidy_gt samples/15-multi-vantage
zeek_of samples/15-multi-vantage
readme 15-multi-vantage "Multi-vantage capture: one incident, four sensors" \
"- **\`capture.pcap\`.** The core SPAN reference: 2,711 packets of the sample 05 PsExec intrusion on
  plain Ethernet.
- **\`capture.edge-tap.pcap\`.** The same 2,711 packets at the WAN TAP. Every internal host is
  source-NAT'd onto 203.0.113.10 and TTL drops by one across the router hop, so per-host
  attribution is gone.
- **\`capture.core-span.pcap\`.** The same 2,711 packets with an 802.1Q VLAN tag (id 10) on every
  frame. A rule that matches at a fixed byte offset breaks here.
- **\`capture.host-10.10.0.40.pcap\`.** The victim's own tcpdump: 154 packets in Linux SLL, its
  flows to 10.10.0.41 and nothing else on the network.
- **The question this answers.** Whether a detection fires given where the sensors actually sit.
  One rule can pass on one of these files and fail on another." \
"scripts/make-samples.sh   # the same intrusion projected through edge/core/host sensors"

scenario 16-fragmented-ids-evasion office --volume normal --attack ransomware --seed 5 --fragment 400
readme 16-fragmented-ids-evasion "IP fragmentation: a reassembly and IDS-evasion test" \
"- **What changed.** This is the sample 03 ransomware SMB sweep with every IP datagram split into
  400-byte fragments. The packet count rises from 10,200 to 27,766, and 23,493 of those packets are
  fragments.
- **\`zeek/smb_files.log\`.** Zeek reassembles and produces the same 80 file rows as sample 03,
  field for field. The flows are unchanged.
- **What this tests.** An engine that matches per packet, or one with a different fragment-overlap
  policy, can miss what Zeek still sees. Run your rules over both files and compare the verdicts." \
"scripts/make-samples.sh   # the ransomware sweep, IP-fragmented"

scenario 17-dcsync-replication office --volume normal --attack dcsync --seed 6
readme 17-dcsync-replication "DCSync: directory replication credential theft (T1003.006)" \
"- **\`zeek/dce_rpc.log\`.** An \`epmapper::ept_map\` lookup on port 135 is followed by six drsuapi
  calls on port 49200 over ncacn_ip_tcp, the plain TCP transport for DCE/RPC.
- **The sequence.** \`DRSBind\`, \`DRSDomainControllerInfo\`, \`DRSCrackNames\`, \`DRSBind\`,
  \`DRSGetNCChanges\`, then \`DRSUnbind\`. It matches a real Empire DCSync capture field for field.
- **The tell.** \`drsuapi::DRSGetNCChanges\` is how domain controllers replicate secrets to each
  other. Here it comes from 10.10.0.40, a workstation, against the DC at 10.10.0.41 (T1003.006).
  That source is what BZAR-style analytics key on.
- **Inert.** The RPC stubs are zero filler. No replicated secret is present in the capture." \
"scripts/make-samples.sh   # replicate secrets from a DC over drsuapi"

# ExploitGym: a PCAP conjured from a news summary, woven into aws-vpc ambient (provenance demo).
mkdir -p samples/18-openai-hf-exploitgym
"$PY" -m packetforge scenario --env aws-vpc --start 1784168100 --duration 600 \
  --volume quiet --texture realistic --storyline flows/openai-hf-exploitgym.yaml \
  --seed 2026 -o samples/18-openai-hf-exploitgym/capture.pcap >/dev/null
cp flows/openai-hf-exploitgym.RECONSTRUCTION.md   samples/18-openai-hf-exploitgym/RECONSTRUCTION.md
cp flows/openai-hf-exploitgym.RECONSTRUCTION.json samples/18-openai-hf-exploitgym/RECONSTRUCTION.json
# Gate 4 (correspondence). Sample 18 is EXPECTED TO FAIL. It is kept frozen as the "before"
# half of the comparison, and the whole point is that the gate catches what it got wrong.
# `|| true` because a failing warrant is this sample's documented state, not a build break.
"$PY" -m packetforge warrant --quiet \
  --claims flows/openai-hf-exploitgym.claims.yaml --flows flows/openai-hf-exploitgym.yaml \
  --score-key flows/openai-hf-exploitgym.answerkey.yaml \
  --manifest-md samples/18-openai-hf-exploitgym/CLAIMS.md \
  --manifest-json samples/18-openai-hf-exploitgym/CLAIMS.json \
  --pcapng samples/18-openai-hf-exploitgym/storyline.provenance.pcapng || true
zeek_of samples/18-openai-hf-exploitgym
readme 18-openai-hf-exploitgym "\"ExploitGym\": a synthetic OpenAI/Hugging Face incident (2026-07-16)" \
"- **Information cutoff: 2026-07-23.** This capture was built from prose and never revised. On that
  date the entire public record of the incident was two short posts: Hugging Face's disclosure of
  2026-07-16 and OpenAI's of 2026-07-21.
- **Neither post carried a network indicator.** No IP, domain, port, hash, User-Agent, fingerprint
  or timestamp appeared in either one. Every indicator in this capture was invented to fill that
  gap, and made plausible enough to pass an analyst's first look.
- **That is the demonstration.** The file is clean under Zeek and tshark and reads as realistic.
  Passing those checks is not evidence that the incident looked like this.
- **The answer key arrived four days later.** Hugging Face published a technical post-mortem on
  2026-07-27. This capture stays frozen as the before half of a comparison, scored in
  [\`docs/exploitgym-postmortem-delta.md\`](../../docs/exploitgym-postmortem-delta.md).
- **[Sample 19](../19-openai-hf-exploitgym-v2/) is the after half.** It rebuilds the same incident
  from only what became public once this one was frozen.
- **16 attack flows sit among 276 connections.** The vantage is host-side on patient zero in
  \`linux_sll\`, woven into \`aws-vpc\` ambient DNS, TLS, SSH and NTP. That ambient carries failed
  and reset connections, and the benign lookups that trip a real sensor.
- **\`zeek/http.log\`.** IMDSv2 credential theft off 169.254.169.254 runs a PUT to
  \`/latest/api/token\`, a GET listing roles, then a GET for \`hf-dsviewer-role\`. The PUT's token
  is echoed in both GET headers, so the exchange is internally consistent.
- **The stolen keys are AWS's published EXAMPLE values.** The response body is real IMDS JSON
  carrying them, so no reader can mistake the credentials for live ones.
- **Every external attacker address is documentation space.** RFC 5737 reserves \`192.0.2.0/24\` and
  \`203.0.113.0/24\` for that purpose, so a bare pcap still identifies itself as synthetic. Attack
  TLS is all 1.3, which encrypts the certificates.
- **It fails Gate 4 on purpose.** \`packetforge warrant\` checks every rendered flow against the
  claim set built from those two posts, and [\`CLAIMS.md\`](CLAIMS.md) records what it found.
- **What it fails on.** Flows rendered with no source licensing them (the stage-2 pull, the SSH hop,
  the exfil lookup), source claims neither rendered nor declared unmodelled, violated magnitude
  floors, and one flow asserting something a source left open.
- **The failure count lives in [\`CLAIMS.md\`](CLAIMS.md), not here.** A number copied into prose
  drifts from the artifact, which is the CIC-IDS2017 failure this layer exists to avoid.
- **Each failure matches an error the post-mortem later confirmed.** The gate found them from the
  sources this capture already had, before the post-mortem existed.
- **The errors are kept, including the date in the title.** 2026-07-16 was Hugging Face's initial
  disclosure, OpenAI posted on 2026-07-21, and the intrusion itself ran 07-09 to 07-13. The delta
  scores them rather than fixing them." \
"scripts/make-samples.sh   # a PCAP conjured from a news summary, woven into ambient"

# ExploitGym, take two: the same incident rebuilt from the 2026-07-27 technical post-mortem.
# Two captures, because one cannot carry both properties that matter. The hunt needs ambient
# noise around a short window; the timeline needs the whole 2.3-day arc.
mkdir -p samples/19-openai-hf-exploitgym-v2
# The hunting window is a strict time-slice of the campaign storyline, derived here so the two
# can never drift apart. 1783764720..1783765320 = 2026-07-11 10:12:00..10:22:00 UTC.
"$PY" - <<'PYWIN'
import yaml
d = yaml.safe_load(open("flows/openai-hf-exploitgym-v2.yaml"))
d["flows"] = [f for f in d["flows"] if 1783764720 <= f["start_time"] <= 1783765320]
yaml.safe_dump(d, open("samples/19-openai-hf-exploitgym-v2/.window.yaml", "w"), sort_keys=False)
PYWIN
# (a) the hunt: identical generator knobs to sample 18, so the two are directly comparable
"$PY" -m packetforge scenario --env aws-vpc --start 1783764720 --duration 600 \
  --volume quiet --texture realistic --storyline samples/19-openai-hf-exploitgym-v2/.window.yaml \
  --seed 2027 -o samples/19-openai-hf-exploitgym-v2/capture.pcap >/dev/null
# (b) the timeline: the whole campaign at its published times, no ambient at all
"$PY" -m packetforge compile flows/openai-hf-exploitgym-v2.yaml \
  -o samples/19-openai-hf-exploitgym-v2/capture.campaign.pcap >/dev/null
rm -f samples/19-openai-hf-exploitgym-v2/.window.yaml
cp flows/openai-hf-exploitgym-v2.RECONSTRUCTION.md   samples/19-openai-hf-exploitgym-v2/RECONSTRUCTION.md
cp flows/openai-hf-exploitgym-v2.RECONSTRUCTION.json samples/19-openai-hf-exploitgym-v2/RECONSTRUCTION.json
# Gate 4 (correspondence): this one MUST pass. A failure breaks the build.
"$PY" -m packetforge warrant --quiet \
  --claims flows/openai-hf-exploitgym-v2.claims.yaml --flows flows/openai-hf-exploitgym-v2.yaml \
  --manifest-md samples/19-openai-hf-exploitgym-v2/CLAIMS.md \
  --manifest-json samples/19-openai-hf-exploitgym-v2/CLAIMS.json \
  --pcapng samples/19-openai-hf-exploitgym-v2/storyline.provenance.pcapng
zeek_of samples/19-openai-hf-exploitgym-v2
zeek_into samples/19-openai-hf-exploitgym-v2/zeek-campaign ../capture.campaign.pcap
readme 19-openai-hf-exploitgym-v2 "The same incident, rebuilt from the technical post-mortem (2026-07-27)" \
"- **Information cutoff: 2026-07-29.** This is the mirror image of sample 18, which was frozen on
  2026-07-23 from two disclosure posts that carried no network indicators at all. This capture uses
  only what became public afterwards.
- **The sources.** Hugging Face's technical timeline and interactive replay (2026-07-27), JFrog's
  advisory (2026-07-27), OpenAI's update block (2026-07-28) and Modal's note (2026-07-29).
- **Only the source material moved.** Same incident, same generator, same environment, same host
  vantage, which is what makes the two comparable.
  [\`docs/exploitgym-postmortem-delta.md\`](../../docs/exploitgym-postmortem-delta.md) measures the
  difference.
- **\`capture.pcap\` is the hunt.** Ten minutes of the Kubernetes and cloud-enumeration burst
  (07-11 10:12 to 10:22 UTC) woven into \`aws-vpc\` ambient, 284 connections in all. The generator
  knobs are identical to sample 18, so only the storyline differs.
- **\`capture.campaign.pcap\` is the timeline.** All 104 attack flows from 07-11 08:07 to 07-13
  14:14, with no ambient traffic at all. Its Zeek logs are in \`zeek-campaign/\`.
- **The spacing is authored.** Named events sit at their published times. The intervals between them
  are invented, because no event-level timing was ever published; the replay's counters only
  interpolate between six checkpoints.
- **A quarter of the attack traffic is the agent failing.** \`zeek-campaign/conn.log\` holds 8 \`S0\`
  connections (SYN with no reply), four of them against the allow-listed production database, plus
  2 \`REJ\` after egress was cut and 1 \`RSTR\`. Fifteen further flows establish cleanly and are
  then refused at the application layer.
- **Those refusals are close to invisible.** Under TLS 1.3 a denied API call and a successful one
  differ only in response size, and they are rendered that way rather than given an invented
  signal. The post-mortem's central finding is that the successful path hid inside thousands of
  failed ones.
- **What changed from sample 18.** The Kubernetes API is on 443 rather than 6443, reached with a
  curl JA3 under SNI \`kubernetes.default.svc\`. There is no SSH anywhere in the capture.
- **The databases.** The internal store is MongoDB on 27017, read only. The Hub production database
  is never reached: two \`mongodb+srv\` SRV lookups and a TXT lookup are followed by
  \`conn_state=S0\` on 27017.
- **Entry and exit.** Initial access is ordinary Hub API traffic carrying an inline payload, not a
  stage-2 pull from a third party. C2 results leave over a raw-socket \`POST /<uuid>\` on cleartext
  port 80 with no User-Agent.
- **Also new.** A mesh-VPN pivot, a service-connector catalog read, PyPI from a production pod, a
  resolver rewrite to \`8.8.8.8\`, and TLS to a host that was never resolved.
- **It passes Gate 4.** [\`CLAIMS.md\`](CLAIMS.md) records the verdict. A pass means the accounting
  is coherent, not that the capture is correct." \
"scripts/make-samples.sh   # the post-mortem-informed rebuild: hunt + timeline"

# Gate: every generated capture must pass the zeek+tshark validation contract (DESIGN.md §7).
# This is what keeps the gallery from silently rotting. A sample that trips a weird or a tshark
# malformation fails the build here, not months later.
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
