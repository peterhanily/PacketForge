# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""ATT&CK-mapped attack library + ground truth (the Ixia "Strike List" analog).

Each attack builder returns a set of flows plus a ground-truth record (which flows are
malicious, their ATT&CK techniques, the IOCs). The composer weaves it into ambient
noise, yielding a training-ready capture: a hunter must separate the storyline from the
background, and the ground truth is the answer key. Builders take an ``intensity`` knob
so the same attack can be quiet-and-slow or loud-and-fast.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from packetforge.environments import Environment
from packetforge.models.flowspec import (
    DceRpcL7, DnsL7, Flow, HttpL7, KerberosL7, LdapL7, NameQueryL7, OpaqueTcpL7, SmbL7,
    SmtpL7, SshL7, TlsL7,
)


@dataclass
class GroundTruthEntry:
    stage: str              # ATT&CK tactic
    technique: str          # "T1071.001 Web Protocols"
    flow_ids: list
    description: str
    iocs: dict = field(default_factory=dict)


@dataclass
class Intrusion:
    flows: list
    ground_truth: list      # list[GroundTruthEntry]
    title: str
    iocs: dict = field(default_factory=dict)
    evasions: list = field(default_factory=list)  # names of applied evasion modifiers


def _hosts(env: Environment, count: int, offset: int = 40) -> list:
    net = ipaddress.ip_network(env.subnet, strict=False)
    base = int(net.network_address)
    return [str(ipaddress.ip_address(base + offset + i)) for i in range(count)]


def build_intrusion(env: Environment, start_time: float, rng, *,
                    intensity: float = 1.0,
                    ad_domain: str = "corp.local",
                    c2_domain: str = "cdn.telemetry-sync.example",
                    c2_ip: str = "203.0.113.66",
                    exfil_ip: str = "198.51.100.44") -> Intrusion:
    """A phishing -> C2 -> discovery -> lateral -> exfil intrusion, ATT&CK-mapped."""
    victim, peer, fileserver = _hosts(env, 3)
    dc = env.dns_server
    mail = env.gateway
    dc_dn = ",".join(f"DC={p}" for p in ad_domain.split("."))  # corp.local -> DC=corp,DC=local
    flows, gt = [], []
    sp = iter(range(40000, 65000))

    def sport() -> int:
        return next(sp)

    # 1) Initial Access — inbound phishing email (T1566.001)
    t = start_time
    flows.append(Flow(flow_id="atk-01-phish", transport="tcp", src_ip=exfil_ip, dst_ip=mail,
                      src_port=sport(), dst_port=25, start_time=t, conn_state="SF",
                      l7=SmtpL7(mail_from="hr-updates@evil.example", rcpt_to=[f"victim@{ad_domain}"],
                                subject="Action required: password expiry", body_len=600)))
    gt.append(GroundTruthEntry("Initial Access", "T1566.001 Spearphishing Attachment",
                               ["atk-01-phish"], "Phishing email delivered to the victim's mailbox.",
                               {"sender": "hr-updates@evil.example"}))

    # 2) Command & Control — DNS resolve then HTTPS beacons at a fixed cadence (T1071)
    t += 45
    flows.append(Flow(flow_id="atk-02-c2dns", transport="udp", src_ip=victim, dst_ip=dc,
                      src_port=sport(), dst_port=53, start_time=t,
                      src_os=env.default_client_os, l7=DnsL7(qname=c2_domain + ".", answers=[c2_ip])))
    beacon_ids = []
    for i in range(max(3, int(6 * intensity))):  # regular cadence + jitter — the classic C2 tell
        bt = t + 30 + i * 60 + rng.uniform(-4, 4)
        fid = f"atk-02-beacon-{i:02d}"
        beacon_ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=victim, dst_ip=c2_ip,
                          src_port=sport(), dst_port=443, start_time=bt, conn_state="SF",
                          src_os=env.default_client_os,
                          l7=TlsL7(server_name=c2_domain, client_profile="curl",
                                   app_data_orig_bytes=rng.randint(120, 200),
                                   app_data_resp_bytes=rng.randint(300, 900))))
    gt.append(GroundTruthEntry("Command and Control", "T1071.001/.004 Web + DNS C2",
                               ["atk-02-c2dns"] + beacon_ids,
                               f"Beaconing to {c2_domain} every ~60s over HTTPS (non-browser JA3).",
                               {"c2_domain": c2_domain, "c2_ip": c2_ip, "cadence_s": 60,
                                "ja3_profile": "curl"}))

    # 3) Discovery — LDAP account enumeration + SMB share listing (T1087 / T1135)
    t += 420
    flows.append(Flow(flow_id="atk-03-ldap", transport="tcp", src_ip=victim, dst_ip=dc,
                      src_port=sport(), dst_port=389, start_time=t, conn_state="SF",
                      src_os=env.default_client_os,
                      l7=LdapL7(bind_dn=f"CN=victim,{dc_dn}",
                                searches=[dc_dn, f"CN=Users,{dc_dn}"])))
    flows.append(Flow(flow_id="atk-03-smbenum", transport="tcp", src_ip=victim, dst_ip=fileserver,
                      src_port=sport(), dst_port=445, start_time=t + 8, conn_state="SF",
                      src_os=env.default_client_os, l7=SmbL7(share="\\\\FILESRV\\IPC$")))
    gt.append(GroundTruthEntry("Discovery", "T1087 Account / T1135 Network Share Discovery",
                               ["atk-03-ldap", "atk-03-smbenum"],
                               "LDAP account enumeration against the DC and SMB share listing.",
                               {"dc": dc, "fileserver": fileserver}))

    # 4) Lateral Movement — SMB to a peer workstation admin share (T1021.002)
    t += 120
    flows.append(Flow(flow_id="atk-04-lateral", transport="tcp", src_ip=victim, dst_ip=peer,
                      src_port=sport(), dst_port=445, start_time=t, conn_state="SF",
                      src_os=env.default_client_os, l7=SmbL7(share=f"\\\\{peer}\\ADMIN$")))
    gt.append(GroundTruthEntry("Lateral Movement", "T1021.002 SMB/Windows Admin Shares",
                               ["atk-04-lateral"], "Lateral movement to a peer over the ADMIN$ share.",
                               {"peer": peer}))

    # 5) Exfiltration — large HTTP POST to an external server (T1048)
    t += 90
    flows.append(Flow(flow_id="atk-05-exfil", transport="tcp", src_ip=victim, dst_ip=exfil_ip,
                      src_port=sport(), dst_port=80, start_time=t, conn_state="SF",
                      src_os=env.default_client_os,
                      l7=HttpL7(method="POST", host="upload.evil.example", uri="/dropbox",
                                request_body_len=45000, status=200, response_body_len=20)))
    gt.append(GroundTruthEntry("Exfiltration", "T1048 Exfiltration Over Alternative Protocol",
                               ["atk-05-exfil"], "45 KB HTTP POST to an external drop server.",
                               {"exfil_ip": exfil_ip, "bytes": 45000}))

    iocs = {"c2_domain": c2_domain, "c2_ip": c2_ip, "exfil_ip": exfil_ip,
            "victim": victim, "sender": "hr-updates@evil.example"}
    return Intrusion(flows=flows, ground_truth=gt,
                     title=f"Phishing to exfiltration in {env.name}", iocs=iocs)


def write_ground_truth(intrusion: Intrusion, md_path, json_path=None) -> None:
    """Write a human GROUND_TRUTH.md (and optional JSON) — the training answer key."""
    import json
    from pathlib import Path

    # Render structured IOC values (e.g. the dce_rpc endpoint/operations) as compact JSON
    # rather than Python dict repr, so the answer key stays readable.
    def _fmt(v):
        return json.dumps(v) if isinstance(v, (dict, list)) else v

    lines = [f"# GROUND TRUTH — {intrusion.title}", "",
             "Malicious flows are labelled `atk-*`; everything else is benign ambient noise.",
             "", "## Kill chain", ""]
    for e in intrusion.ground_truth:
        lines.append(f"### {e.stage} — {e.technique}")
        lines.append(f"- {e.description}")
        lines.append(f"- Flows: {', '.join(e.flow_ids)}")
        if e.iocs:
            lines.append(f"- IOCs: {', '.join(f'{k}={_fmt(v)}' for k, v in e.iocs.items())}")
        lines.append("")
    if intrusion.evasions:
        lines += ["## Evasions applied", "",
                  f"The naive IOCs below are defeated by: {', '.join(intrusion.evasions)}.",
                  "A robust detection must still fire; a brittle one now misses.", ""]
    lines += ["## Indicators of compromise", ""]
    lines += [f"- `{k}`: {v}" for k, v in intrusion.iocs.items()]
    lines.append("")
    Path(md_path).write_text("\n".join(lines), encoding="utf-8")
    if json_path:
        tech_of = {fid: e.technique for e in intrusion.ground_truth for fid in e.flow_ids}
        mal = [{"flow_id": f.flow_id, "src_ip": f.src_ip, "dst_ip": f.dst_ip,
                "dst_port": f.dst_port, "proto": f.transport, "technique": tech_of.get(f.flow_id, "")}
               for f in intrusion.flows]
        payload = {"title": intrusion.title, "iocs": intrusion.iocs,
                   "evasions": intrusion.evasions,
                   "kill_chain": [{"stage": e.stage, "technique": e.technique,
                                   "flows": e.flow_ids, "description": e.description,
                                   "iocs": e.iocs} for e in intrusion.ground_truth],
                   "malicious_flows": mal}
        Path(json_path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Attack library — each builder returns an Intrusion; intensity scales volume. #
# --------------------------------------------------------------------------- #
import base64  # noqa: E402


def _public_ip(rng) -> str:
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _label(rng, n: int = 24) -> str:
    raw = bytes(rng.randint(0, 255) for _ in range(n))
    return base64.b32encode(raw).decode().rstrip("=").lower()[:48]


def _sports(start: int = 40000):
    p = start
    while True:
        yield p
        p += 1


def build_dns_exfil(env: Environment, start_time: float, rng, *, intensity: float = 1.0,
                    domain: str = "exfil.evil.example") -> Intrusion:
    """DNS tunneling exfiltration — many encoded subdomain lookups (T1048.003)."""
    victim = _hosts(env, 1)[0]
    n = max(8, int(60 * intensity))
    sp = _sports()
    flows, ids = [], []
    for i in range(n):
        fid = f"atk-dnsx-{i:03d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="udp", src_ip=victim, dst_ip=env.dns_server,
                          src_port=next(sp), dst_port=53, start_time=start_time + i * (2.0 / max(0.1, intensity)),
                          src_os=env.default_client_os,
                          l7=DnsL7(qname=f"{_label(rng)}.{domain}.", qtype="A", answers=[], rcode="NXDOMAIN")))
    gt = [GroundTruthEntry("Exfiltration", "T1048.003 Exfiltration Over Unencrypted Non-C2 (DNS)",
                           ids, f"{n} DNS lookups with long encoded subdomains under {domain} — tunneling.",
                           {"exfil_domain": domain, "query_count": n})]
    return Intrusion(flows, gt, f"DNS-tunnel exfiltration in {env.name}",
                     {"exfil_domain": domain, "victim": victim})


# Public DoH/DoT resolvers (server_name, ip) — the SNI/IP a defender blocklists.
_DOH_RESOLVERS = [("cloudflare-dns.com", "1.1.1.1"), ("dns.google", "8.8.8.8"),
                  ("dns.quad9.net", "9.9.9.9")]


def build_doh_tunnel(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """DNS-over-HTTPS tunneling — encrypted-DNS C2/exfil to a public DoH resolver.

    On the wire DoH is indistinguishable from HTTPS except by destination: TLS 1.3 (ALPN
    h2) to a known DoH provider's SNI/IP on 443. It defeats plaintext-DNS monitoring, so
    the detection is the resolver SNI/IP + a beacon cadence, not DNS content (T1071.004
    Application Layer Protocol: DNS / T1572 Protocol Tunneling)."""
    victim = _hosts(env, 1)[0]
    resolver, rip = _DOH_RESOLVERS[0]
    n = max(8, int(40 * intensity))
    sp = _sports()
    flows, ids = [], []
    for i in range(n):
        fid = f"atk-doh-{i:03d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=victim, dst_ip=rip,
                          src_port=next(sp), dst_port=443, conn_state="SF",
                          start_time=start_time + i * (3.0 / max(0.1, intensity)),
                          src_os=env.default_client_os,
                          l7=TlsL7(server_name=resolver, version="TLS1.3", client_profile="curl",
                                   alpn=["h2"], app_data_orig_bytes=rng.randint(80, 160),
                                   app_data_resp_bytes=rng.randint(200, 700))))
    gt = [GroundTruthEntry(
        "Command and Control", "T1071.004 Application Layer Protocol: DNS / T1572 Protocol Tunneling",
        ids, f"{n} DoH sessions to {resolver} ({rip}) — encrypted-DNS C2/exfil that bypasses "
        f"plaintext-DNS monitoring.",
        {"victim": victim, "resolver": resolver, "resolver_ip": rip, "channel": "doh",
         "expected_signal": f"ssl.log server_name={resolver} to :443 (known DoH provider)"})]
    return Intrusion(flows, gt, f"DoH tunnel from {victim} in {env.name}",
                     {"victim": victim, "resolver": resolver, "channel": "doh"})


def build_dot_tunnel(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """DNS-over-TLS tunneling — encrypted-DNS on the dedicated TLS/853 port (T1071.004 / T1572).

    Unlike DoH, DoT has its own port, so it stands out: TLS on 853 with ALPN ``dot`` (which
    Zeek records as ssl.log next_protocol). Detection = TLS on 853 to a resolver."""
    victim = _hosts(env, 1)[0]
    resolver, rip = _DOH_RESOLVERS[0]
    n = max(8, int(40 * intensity))
    sp = _sports()
    flows, ids = [], []
    for i in range(n):
        fid = f"atk-dot-{i:03d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=victim, dst_ip=rip,
                          src_port=next(sp), dst_port=853, conn_state="SF",
                          start_time=start_time + i * (3.0 / max(0.1, intensity)),
                          src_os=env.default_client_os,
                          l7=TlsL7(server_name=resolver, version="TLS1.2", client_profile="curl",
                                   alpn=["dot"], app_data_orig_bytes=rng.randint(80, 160),
                                   app_data_resp_bytes=rng.randint(200, 700))))
    gt = [GroundTruthEntry(
        "Command and Control", "T1071.004 Application Layer Protocol: DNS / T1572 Protocol Tunneling",
        ids, f"{n} DoT sessions to {resolver} ({rip}) on tcp/853 — encrypted-DNS off the "
        f"standard resolver path.",
        {"victim": victim, "resolver": resolver, "resolver_ip": rip, "channel": "dot",
         "expected_signal": "ssl.log to :853 with next_protocol=dot"})]
    return Intrusion(flows, gt, f"DoT tunnel from {victim} in {env.name}",
                     {"victim": victim, "resolver": resolver, "channel": "dot"})


def build_ipv6_c2(env: Environment, start_time: float, rng, *, intensity: float = 1.0,
                  c2_domain: str = "cdn.telemetry-sync.example") -> Intrusion:
    """HTTPS C2 beaconing over IPv6 — tests whether a detection is address-family-blind (T1071.001).

    Many detections are written against IPv4 5-tuples and silently miss the identical
    behaviour over v6. The victim resolves the C2 to an AAAA record, then beacons to it over
    IPv6 with a non-browser JA3 at a fixed cadence — the same C2 tell, one address family over."""
    victim = "2001:db8:1::40"
    c2_ip = "2606:4700:8ac0::66"
    dc = env.dns_server
    sp = _sports()
    flows = []
    # AAAA resolution of the C2 (over the v4 resolver — mixed-stack is realistic).
    flows.append(Flow(flow_id="atk-6-dns", transport="udp", src_ip="10.10.0.40", dst_ip=dc,
                      src_port=next(sp), dst_port=53, start_time=start_time,
                      src_os=env.default_client_os,
                      l7=DnsL7(qname=c2_domain + ".", qtype="AAAA", answers=[c2_ip])))
    beacon_ids = []
    for i in range(max(3, int(6 * intensity))):
        fid = f"atk-6-beacon-{i:02d}"
        beacon_ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=victim, dst_ip=c2_ip,
                          src_port=next(sp), dst_port=443, conn_state="SF",
                          start_time=start_time + 30 + i * 60 + rng.uniform(-4, 4),
                          src_os=env.default_client_os,
                          l7=TlsL7(server_name=c2_domain, version="TLS1.3", client_profile="curl",
                                   app_data_orig_bytes=rng.randint(120, 200),
                                   app_data_resp_bytes=rng.randint(300, 900))))
    gt = [GroundTruthEntry(
        "Command and Control", "T1071.001 Application Layer Protocol: Web Protocols (over IPv6)",
        ["atk-6-dns"] + beacon_ids,
        f"HTTPS beaconing to {c2_domain} ({c2_ip}) over IPv6 — a v4-only detection misses it.",
        {"victim": victim, "c2_domain": c2_domain, "c2_ip": c2_ip, "family": "ipv6",
         "expected_signal": f"ssl.log to {c2_ip} (IPv6) with a curl JA3 at ~60s cadence"})]
    return Intrusion(flows, gt, f"IPv6 C2 beaconing in {env.name}",
                     {"victim": victim, "c2_domain": c2_domain, "c2_ip": c2_ip})


# --------------------------------------------------------------------------- #
# Cloud (AWS/Azure/GCP/OCI) north-south attacks. The provider is inferred from   #
# the environment name so one builder renders the right metadata endpoint,       #
# headers, and storage SNI per cloud.                                            #
# --------------------------------------------------------------------------- #
_METADATA_IP = "169.254.169.254"  # the link-local instance-metadata address (all clouds)

# provider -> (metadata host, credential path, required request headers)
_IMDS = {
    "aws": ("169.254.169.254", "/latest/meta-data/iam/security-credentials/ec2-app-role", {}),
    "gcp": ("metadata.google.internal",
            "/computeMetadata/v1/instance/service-accounts/default/token",
            {"Metadata-Flavor": "Google"}),
    "azure": ("169.254.169.254",
              "/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/",
              {"Metadata": "true"}),
    "oci": ("169.254.169.254", "/opc/v2/instance/", {"Authorization": "Bearer Oracle"}),
}
_CLOUD_STORAGE = {
    "aws": "exfil-staging.s3.amazonaws.com",
    "azure": "exfilstg.blob.core.windows.net",
    "gcp": "storage.googleapis.com",
    "oci": "objectstorage.us-ashburn-1.oraclecloud.com",
}


def _cloud_provider(env: Environment) -> str:
    for p in ("aws", "azure", "gcp", "oci"):
        if p in env.name:
            return p
    return "aws"


def build_imds_ssrf(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Cloud instance-metadata credential theft via SSRF — T1552.005 (the Capital One shape).

    A compromised/SSRF-abused instance reaches the link-local metadata service (169.254.169.254)
    and pulls the instance's IAM role credentials/token. The detection is traffic to the
    metadata IP on the credential path from a host that shouldn't be calling it."""
    victim = _hosts(env, 1)[0]
    provider = _cloud_provider(env)
    host, cred_path, headers = _IMDS[provider]
    sp = _sports()
    flows = []
    for i, path in enumerate(["/latest/meta-data/" if provider == "aws" else "/", cred_path]):
        flows.append(Flow(flow_id=f"atk-imds-{i}", transport="tcp", src_ip=victim, dst_ip=_METADATA_IP,
                          src_port=next(sp), dst_port=80, conn_state="SF",
                          start_time=start_time + i * 0.5, src_os=env.default_client_os,
                          l7=HttpL7(method="GET", host=host, uri=path, request_headers=headers,
                                    status=200, response_body_len=rng.randint(400, 1200))))
    gt = [GroundTruthEntry(
        "Credential Access", "T1552.005 Unsecured Credentials: Cloud Instance Metadata API",
        [f.flow_id for f in flows],
        f"{victim} queried the instance metadata service ({_METADATA_IP}) for {provider.upper()} "
        f"IAM credentials — SSRF-to-IMDS theft (the Capital One pattern).",
        {"victim": victim, "provider": provider, "metadata_ip": _METADATA_IP, "cred_path": cred_path,
         "expected_signal": f"http.log to {_METADATA_IP} uri={cred_path}"})]
    return Intrusion(flows, gt, f"IMDS SSRF credential theft in {env.name}",
                     {"victim": victim, "provider": provider, "metadata_ip": _METADATA_IP})


def build_cloud_exfil(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Exfiltration to cloud storage — T1567.002. Large HTTPS uploads to a provider bucket/blob."""
    victim = _hosts(env, 1)[0]
    provider = _cloud_provider(env)
    sni = _CLOUD_STORAGE[provider]
    sp = _sports()
    flows = [Flow(flow_id="atk-cx-dns", transport="udp", src_ip=victim, dst_ip=env.dns_server,
                 src_port=next(sp), dst_port=53, start_time=start_time, src_os=env.default_client_os,
                 l7=DnsL7(qname=sni + ".", answers=["203.0.113.90"]))]
    n = max(3, int(6 * intensity))
    ids = []
    for i in range(n):
        fid = f"atk-cx-{i:02d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=victim, dst_ip="203.0.113.90",
                          src_port=next(sp), dst_port=443, conn_state="SF",
                          start_time=start_time + 5 + i * 2.0, src_os=env.default_client_os,
                          l7=TlsL7(server_name=sni, version="TLS1.3", client_profile="curl",
                                   app_data_orig_bytes=rng.randint(220_000, 480_000),
                                   app_data_resp_bytes=rng.randint(120, 300))))
    gt = [GroundTruthEntry(
        "Exfiltration", "T1567.002 Exfiltration to Cloud Storage",
        ["atk-cx-dns"] + ids,
        f"{n} large HTTPS uploads from {victim} to {provider.upper()} cloud storage ({sni}) — "
        f"data staged out through a trusted cloud endpoint.",
        {"victim": victim, "provider": provider, "storage": sni,
         "expected_signal": f"ssl.log server_name={sni} with large orig_bytes (upload-heavy)"})]
    return Intrusion(flows, gt, f"Cloud-storage exfil in {env.name}",
                     {"victim": victim, "provider": provider, "storage": sni})


def build_k8s_lateral(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Lateral movement inside a Kubernetes cluster — T1613 / T1552.007 / T1021 (in-cluster).

    A compromised pod discovers cluster services via CoreDNS, reaches the API server (using its
    mounted service-account token), then fans out mutual-TLS across the service mesh to other
    pods. Captured at a mirror collector, this is all VXLAN-encapsulated east-west traffic."""
    attacker_pod = "10.244.1.13"
    api = "10.96.0.1"  # kubernetes.default.svc ClusterIP
    coredns = env.dns_server
    sp = _sports()
    flows = []
    t = start_time
    for svc in ["kubernetes.default.svc.cluster.local", "vault.default.svc.cluster.local"]:
        flows.append(Flow(flow_id=f"atk-k8s-dns-{len(flows)}", transport="udp", src_ip=attacker_pod,
                          dst_ip=coredns, src_port=next(sp), dst_port=53, start_time=t, src_os="linux",
                          l7=DnsL7(qname=svc + ".", answers=["10.96.0.1"])))
        t += 1.0
    flows.append(Flow(flow_id="atk-k8s-api", transport="tcp", src_ip=attacker_pod, dst_ip=api,
                      src_port=next(sp), dst_port=443, start_time=t, conn_state="SF", src_os="linux",
                      seg_bytes=1350,  # VXLAN CNI reduces the pod MTU to leave room for encapsulation
                      l7=TlsL7(server_name="kubernetes.default.svc", version="TLS1.3",
                               client_profile="curl", app_data_orig_bytes=rng.randint(400, 900),
                               app_data_resp_bytes=rng.randint(2000, 8000))))
    t += 2.0
    pods = ["10.244.2.20", "10.244.3.7", "10.244.2.44", "10.244.4.11"]
    ids = []
    for i, pod in enumerate(pods):
        fid = f"atk-k8s-lat-{i}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=attacker_pod, dst_ip=pod,
                          src_port=next(sp), dst_port=8443, conn_state="SF", start_time=t + i * 1.5,
                          src_os="linux", seg_bytes=1350,
                          l7=TlsL7(server_name=f"svc-{i}.default.svc", version="TLS1.3",
                                   client_profile="curl", app_data_orig_bytes=rng.randint(200, 500),
                                   app_data_resp_bytes=rng.randint(300, 900))))
    gt = [GroundTruthEntry(
        "Lateral Movement", "T1613 Container/Cluster Discovery / T1021 Remote Services (in-cluster)",
        [f.flow_id for f in flows],
        f"A compromised pod ({attacker_pod}) discovered cluster services via CoreDNS, reached the "
        f"API server ({api}), then fanned out mTLS to {len(pods)} pods across the service mesh.",
        {"attacker_pod": attacker_pod, "api_server": api, "pod_count": len(pods),
         "expected_signal": f"a pod talking to {api}:443 then mTLS fan-out to many pods (VXLAN-decapped)"})]
    return Intrusion(flows, gt, f"K8s cluster lateral movement in {env.name}",
                     {"attacker_pod": attacker_pod, "api_server": api})


def build_llmnr_poisoning(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """LLMNR/NBT-NS poisoning -> SMB/NTLM capture (Responder-style) — T1557.001.

    A victim's failed name lookups fall back to LLMNR broadcast; a rogue internal host
    answers every one (including the classic ``wpad`` proxy-autodiscovery name) claiming
    its own IP, then the victim authenticates to it over SMB — handing over an NTLMv2 hash.
    The tell: an LLMNR answer whose rdata is a workstation, from a non-DNS host, immediately
    followed by SMB to that host."""
    victim, attacker = _hosts(env, 2)
    sp = _sports()
    names = ["wpad", "fileserverr", "sharepoin"]  # wpad first: the highest-value Responder target
    flows, ids = [], []
    for i, name in enumerate(names):
        fid = f"atk-llmnr-{i:02d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="udp", src_ip=victim, dst_ip="224.0.0.252",
                          src_port=next(sp), dst_port=5355, start_time=start_time + i * 4.0,
                          src_os=env.default_client_os,
                          l7=NameQueryL7(protocol="llmnr", qname=name, poison_from=attacker)))
    smb_id = "atk-llmnr-smb"
    flows.append(Flow(flow_id=smb_id, transport="tcp", src_ip=victim, dst_ip=attacker,
                      src_port=next(sp), dst_port=445, conn_state="SF",
                      start_time=start_time + len(names) * 4.0 + 2.0, src_os=env.default_client_os,
                      l7=SmbL7(share=f"\\\\{attacker}\\wpad")))
    gt = [GroundTruthEntry(
        "Credential Access", "T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay",
        ids + [smb_id],
        f"{victim} broadcast LLMNR lookups (incl. wpad); {attacker} poisoned each with its own "
        f"IP, then {victim} authenticated to {attacker} over SMB — a Responder-style NTLM capture.",
        {"victim": victim, "attacker": attacker,
         "expected_signal": f"dns.log LLMNR answer={attacker} (a workstation) from a non-DNS host, "
                            f"then SMB {victim}->{attacker}"})]
    return Intrusion(flows, gt, f"LLMNR poisoning in {env.name}",
                     {"victim": victim, "attacker": attacker})


def build_ddos_syn_flood(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Volumetric SYN flood against an internal service (T1499.001 / T1498)."""
    victim = _hosts(env, 1)[0]
    n = max(40, int(300 * intensity))
    flows, ids = [], []
    for i in range(n):
        fid = f"atk-syn-{i:04d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=_public_ip(rng), dst_ip=victim,
                          src_port=rng.randint(1024, 65535), dst_port=443,
                          start_time=start_time + i * (0.05 / max(0.1, intensity)), conn_state="S0",
                          l7=OpaqueTcpL7(orig_bytes=0, resp_bytes=0)))
    gt = [GroundTruthEntry("Impact", "T1499.001 Endpoint DoS: OS Exhaustion (SYN flood)",
                           ids, f"{n} half-open (S0) connections to {victim}:443 from spoofed sources.",
                           {"victim": victim, "syn_count": n})]
    return Intrusion(flows, gt, f"SYN flood against {victim}", {"victim": victim})


def build_port_scan(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Vertical port scan of an internal host (T1046 / TA0007)."""
    scanner, target = _hosts(env, 2)
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]
    ports = (ports * max(1, int(intensity)))[: max(12, int(len(ports) * intensity))]
    sp = _sports()
    flows, ids = [], []
    for i, port in enumerate(ports):
        fid = f"atk-scan-{i:03d}"
        ids.append(fid)
        state = "SF" if port in (80, 443, 445) else "REJ"  # a few open, most closed
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=scanner, dst_ip=target,
                          src_port=next(sp), dst_port=port, start_time=start_time + i * 0.3,
                          src_os=env.default_client_os, conn_state=state,
                          l7=OpaqueTcpL7(orig_bytes=0, resp_bytes=0)))
    gt = [GroundTruthEntry("Discovery", "T1046 Network Service Discovery (port scan)",
                           ids, f"{scanner} scanned {len(ports)} ports on {target} (mostly REJ).",
                           {"scanner": scanner, "target": target})]
    return Intrusion(flows, gt, f"Port scan of {target}", {"scanner": scanner, "target": target})


def build_brute_force(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """SSH password brute force / spray against a server (T1110)."""
    attacker, target = _hosts(env, 2)
    n = max(10, int(30 * intensity))
    sp = _sports()
    flows, ids = [], []
    for i in range(n):
        fid = f"atk-bf-{i:03d}"
        ids.append(fid)
        # failed attempts reset the connection after the banner/kex
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=attacker, dst_ip=target,
                          src_port=next(sp), dst_port=22, start_time=start_time + i * (1.5 / max(0.1, intensity)),
                          src_os=env.default_client_os, conn_state="RSTO",
                          l7=SshL7(payload_bytes=200)))
    gt = [GroundTruthEntry("Credential Access", "T1110.001 Brute Force: Password Guessing (SSH)",
                           ids, f"{n} SSH attempts from {attacker} to {target} (repeated resets).",
                           {"attacker": attacker, "target": target, "attempts": n})]
    return Intrusion(flows, gt, f"SSH brute force against {target}", {"attacker": attacker, "target": target})


def build_ransomware(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Human-operated ransomware: recon -> C2 -> mass SMB file access (T1486)."""
    victim, fileserver = _hosts(env, 2)
    c2_ip = _public_ip(rng)
    sp = _sports()
    flows, gt = [], []
    # C2 check-in
    flows.append(Flow(flow_id="atk-rw-c2", transport="tcp", src_ip=victim, dst_ip=c2_ip, src_port=next(sp),
                      dst_port=443, start_time=start_time, conn_state="SF", src_os=env.default_client_os,
                      l7=TlsL7(server_name="update.evil.example", client_profile="curl",
                               app_data_resp_bytes=800)))
    gt.append(GroundTruthEntry("Command and Control", "T1071.001 Web C2", ["atk-rw-c2"],
                               "Ransomware C2 check-in over HTTPS.", {"c2_ip": c2_ip}))
    # mass SMB file access (encryption) — each reads a real file off the share, so the
    # stolen/encrypted documents are extractable from the capture.
    n = max(20, int(80 * intensity))
    _docs = ["Q3-financials.xlsx", "payroll.xlsx", "contract.docx", "roadmap.pptx",
             "customers.zip", "backup.zip", "passwords.docx", "invoice.pdf"]
    ids = []
    for i in range(n):
        fid = f"atk-rw-smb-{i:03d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=victim, dst_ip=fileserver, src_port=next(sp),
                          dst_port=445, start_time=start_time + 30 + i * (0.4 / max(0.1, intensity)),
                          src_os=env.default_client_os, conn_state="SF",
                          l7=SmbL7(share=f"\\\\{fileserver}\\Share",
                                   read_file=_docs[i % len(_docs)], file_bytes=8000 + i * 64)))
    gt.append(GroundTruthEntry("Impact", "T1486 Data Encrypted for Impact (mass SMB access)",
                               ids, f"{n} rapid SMB sessions to {fileserver} — file encryption sweep.",
                               {"fileserver": fileserver, "session_count": n}))
    return Intrusion(flows, gt, f"Ransomware sweep in {env.name}",
                     {"victim": victim, "fileserver": fileserver, "c2_ip": c2_ip})


_ROAST_SPNS = [
    "MSSQLSvc/sql01.corp.example:1433", "HTTP/intranet.corp.example",
    "CIFS/fileserver.corp.example", "MSSQLSvc/sql02.corp.example:1433",
    "HTTP/reports.corp.example", "LDAP/dc01.corp.example",
    "FTP/ftp.corp.example", "TERMSRV/jump.corp.example",
]


def build_kerberoasting(env: Environment, start_time: float, rng, *, intensity: float = 1.0,
                        realm: str = "CORP.EXAMPLE") -> Intrusion:
    """Kerberoasting: one principal requests many RC4 service tickets in a burst (T1558.003).

    The tell is on the wire: a normal TGT (AES), then a rapid run of TGS-REQs for
    distinct SPNs, each forcing RC4-HMAC (etype 23) so the service tickets are
    offline-crackable. Real Zeek logs each as ``cipher=rc4-hmac``; Suricata fires
    ``krb5.weak_encryption``.
    """
    victim = _hosts(env, 1)[0]
    dc = env.dns_server
    sp = _sports()
    flows, gt = [], []
    user = "svc-analyst"
    # 1) attacker's own TGT — looks normal (AES256, pre-auth)
    flows.append(Flow(flow_id="atk-krb-tgt", transport="tcp", src_ip=victim, dst_ip=dc,
                      src_port=next(sp), dst_port=88, start_time=start_time, conn_state="SF",
                      src_os=env.default_client_os,
                      l7=KerberosL7(request_type="AS", client=user, realm=realm,
                                    etype=18, request_etypes=[18, 17])))
    # 2) the roast: a burst of RC4 service-ticket requests
    n = max(4, int(len(_ROAST_SPNS) * intensity))
    spns = (_ROAST_SPNS * (n // len(_ROAST_SPNS) + 1))[:n]
    ids = []
    for i, spn in enumerate(spns):
        fid = f"atk-krb-roast-{i:02d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=victim, dst_ip=dc,
                          src_port=next(sp), dst_port=88,
                          start_time=start_time + 5 + i * (1.5 / max(0.1, intensity)),
                          conn_state="SF", src_os=env.default_client_os,
                          l7=KerberosL7(request_type="TGS", client=user, realm=realm,
                                        service=f"{spn}@{realm}", etype=23, request_etypes=[23])))
    gt.append(GroundTruthEntry(
        "Credential Access", "T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting",
        ["atk-krb-tgt"] + ids,
        f"{user}@{victim} requested {n} RC4 service tickets across distinct SPNs in a burst.",
        {"principal": user, "victim": victim, "dc": dc, "spn_count": n, "enctype": "rc4-hmac"}))
    return Intrusion(flows, gt, f"Kerberoasting from {victim} in {env.name}",
                     {"principal": user, "victim": victim, "dc": dc, "enctype": "rc4-hmac"})


def build_asrep_roasting(env: Environment, start_time: float, rng, *, intensity: float = 1.0,
                         realm: str = "CORP.EXAMPLE") -> Intrusion:
    """AS-REP roasting: AS-REQs with no pre-auth yield crackable AS-REPs (T1558.004).

    For accounts flagged "do not require Kerberos pre-authentication", an AS-REQ
    without PA-ENC-TIMESTAMP returns an AS-REP whose encrypted part is offline-
    crackable. We force RC4 (the easy crack), which real Zeek logs as ``cipher=
    rc4-hmac`` and Suricata flags as ``krb5.weak_encryption``. The deeper tell — no
    pre-auth — is captured faithfully (the AS-REQ carries no PA-ENC-TIMESTAMP).
    """
    victim = _hosts(env, 1)[0]
    dc = env.dns_server
    sp = _sports()
    targets = ["svc-backup", "svc-web", "helpdesk", "svc-scan", "kiosk", "svc-report"]
    n = max(3, int(len(targets) * intensity))
    targets = (targets * (n // len(targets) + 1))[:n]
    flows, ids = [], []
    for i, tgt in enumerate(targets):
        fid = f"atk-asrep-{i:02d}"
        ids.append(fid)
        flows.append(Flow(flow_id=fid, transport="tcp", src_ip=victim, dst_ip=dc,
                          src_port=next(sp), dst_port=88,
                          start_time=start_time + i * (2.0 / max(0.1, intensity)),
                          conn_state="SF", src_os=env.default_client_os,
                          l7=KerberosL7(request_type="AS", client=tgt, realm=realm,
                                        etype=23, request_etypes=[23], preauth=False)))
    gt = [GroundTruthEntry(
        "Credential Access", "T1558.004 Steal or Forge Kerberos Tickets: AS-REP Roasting",
        ids, f"{n} pre-auth-less AS-REQs from {victim} yielding RC4 AS-REPs for cracking.",
        {"victim": victim, "dc": dc, "target_count": n, "enctype": "rc4-hmac", "preauth": False})]
    return Intrusion(flows, gt, f"AS-REP roasting from {victim} in {env.name}",
                     {"victim": victim, "dc": dc, "enctype": "rc4-hmac"})


# --------------------------------------------------------------------------- #
# BZAR lateral-movement pack — inert MS-RPC-over-SMB fixtures.                  #
#                                                                              #
# Each builder renders the on-the-wire *shape* of a lateral-movement technique #
# (SMB named pipe + DCE-RPC bind + the operation's opnum) so a blue team can    #
# point Zeek + the BZAR analytic at the capture and confirm their coverage      #
# fires. Inert by construction: the DCE-RPC request stubs are opaque filler,    #
# never real operation arguments — no service binary/path, task payload, or      #
# command. See docs/inert-by-construction.md. Ground truth carries the ATT&CK    #
# technique, the concrete Zeek dce_rpc.log endpoint+operations, and the BZAR     #
# notice the flow is expected to trip.                                          #
# --------------------------------------------------------------------------- #


# PsExec-style remote service creation over \svcctl (opnums -> Zeek operation names,
# verified against real Zeek). The full sysinternals-PsExec service-install sequence, matched
# to real captures (sbousseaden LM_psexec, OTRF Empire): open the SCM, create the service,
# query it, open it, start it, query again, then close each handle. Earlier this was the bare
# OpenSCManager->Create->Start->Close — the BZAR detection signal is the same, but real tools
# emit the fuller sequence, so a sequence-aware hunter could tell the short form apart.
_SVCCTL_CREATE_START = (
    [15, 12, 6, 16, 19, 6, 0, 0, 0],
    ["OpenSCManagerW", "CreateServiceW", "QueryServiceStatus", "OpenServiceW",
     "StartServiceW", "QueryServiceStatus", "CloseServiceHandle", "CloseServiceHandle",
     "CloseServiceHandle"])


def _dcerpc_flow(flow_id: str, src: str, dst: str, sport: int, start: float, *,
                 pipe: str, interface: str, share: str, operations: list, op_names: list,
                 src_os: str, dst_port: int = 445, transport: str = "ncacn_np") -> Flow:
    return Flow(flow_id=flow_id, transport="tcp", src_ip=src, dst_ip=dst,
               src_port=sport, dst_port=dst_port, start_time=start, conn_state="SF", src_os=src_os,
               l7=DceRpcL7(share=share, pipe=pipe, interface=interface,
                          operations=operations, op_names=op_names, transport=transport))


def _epmapper_flow(flow_id: str, src: str, dst: str, sport: int, start: float, src_os: str) -> Flow:
    """The endpoint-mapper lookup (epmapper::ept_map over ncacn_ip_tcp/135) that precedes a real
    DCE-RPC service call — a compromised host resolving the target's dynamic RPC endpoint."""
    return _dcerpc_flow(flow_id, src, dst, sport, start, pipe="epmapper", interface="epmapper",
                        share="", operations=[3], op_names=["ept_map"], src_os=src_os,
                        dst_port=135, transport="ncacn_ip_tcp")


def build_remote_service(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Remote service creation over \\svcctl (PsExec-style) — T1543.003 / T1569.002."""
    attacker, target = _hosts(env, 2)
    sp = _sports()
    ops, names = _SVCCTL_CREATE_START
    epm = _epmapper_flow("atk-svcctl-epm", attacker, target, next(sp), start_time,
                         env.default_client_os)
    flow = _dcerpc_flow("atk-svcctl-01", attacker, target, next(sp), start_time + 0.2,
                        pipe="svcctl", interface="svcctl", share=f"\\\\{target}\\IPC$",
                        operations=ops, op_names=names, src_os=env.default_client_os)
    gt = [GroundTruthEntry(
        "Lateral Movement",
        "T1543.003 Create or Modify System Process / T1569.002 Service Execution",
        ["atk-svcctl-epm", "atk-svcctl-01"],
        f"Remote service creation on {target}: endpoint-mapper lookup (epmapper::ept_map) then "
        f"\\svcctl OpenSCManagerW -> CreateServiceW -> StartServiceW (PsExec-style).",
        {"attacker": attacker, "target": target, "pipe": "svcctl",
         "dce_rpc": {"endpoint": "svcctl", "operations": ["CreateServiceW", "StartServiceW"]},
         "expected_notice": "ATTACK::Execution"})]  # BZAR: T1569.002 Service Execution
    return Intrusion([epm, flow], gt, f"Remote service creation on {target}",
                     {"attacker": attacker, "target": target})


def build_scheduled_task(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Remote scheduled-task registration over \\atsvc — T1053.005."""
    attacker, target = _hosts(env, 2)
    sp = _sports()
    flow = _dcerpc_flow("atk-atsvc-01", attacker, target, next(sp), start_time,
                        pipe="atsvc", interface="ITaskSchedulerService", share=f"\\\\{target}\\IPC$",
                        operations=[1], op_names=["SchRpcRegisterTask"], src_os=env.default_client_os)
    gt = [GroundTruthEntry(
        "Persistence", "T1053.005 Scheduled Task/Job: Scheduled Task",
        ["atk-atsvc-01"],
        f"Remote scheduled-task registration on {target} via ITaskSchedulerService::SchRpcRegisterTask.",
        {"attacker": attacker, "target": target, "pipe": "atsvc",
         "dce_rpc": {"endpoint": "ITaskSchedulerService", "operations": ["SchRpcRegisterTask"]},
         "expected_notice": "ATTACK::Execution"})]  # BZAR: T1053.005 Scheduled Task
    return Intrusion([flow], gt, f"Remote scheduled task on {target}",
                     {"attacker": attacker, "target": target})


def build_wmi_exec(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """WMI remote execution via IWbemServices::ExecMethod — T1047.

    Real WMI rides DCOM over ncacn_ip_tcp; the fixture renders the IWbemServices bind +
    ExecMethod opnum (the dce_rpc.log signal BZAR watches) over the uniform SMB-pipe
    substrate, with an inert stub in place of the method arguments.
    """
    attacker, target = _hosts(env, 2)
    sp = _sports()
    flow = _dcerpc_flow("atk-wmi-01", attacker, target, next(sp), start_time,
                        pipe="wmi", interface="IWbemServices", share=f"\\\\{target}\\IPC$",
                        operations=[24], op_names=["ExecMethod"], src_os=env.default_client_os)
    gt = [GroundTruthEntry(
        "Execution", "T1047 Windows Management Instrumentation",
        ["atk-wmi-01"],
        f"WMI remote execution against {target}: IWbemServices::ExecMethod.",
        {"attacker": attacker, "target": target, "pipe": "wmi",
         "dce_rpc": {"endpoint": "IWbemServices", "operations": ["ExecMethod"]},
         "expected_notice": "ATTACK::Execution"})]
    return Intrusion([flow], gt, f"WMI execution on {target}",
                     {"attacker": attacker, "target": target})


def build_admin_share_transfer(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Lateral tool transfer to an ADMIN$ share — T1021.002 / T1570.

    The transferred file is an inert PE *shell* (valid MZ/PE header over synthetic
    filler, no code) — extraction tooling sees a file, but nothing executable.
    """
    attacker, target = _hosts(env, 2)
    sp = _sports()
    flow = Flow(flow_id="atk-admin-01", transport="tcp", src_ip=attacker, dst_ip=target,
                src_port=next(sp), dst_port=445, start_time=start_time, conn_state="SF",
                src_os=env.default_client_os,
                l7=SmbL7(share=f"\\\\{target}\\ADMIN$", write_file="svc.exe", file_bytes=6144))
    gt = [GroundTruthEntry(
        "Lateral Movement", "T1021.002 SMB/Windows Admin Shares / T1570 Lateral Tool Transfer",
        ["atk-admin-01"],
        f"Lateral tool transfer to {target}\\ADMIN$ (SMB write of svc.exe, inert PE shell).",
        {"attacker": attacker, "target": target, "share": f"\\\\{target}\\ADMIN$",
         "smb_files": {"share": "ADMIN$", "name": "svc.exe"},
         # A single SMB write to an admin file share trips BZAR's T1021.002/T1570 notice.
         "expected_notice": "ATTACK::Lateral_Movement"})]
    return Intrusion([flow], gt, f"Admin-share tool transfer to {target}",
                     {"attacker": attacker, "target": target})


def build_share_discovery(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Network share enumeration over \\srvsvc — T1135."""
    attacker, target = _hosts(env, 2)
    sp = _sports()
    # A share sweep: enumerate shares, then pull details on each. Six discovery calls, so
    # BZAR's SumStats crosses its Discovery threshold (>=5 in the epoch).
    ops = [15, 16, 16, 16, 16, 16]
    names = ["NetrShareEnum"] + ["NetrShareGetInfo"] * 5
    flow = _dcerpc_flow("atk-srvsvc-01", attacker, target, next(sp), start_time,
                        pipe="srvsvc", interface="srvsvc", share=f"\\\\{target}\\IPC$",
                        operations=ops, op_names=names, src_os=env.default_client_os)
    gt = [GroundTruthEntry(
        "Discovery", "T1135 Network Share Discovery",
        ["atk-srvsvc-01"],
        f"Network share enumeration on {target}: srvsvc NetrShareEnum + per-share NetrShareGetInfo.",
        {"attacker": attacker, "target": target, "pipe": "srvsvc",
         "dce_rpc": {"endpoint": "srvsvc", "operations": ["NetrShareEnum", "NetrShareGetInfo"]},
         "expected_notice": "ATTACK::Discovery"})]
    return Intrusion([flow], gt, f"Share discovery against {target}",
                     {"attacker": attacker, "target": target})


def build_account_discovery(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Domain account enumeration over \\samr — T1087.002."""
    attacker, target = _hosts(env, 2)
    sp = _sports()
    # Full account-enumeration chain. The six Enumerate*/Query*/Lookup* calls are all
    # BZAR discovery operations, so its SumStats crosses the Discovery threshold (>=5).
    ops = [0, 5, 6, 7, 8, 13, 11, 15, 17, 1]
    names = ["SamrConnect", "SamrLookupDomainInSamServer", "SamrEnumerateDomainsInSamServer",
             "SamrOpenDomain", "SamrQueryInformationDomain", "SamrEnumerateUsersInDomain",
             "SamrEnumerateGroupsInDomain", "SamrEnumerateAliasesInDomain",
             "SamrLookupNamesInDomain", "SamrCloseHandle"]
    flow = _dcerpc_flow("atk-samr-01", attacker, target, next(sp), start_time,
                        pipe="samr", interface="samr", share=f"\\\\{target}\\IPC$",
                        operations=ops, op_names=names, src_os=env.default_client_os)
    gt = [GroundTruthEntry(
        "Discovery", "T1087.002 Account Discovery: Domain Account",
        ["atk-samr-01"],
        f"Domain account enumeration on {target}: samr Connect/OpenDomain then "
        f"EnumerateUsers/Groups/Aliases + LookupNames.",
        {"attacker": attacker, "target": target, "pipe": "samr",
         "dce_rpc": {"endpoint": "samr",
                     "operations": ["SamrEnumerateUsersInDomain", "SamrEnumerateAliasesInDomain"]},
         "expected_notice": "ATTACK::Discovery"})]
    return Intrusion([flow], gt, f"Account discovery against {target}",
                     {"attacker": attacker, "target": target})


def build_dcsync(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """DCSync: replicate directory secrets from a DC over drsuapi (DRSGetNCChanges) from a
    non-DC host — T1003.006. The Zeek signal is ``drsuapi::DRSGetNCChanges`` sourced from a
    host that is not a domain controller. Inert: the RPC stubs are zero filler, never any
    replicated secret. Real DCSync often Kerberos-seals this DCE-RPC channel (so a real capture
    yields no dce_rpc.log); we reproduce the detection *signal* over a clean channel by design."""
    attacker, dc = _hosts(env, 2)
    sp = _sports()
    epm = _epmapper_flow("atk-dcsync-epm", attacker, dc, next(sp), start_time, env.default_client_os)
    # drsuapi rides ncacn_ip_tcp on a dynamic port (resolved via the epmapper lookup). The full
    # Empire/Covenant DCSync sequence, matched to a real capture (OTRF empire_dcsync): bind, locate
    # the DC (DRSDomainControllerInfo), resolve the target principal (DRSCrackNames), re-bind, then
    # DRSGetNCChanges (the replication that dumps the secret) and unbind.
    ops = [0, 16, 12, 0, 3, 1]
    names = ["DRSBind", "DRSDomainControllerInfo", "DRSCrackNames", "DRSBind",
             "DRSGetNCChanges", "DRSUnbind"]
    drs = _dcerpc_flow("atk-dcsync-drs", attacker, dc, next(sp), start_time + 0.2,
                       pipe="drsuapi", interface="drsuapi", share="",
                       operations=ops, op_names=names,
                       src_os=env.default_client_os, dst_port=49200, transport="ncacn_ip_tcp")
    gt = [GroundTruthEntry(
        "Credential Access", "T1003.006 OS Credential Dumping: DCSync",
        ["atk-dcsync-epm", "atk-dcsync-drs"],
        f"DCSync against DC {dc}: an epmapper lookup then drsuapi DRSGetNCChanges from non-DC "
        f"host {attacker} — directory replication of secrets. Inert (zero stubs, no secrets).",
        {"attacker": attacker, "target": dc,
         "dce_rpc": {"endpoint": "drsuapi", "operations": ["DRSGetNCChanges"]}})]
    return Intrusion([epm, drs], gt, f"DCSync against {dc}",
                     {"attacker": attacker, "target": dc})


def build_remote_registry(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Remote registry modification over \\winreg — T1112."""
    attacker, target = _hosts(env, 2)
    sp = _sports()
    flow = _dcerpc_flow("atk-winreg-01", attacker, target, next(sp), start_time,
                        pipe="winreg", interface="winreg", share=f"\\\\{target}\\IPC$",
                        operations=[6, 22], op_names=["BaseRegCreateKey", "BaseRegSetValue"],
                        src_os=env.default_client_os)
    gt = [GroundTruthEntry(
        "Defense Evasion", "T1112 Modify Registry",
        ["atk-winreg-01"],
        f"Remote registry modification on {target}: winreg BaseRegCreateKey -> BaseRegSetValue.",
        {"attacker": attacker, "target": target, "pipe": "winreg",
         "dce_rpc": {"endpoint": "winreg", "operations": ["BaseRegCreateKey", "BaseRegSetValue"]},
         # Generic winreg writes are not a BZAR-detected technique; the detection is the
         # dce_rpc.log winreg operation itself (a defender's own rule keys on it).
         "detection": "dce_rpc.log winreg BaseRegCreateKey/BaseRegSetValue"})]
    return Intrusion([flow], gt, f"Remote registry write on {target}",
                     {"attacker": attacker, "target": target})


def build_psexec_lateral(env: Environment, start_time: float, rng, *, intensity: float = 1.0) -> Intrusion:
    """Co-detect: admin-share tool transfer + remote service creation, same target.

    The combination BZAR raises a single ``ATTACK::Lateral_Movement`` on: an ADMIN$ file
    staging followed by svcctl service creation/start against the same host (classic
    PsExec). Both flows are inert.
    """
    attacker, target = _hosts(env, 2)
    sp = _sports()
    drop = Flow(flow_id="atk-psexec-drop", transport="tcp", src_ip=attacker, dst_ip=target,
                src_port=next(sp), dst_port=445, start_time=start_time, conn_state="SF",
                src_os=env.default_client_os,
                l7=SmbL7(share=f"\\\\{target}\\ADMIN$", write_file="svc.exe", file_bytes=6144))
    epm = _epmapper_flow("atk-psexec-epm", attacker, target, next(sp), start_time + 2.8,
                         env.default_client_os)
    svc = _dcerpc_flow("atk-psexec-svc", attacker, target, next(sp), start_time + 3.0,
                       pipe="svcctl", interface="svcctl", share=f"\\\\{target}\\IPC$",
                       operations=_SVCCTL_CREATE_START[0], op_names=_SVCCTL_CREATE_START[1],
                       src_os=env.default_client_os)
    gt = [GroundTruthEntry(
        "Lateral Movement", "T1021.002 SMB/Windows Admin Shares / T1570 / T1569.002 Service Execution",
        ["atk-psexec-drop", "atk-psexec-svc"],
        f"PsExec-style lateral movement to {target}: ADMIN$ tool transfer (SMB write of svc.exe) "
        f"then svcctl CreateServiceW/StartServiceW — the combination BZAR flags.",
        {"attacker": attacker, "target": target,
         "smb_files": {"share": "ADMIN$", "name": "svc.exe"},
         "dce_rpc": {"endpoint": "svcctl", "operations": ["CreateServiceW", "StartServiceW"]},
         # ADMIN$ write (score 1) + RPC exec (score 1000) to the same host -> BZAR's combined notice.
         "expected_notice": "ATTACK::Lateral_Movement_and_Execution"})]
    return Intrusion([drop, epm, svc], gt, f"PsExec-style lateral movement to {target}",
                     {"attacker": attacker, "target": target})


# The BZAR lateral-movement pack — the attacks added by this content pack. Kept as a
# named set so the pack's inert-invariant and Zeek round-trip tests can iterate it.
BZAR_PACK = {
    "remote-service": build_remote_service,
    "scheduled-task": build_scheduled_task,
    "wmi-exec": build_wmi_exec,
    "admin-share-transfer": build_admin_share_transfer,
    "share-discovery": build_share_discovery,
    "account-discovery": build_account_discovery,
    "remote-registry": build_remote_registry,
    "psexec-lateral": build_psexec_lateral,
}


ATTACKS = {
    "phishing-intrusion": build_intrusion,
    "dns-exfil": build_dns_exfil,
    "doh-tunnel": build_doh_tunnel,
    "dot-tunnel": build_dot_tunnel,
    "llmnr-poisoning": build_llmnr_poisoning,
    "ipv6-c2": build_ipv6_c2,
    "imds-ssrf": build_imds_ssrf,
    "cloud-exfil": build_cloud_exfil,
    "k8s-lateral": build_k8s_lateral,
    "ddos-syn-flood": build_ddos_syn_flood,
    "port-scan": build_port_scan,
    "brute-force": build_brute_force,
    "ransomware": build_ransomware,
    "kerberoasting": build_kerberoasting,
    "asrep-roasting": build_asrep_roasting,
    "dcsync": build_dcsync,
    **BZAR_PACK,
}


def list_attacks() -> list:
    return sorted(ATTACKS)


# --------------------------------------------------------------------------- #
# Evasion modifiers — mutate an Intrusion so a naive IOC misses it, while the  #
# ground-truth technique is unchanged. This is how we *measure* rule           #
# robustness: run the same rule on the clean vs evasive capture (Phase B).     #
# Each modifier is a pure flow-field mutation, so captures stay Zeek-clean.    #
# --------------------------------------------------------------------------- #
from packetforge.models.flowspec import TlsL7 as _TlsL7  # noqa: E402

_FRONT_DOMAINS = ["d3akx9f2p1qz.cloudfront.net", "ajax.googleapis.com",
                  "cdn.jsdelivr.net", "s3.amazonaws.com", "cdnjs.cloudflare.com"]
_ALT_C2_PORTS = [8443, 4443, 2087, 8883, 9443]


def _c2_tls_flows(intr: Intrusion) -> list:
    """The intrusion's C2/HTTPS beacon flows (TLS whose SNI is the C2 domain)."""
    c2 = intr.iocs.get("c2_domain")
    return [f for f in intr.flows
            if isinstance(f.l7, _TlsL7) and (c2 is None or f.l7.server_name == c2)]


def _evade_domain_fronting(intr: Intrusion, rng) -> None:
    """SNI -> a benign CDN front; the real C2 destination IP is unchanged.

    Defeats SNI/domain blocklists (the most common TLS C2 rule). Only IP-reputation,
    JA3, or behavioral detection still sees it — exactly the brittleness to quantify.
    """
    fronted = []
    for f in _c2_tls_flows(intr):
        f.l7 = f.l7.model_copy(update={"server_name": rng.choice(_FRONT_DOMAINS)})
        fronted.append(f.flow_id)
    if fronted:
        intr.iocs["fronted_flows"] = len(fronted)
        intr.iocs["note_domain_fronting"] = "TLS SNI is a benign CDN; C2 is the dest IP"


def _evade_ja3_randomization(intr: Intrusion, rng) -> None:
    """Rotate the TLS client profile across beacons so JA3 is not a stable IOC."""
    profiles = ["generic_browser", "curl"]
    for f in _c2_tls_flows(intr):
        f.l7 = f.l7.model_copy(update={"client_profile": rng.choice(profiles)})
    intr.iocs["note_ja3_randomization"] = "beacon JA3 rotates; a single-hash IOC misses"


def _evade_port_hopping(intr: Intrusion, rng) -> None:
    """Move C2/HTTPS beacons off 443 to a non-standard TLS port."""
    port = rng.choice(_ALT_C2_PORTS)
    for f in _c2_tls_flows(intr):
        f.dst_port = port
    intr.iocs["note_port_hopping"] = f"C2 on tcp/{port} (not 443)"


def _evade_slow_and_low(intr: Intrusion, rng) -> None:
    """Stretch the storyline's timeline so rate/volume heuristics fall below threshold."""
    if not intr.flows:
        return
    t0 = min(f.start_time for f in intr.flows)
    stretch = 12.0  # ~12x slower cadence
    for f in intr.flows:
        f.start_time = t0 + (f.start_time - t0) * stretch
    intr.iocs["note_slow_and_low"] = f"inter-event gaps stretched {int(stretch)}x"


def _evade_dns_depth(intr: Intrusion, rng) -> None:
    """Deepen DNS-tunnel labels (longer, chunked subdomains) to look less anomalous
    to length heuristics while carrying the same payload."""
    from packetforge.models.flowspec import DnsL7
    changed = 0
    for f in intr.flows:
        if isinstance(f.l7, DnsL7) and f.dst_port == 53 and "." in f.l7.qname:
            head, _, tail = f.l7.qname.partition(".")
            chunked = ".".join(head[i:i + 15] for i in range(0, len(head), 15)) or head
            f.l7 = f.l7.model_copy(update={"qname": f"{chunked}.{tail}"})
            changed += 1
    if changed:
        intr.iocs["note_dns_depth"] = "tunnel labels chunked into multiple short subdomains"


EVASIONS = {
    "domain-fronting": _evade_domain_fronting,
    "ja3-randomization": _evade_ja3_randomization,
    "port-hopping": _evade_port_hopping,
    "slow-and-low": _evade_slow_and_low,
    "dns-depth": _evade_dns_depth,
}


def list_evasions() -> list:
    return sorted(EVASIONS)


def build_attack(name: str, env: Environment, start_time: float, rng, *,
                 intensity: float = 1.0, evasions=()) -> Intrusion:
    if name not in ATTACKS:
        raise ValueError(f"unknown attack {name!r}; available: {list_attacks()}")
    intr = ATTACKS[name](env, start_time, rng, intensity=intensity)
    for ev in evasions:
        if ev not in EVASIONS:
            raise ValueError(f"unknown evasion {ev!r}; available: {list_evasions()}")
        EVASIONS[ev](intr, rng)
        intr.evasions.append(ev)
    return intr
