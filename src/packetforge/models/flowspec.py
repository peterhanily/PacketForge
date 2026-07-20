# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The Flow IR — PacketForge's versioned contract.

A ``FlowSet`` fully describes the packet-level story of one or more network flows:
enough to render bytes, and nothing about *why* the flow happened. EvidenceForge
(later) emits this from its canonical ``SecurityEvent``; PacketForge compiles it to a
``.pcap``. Because both derive from the same source event, the packets and
EvidenceForge's logs are consistent by construction — and the round-trip validator
proves it.

Design notes:
- Typed with pydantic v2, mirroring EvidenceForge's modeling approach.
- ``list[...]`` builtins are used, but runtime ``X | None`` unions are avoided so the
  module also imports on Python 3.9 (the package targets 3.11+ for merge parity).
- L7 payloads are a discriminated union on ``kind``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "0.1"

# --------------------------------------------------------------------------- #
# L7 payload specs — one per protocol family. Discriminated by ``kind``.       #
# --------------------------------------------------------------------------- #


class _L7Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DnsL7(_L7Base):
    """A DNS query and (optionally) its response, over UDP."""

    kind: Literal["dns"] = "dns"
    qname: str
    qtype: str = "A"  # any DNS type name; answer RRs are rendered for A/AAAA
    answers: list[str] = Field(default_factory=list)
    rcode: str = "NOERROR"  # DNS rcode name, e.g. NOERROR / NXDOMAIN / SERVFAIL
    respond: bool = True


class HttpL7(_L7Base):
    """A single cleartext HTTP request/response over TCP."""

    kind: Literal["http"] = "http"
    method: str = "GET"  # any HTTP method (GET, POST, CONNECT, ...)
    uri: str = "/"
    host: str = ""
    user_agent: str = "Mozilla/5.0"
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body_len: int = 0
    status: int = 200
    reason: str = ""
    response_headers: dict[str, str] = Field(default_factory=dict)
    # Response body: either an explicit base64 blob or a deterministic filler of N bytes.
    response_body_len: int = 0
    response_body_b64: Optional[str] = None


class TlsL7(_L7Base):
    """A TLS session: real handshake (JA3 driven by client profile) + opaque app data."""

    kind: Literal["tls"] = "tls"
    server_name: str
    version: Literal["TLS1.2", "TLS1.3"] = "TLS1.2"
    client_profile: str = "generic_browser"  # -> fingerprints/ja3/<profile>.yaml
    ja3: Optional[str] = None  # explicit JA3 string to reproduce (overrides client_profile)
    server_cipher: Optional[int] = None  # override the negotiated cipher (IANA id)
    # ALPN protocols the ClientHello advertises (e.g. ["h2","http/1.1"], ["dot"], ["h3"]).
    # None -> the browser default. Zeek records the first as ssl.log `next_protocol`.
    alpn: Optional[list[str]] = None
    app_data_orig_bytes: int = 0
    app_data_resp_bytes: int = 0


class IcmpL7(_L7Base):
    """ICMP echo request/reply pairs."""

    kind: Literal["icmp"] = "icmp"
    icmp_type: Literal["echo"] = "echo"
    count: int = 1
    payload_len: int = 56


class SmtpL7(_L7Base):
    """A cleartext SMTP delivery conversation over TCP."""

    kind: Literal["smtp"] = "smtp"
    helo: str = "client.example"
    mail_from: str
    rcpt_to: list[str]
    subject: str = ""
    from_header: str = ""
    to_header: str = ""
    body_len: int = 200
    server_banner: str = "mail.example ESMTP Postfix"


class OpaqueTcpL7(_L7Base):
    """An honest opaque TCP shell for binary protocols (SMB/Kerberos/RDP/...).

    Correct handshake, teardown, and volumetrics; application bytes are opaque and
    sized. No L7 dissection is claimed — a sensor without the right dissector sees
    the same thing.
    """

    kind: Literal["opaque_tcp"] = "opaque_tcp"
    service_hint: str = ""  # documentation only, e.g. "smb", "kerberos"
    orig_bytes: int = 0
    resp_bytes: int = 0
    segments: int = 1  # how many data segments per direction
    # Optional hex-encoded literal bytes placed at the START of the originator payload.
    # Used only by the signature-conditioning engine to trip a specific content-based IDS
    # rule (e.g. an MSN `CAL ` command) with an otherwise-opaque, inert flow.
    orig_literal_hex: Optional[str] = None


class OpaqueUdpL7(_L7Base):
    """An opaque UDP exchange for non-DNS UDP services (kerberos, dhcp, ntp, ...)."""

    kind: Literal["opaque_udp"] = "opaque_udp"
    service_hint: str = ""
    orig_bytes: int = 0
    resp_bytes: int = 0
    # Optional hex-encoded literal bytes placed at the START of the originator datagram —
    # used by the signature-conditioning engine to trip a content-based UDP rule (e.g. a
    # Dropbox LAN-sync broadcast) with an inert flow.
    orig_literal_hex: Optional[str] = None


class DhcpL7(_L7Base):
    """A DHCP DORA (Discover/Offer/Request/Ack) exchange."""

    kind: Literal["dhcp"] = "dhcp"
    assigned_ip: str
    server_ip: str
    gateway: str = ""
    dns_server: str = ""
    lease_time: int = 3600
    subnet_mask: str = "255.255.255.0"
    hostname: str = ""


class NtpL7(_L7Base):
    """An NTP client/server time exchange."""

    kind: Literal["ntp"] = "ntp"
    version: int = 4
    stratum: int = 2
    count: int = 1


class SshL7(_L7Base):
    """An SSH connection: cleartext version banners + KEXINIT, then opaque."""

    kind: Literal["ssh"] = "ssh"
    client_version: str = "SSH-2.0-OpenSSH_9.6"
    server_version: str = "SSH-2.0-OpenSSH_9.6"
    payload_bytes: int = 2000  # opaque encrypted traffic after key exchange


class FtpL7(_L7Base):
    """A cleartext FTP control session.

    If ``retrieve_file`` is set, the session enters passive mode and RETRs the file over
    a second (data) connection carrying real, typed content — recoverable by following
    the ftp-data stream and logged by Zeek's ``files.log``.
    """

    kind: Literal["ftp"] = "ftp"
    user: str = "anonymous"
    password: str = "anonymous@"
    commands: list[str] = Field(default_factory=lambda: ["SYST", "PWD", "TYPE I"])
    banner: str = "220 (vsFTPd 3.0.5)"
    retrieve_file: str = ""  # e.g. "backup.zip"; empty = control session only
    file_bytes: int = 4096


class SnmpL7(_L7Base):
    """An SNMP get/response exchange."""

    kind: Literal["snmp"] = "snmp"
    community: str = "public"
    oid: str = "1.3.6.1.2.1.1.1.0"
    value: str = "PacketForge device"
    count: int = 1


class ModbusL7(_L7Base):
    """A Modbus/TCP read-holding-registers exchange (OT/ICS)."""

    kind: Literal["modbus"] = "modbus"
    unit_id: int = 1
    start_addr: int = 0
    quantity: int = 10
    count: int = 1


class RadiusL7(_L7Base):
    """A RADIUS Access-Request / Access-Accept exchange."""

    kind: Literal["radius"] = "radius"
    username: str = "alice"
    accept: bool = True


class LdapL7(_L7Base):
    """An LDAP bind (+ optional search) — the AD directory workhorse."""

    kind: Literal["ldap"] = "ldap"
    bind_dn: str = "CN=svc,DC=corp,DC=local"
    password: str = "Passw0rd"
    searches: list[str] = Field(default_factory=list)  # base DNs to search


class NameQueryL7(_L7Base):
    """A broadcast/multicast name-resolution query, and optionally a *poisoned* answer.

    LLMNR (udp/5355, 224.0.0.252), NBT-NS (udp/137, subnet broadcast), and mDNS (udp/5353,
    224.0.0.251) let a host resolve a name its DNS server didn't answer — by asking every
    host on the segment. An attacker (Responder-style) races a spoofed reply that claims a
    name for its own IP, becoming the machine-in-the-middle (T1557.001). Set ``poison_from``
    to the attacker IP to render that reply; Zeek logs both to ``dns.log`` (the poisoned
    answer's rdata is the attacker's address)."""

    kind: Literal["namequery"] = "namequery"
    protocol: Literal["llmnr", "nbns", "mdns"] = "llmnr"
    qname: str
    qtype: str = "A"
    poison_from: Optional[str] = None  # attacker IP that answers with a spoofed reply


class NtlmAuth(_L7Base):
    """An inert NTLMSSP handshake carried in the SMB2 session setup — the credential a
    Responder-style LLMNR/NBT-NS poisoner captures off the wire (T1557.001).

    When set on an :class:`SmbL7` flow, the session setup renders the real three-message
    NTLMSSP exchange (NEGOTIATE -> CHALLENGE -> AUTHENTICATE) in place of an empty setup,
    so Zeek's ``ntlm.log`` reads back the victim's ``domainname``/``username`` and
    ``hostname`` (workstation) — the capture payoff of the poisoning story.

    Inert by construction: the LM/NT challenge responses are fixed filler bytes, never a
    real (offline-crackable) NTLMv2 hash. Only the identity fields and the on-wire framing
    are real. The blob is raw NTLMSSP (the signature Zeek's NTLM analyzer keys on), not a
    hash a defender could relay or crack.

    Scope: the security blob carries raw NTLMSSP, not a GSS-API/SPNEGO envelope, so Zeek
    reads back every identity field (username/domainname/hostname/server_nb_computer_name)
    but leaves ``ntlm.log`` ``success`` unset — that column is populated only from a SPNEGO
    ``gssapi_neg_result``. The captured credential (the detection payoff) is fully present.
    """

    domain: str = "CORP"          # victim's account domain (NetBIOS) -> ntlm.log domainname
    user: str = "jdoe"            # victim's sAMAccountName -> ntlm.log username (the credential)
    workstation: str = "WKS-01"   # victim's machine name -> ntlm.log hostname
    server_domain: str = "CORP"   # name the rogue server claims in the CHALLENGE TargetInfo
    server_host: str = "FILESRV"  # rogue server's NetBIOS computer name (CHALLENGE)


class SmbL7(_L7Base):
    """An SMB2/3 session: negotiate -> session setup -> tree connect to a share.

    If ``read_file`` is set, the session goes on to CREATE/READ/CLOSE that file, and the
    READ carries real file content (typed by extension) that Wireshark's "Export Objects
    > SMB" and Zeek's ``smb_files.log`` can pull out. If ``write_file`` is set, the session
    CREATE/WRITE/CLOSEs it instead, sending the (inert, typed) content originator->responder
    so Zeek logs an ``SMB::FILE_WRITE`` — the lateral-tool-transfer signal (T1570).

    If ``ntlm`` is set, the session setup renders a real NTLMSSP exchange so Zeek populates
    ``ntlm.log`` with the captured ``domain``/``user`` — the LLMNR-poisoning payoff.
    """

    kind: Literal["smb"] = "smb"
    share: str = "\\\\FILESRV\\Share"
    dialect: int = 0x0300  # SMB 3.0
    read_file: str = ""  # e.g. "payroll.xlsx"; empty = session only (no file transfer)
    write_file: str = ""  # e.g. "svc.exe"; empty = no write. A push to the share (FILE_WRITE)
    file_bytes: int = 4096  # size of the file content read/written
    ntlm: Optional[NtlmAuth] = None  # if set, render an NTLMSSP session setup -> ntlm.log


class DceRpcL7(_L7Base):
    """DCE-RPC over an SMB named pipe — the MS-RPC lateral-movement workhorse.

    Renders the on-the-wire *shape* of a remote MS-RPC operation: the SMB2 named-pipe
    setup (tree connect to ``IPC$`` -> create ``\\<pipe>``), a DCE-RPC bind to a
    well-known interface (svcctl/atsvc/srvsvc/samr/winreg/...), and one request/response
    per operation. Real Zeek reads back the interface (``endpoint``) and each
    ``operation`` in ``dce_rpc.log`` — the exact signal an analytic like BZAR keys on for
    remote service creation, scheduled tasks, WMI, share/account discovery, etc.

    Inert by construction: the request/response stubs are opaque filler, never real
    operation arguments (no service binary/path, command line, task XML, or registry
    payload). There are deliberately **no argument fields** — ``operations`` are DCE-RPC
    opnums (ints) and ``op_names`` are human labels with no effect on the emitted bytes.
    """

    kind: Literal["dcerpc"] = "dcerpc"
    share: str = "\\\\HOST\\IPC$"
    pipe: str = "svcctl"  # named pipe opened over IPC$ (e.g. svcctl, atsvc, winreg)
    interface: str = "svcctl"  # well-known interface name -> UUID/version in the renderer
    operations: list[int] = Field(default_factory=list)  # DCE-RPC opnums, in call order
    op_names: list[str] = Field(default_factory=list)  # labels only; no wire effect
    # Transport binding. "ncacn_np" (default): DCE-RPC over the SMB named pipe. "ncacn_ip_tcp":
    # DCE-RPC directly over TCP with no SMB wrapping — e.g. the endpoint mapper (epmapper) on
    # port 135, which real tools ept_map before the service call.
    transport: Literal["ncacn_np", "ncacn_ip_tcp"] = "ncacn_np"


class KerberosL7(_L7Base):
    """A Kerberos AS or TGS exchange over TCP/88 (drives Zeek ``kerberos.log``).

    One flow renders one request+reply. Faithful enough that real Zeek logs the
    request type, client, service (SPN), and the ticket ``cipher`` — so an **RC4
    downgrade** (``etype`` 23), the on-the-wire signal Kerberoasting and AS-REP
    roasting depend on, is visible and detectable. We hold no KDC keys, so the
    encrypted blobs are opaque and sized; the ASN.1 envelope and the enctype are real.
    """

    kind: Literal["kerberos"] = "kerberos"
    request_type: Literal["AS", "TGS"] = "AS"
    client: str = "alice"  # sAMAccountName of the requesting principal
    realm: str = "CORP.EXAMPLE"
    service: str = ""  # SPN; empty AS -> krbtgt/<realm>, empty TGS -> host/<realm>
    # Reply ticket encryption type: 18=AES256, 17=AES128, 23=RC4-HMAC (the downgrade).
    etype: int = 18
    request_etypes: list[int] = Field(default_factory=lambda: [18, 17, 23])
    preauth: bool = True  # AS only: PA-ENC-TIMESTAMP present (False = AS-REP roastable)
    success: bool = True


class Pop3L7(_L7Base):
    """A cleartext POP3 mail-retrieval session."""

    kind: Literal["pop3"] = "pop3"
    user: str = "bob"
    password: str = "secret"


class ImapL7(_L7Base):
    """A cleartext IMAP session."""

    kind: Literal["imap"] = "imap"
    user: str = "bob"
    password: str = "secret"


class IrcL7(_L7Base):
    """An IRC session (classic C2 channel)."""

    kind: Literal["irc"] = "irc"
    nick: str = "user"
    channel: str = "#chat"


class SipL7(_L7Base):
    """A SIP request/response over UDP (VoIP signalling)."""

    kind: Literal["sip"] = "sip"
    user: str = "bob"
    domain: str = "example.com"
    method: Literal["REGISTER", "INVITE", "OPTIONS"] = "REGISTER"


L7Spec = Annotated[
    Union[DnsL7, HttpL7, TlsL7, SmtpL7, IcmpL7, OpaqueTcpL7, OpaqueUdpL7,
          DhcpL7, NtpL7, SshL7, FtpL7, SnmpL7, ModbusL7, RadiusL7, LdapL7, SmbL7,
          DceRpcL7, NameQueryL7, KerberosL7, Pop3L7, ImapL7, IrcL7, SipL7],
    Field(discriminator="kind"),
]


# --------------------------------------------------------------------------- #
# Flow + FlowSet                                                               #
# --------------------------------------------------------------------------- #


class ExpectZeek(BaseModel):
    """Optional author/emitter-declared ground truth, asserted by the validator.

    Any field left unset is simply not checked. The renderer also computes a
    *measured* summary from the emitted packets; the validator checks Zeek against
    both.
    """

    model_config = ConfigDict(extra="forbid")

    service: Optional[str] = None
    conn_state: Optional[str] = None
    history: Optional[str] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    orig_pkts: Optional[int] = None
    resp_pkts: Optional[int] = None


class Flow(BaseModel):
    """One network flow: a 5-tuple, timing, endpoints' OS, and an L7 payload."""

    model_config = ConfigDict(extra="forbid")

    flow_id: str = Field(description="Stable identity; seeds all deterministic fields.")
    transport: Literal["tcp", "udp", "icmp"]
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    start_time: float = Field(description="Epoch seconds of the first packet.")
    src_os: str = "windows_10"  # -> fingerprints/tcp/<os>.yaml
    dst_os: str = "linux"
    # Optional per-flow overrides of the originator's SYN window / TTL. Reference-
    # conditioning uses these to draw from a real capture's measured distributions so the
    # synthetic matches its fingerprint marginals, rather than the OS-profile defaults.
    syn_window: Optional[int] = None
    syn_ttl: Optional[int] = None
    # Effective on-the-wire segment size (bytes). Real captures are taken above NIC offload
    # (GRO/LSO), so a large transfer appears as fewer, larger-than-MSS segments; conditioning
    # this to the reference's bytes-per-packet matches its packet counts (orig_pkts, resp_bpp).
    seg_bytes: Optional[int] = None
    rtt: float = 0.03  # seconds; used to space handshake/data/teardown
    # Exact target duration (seconds) for the flow. When set, the compiler linearly rescales the
    # rendered packet timestamps so real Zeek recomputes exactly this conn.log duration. Lets a
    # flow carry a duration from an upstream source of truth (e.g. an EvidenceForge event whose
    # own logs assert that duration) so the pcap agrees with it instead of diverging.
    duration: Optional[float] = None
    conn_state: str = "SF"  # target Zeek conn_state for TCP flows
    l7: L7Spec
    expect: Optional[ExpectZeek] = None
    # IDS signatures this flow is expected to trip. For benign flows this is the modeled
    # false-positive surface (the ET rules real benign apps set off); it is ground truth a
    # detection test can assert on, not just incidental noise.
    expected_alert: list[int] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_transport_matches_l7(self) -> "Flow":
        kind = self.l7.kind
        expected = {
            "dns": {"udp", "tcp"},
            "http": {"tcp"},
            "tls": {"tcp"},
            "smtp": {"tcp"},
            "icmp": {"icmp"},
            "opaque_tcp": {"tcp"},
            "opaque_udp": {"udp"},
            "dhcp": {"udp"},
            "ntp": {"udp"},
            "ssh": {"tcp"},
            "ftp": {"tcp"},
            "snmp": {"udp"},
            "modbus": {"tcp"},
            "radius": {"udp"},
            "ldap": {"tcp"},
            "smb": {"tcp"},
            "dcerpc": {"tcp"},
            "namequery": {"udp"},
            "kerberos": {"tcp"},
            "pop3": {"tcp"},
            "imap": {"tcp"},
            "irc": {"tcp"},
            "sip": {"udp"},
        }[kind]
        if self.transport not in expected:
            raise ValueError(
                f"L7 kind '{kind}' requires transport in {sorted(expected)}, "
                f"got '{self.transport}' (flow_id={self.flow_id})"
            )
        if self.transport == "icmp" and (self.src_port or self.dst_port):
            raise ValueError(f"icmp flow must not set ports (flow_id={self.flow_id})")
        return self


class CaptureMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = ""
    # ethernet = a SPAN/TAP or LAN capture; linux_sll = a host-side tcpdump (cooked).
    link_type: Literal["ethernet", "linux_sll"] = "ethernet"
    snaplen: int = 262144
    mac_oui: Optional[str] = None  # 3-octet vendor prefix for internal host MACs
    # clean = byte-exact ideal flows; realistic = RTT jitter + retransmits + dup-ACKs
    # (still Zeek-clean; the reassembled stream and seq-based byte counts are unchanged).
    texture: Literal["clean", "realistic", "conditioned"] = "clean"


class FlowSet(BaseModel):
    """The top-level IR document: a schema-versioned set of flows to render."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    capture: CaptureMeta = Field(default_factory=CaptureMeta)
    flows: list[Flow]

    @model_validator(mode="after")
    def _check_version(self) -> "FlowSet":
        major = self.schema_version.split(".")[0]
        if major != SCHEMA_VERSION.split(".")[0]:
            raise ValueError(
                f"FlowSet schema_version {self.schema_version!r} is incompatible with "
                f"supported {SCHEMA_VERSION!r} (major version mismatch)"
            )
        return self


def load_flowset(path: str | Path) -> FlowSet:
    """Load a FlowSet from a YAML or JSON file."""
    import json

    import yaml

    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) if str(path).endswith((".yaml", ".yml")) else json.loads(text)
    return FlowSet.model_validate(data)
