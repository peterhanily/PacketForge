# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Multi-vantage capture: one rendered incident, seen from several sensor placements.

The same flows look different depending on *where* the sensor sits. An edge TAP on the
WAN side sees source-NAT (every internal host collapsed to one public IP) and one-lower
TTL after the router hop; a core-switch SPAN on a trunk sees 802.1Q VLAN tags; a host
``tcpdump`` sees only that host's own packets, as a cooked (Linux SLL) capture with no
peer MAC. Rendering the incident once and projecting it through each ``Vantage`` lets a
defender ask the question real SOCs get wrong — *does my detection fire given where my
sensors actually are?* — instead of assuming a single omniscient capture.

Each projection is a pure, deterministic packet transform (no new randomness); every
vantage's output is an independent, Zeek-clean pcap of the same event.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

import hashlib

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import CookedLinux, Dot1Q, Ether
from scapy.layers.vxlan import VXLAN
from scapy.packet import Packet, Raw
from scapy.utils import mac2str


@dataclass(frozen=True)
class Vantage:
    """One sensor placement and what it does to the packets that reach it."""

    name: str
    link_type: str = "ethernet"          # "ethernet" (SPAN/TAP) | "linux_sll" (host tcpdump)
    hops: int = 0                        # router hops downstream -> TTL/hop-limit decrement
    vlan: Optional[int] = None           # 802.1Q tag a trunk port would see
    nat_subnet: Optional[str] = None     # CIDR of internal addresses source-NAT'd...
    nat_public: Optional[str] = None     # ...to this public IP (an edge/WAN-side sensor)
    sees_host: Optional[str] = None      # host tcpdump: keep only packets touching this IP
    # VXLAN encapsulation: a VPC Traffic Mirror / GCP Packet Mirror / K8s CNI overlay wraps
    # each frame in Ether/IP/UDP(4789)/VXLAN and ships it to a collector VTEP. Zeek decaps it
    # and logs the inner conn plus a tunnel.log entry.
    vxlan_vni: Optional[int] = None
    vxlan_src: str = "10.0.0.5"          # source VTEP (mirror source / local node)
    vxlan_dst: str = "10.0.0.99"         # collector VTEP (remote node / mirror target)


def _in_subnet(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _project_ip(pkt: Packet, v: Vantage, net) -> None:
    """Apply TTL decrement + source-NAT to the IP layer in place (fields recomputed later)."""
    if IP not in pkt:
        return
    ip = pkt[IP]
    touched = False
    if v.hops:
        ip.ttl = max(1, ip.ttl - v.hops)
        touched = True
    if net is not None and v.nat_public:
        # Source-NAT: an internal host is seen as the public IP from the WAN side (in both
        # directions), so an edge sensor cannot tell which internal host it was.
        if _in_subnet(ip.src, net):
            ip.src = v.nat_public
            touched = True
        if _in_subnet(ip.dst, net):
            ip.dst = v.nat_public
            touched = True
    if touched:
        # Force recomputation of lengths/checksums on the next serialization.
        del ip.len
        del ip.chksum
        if TCP in pkt:
            del pkt[TCP].chksum
        if UDP in pkt:
            del pkt[UDP].chksum


def _to_sll(pkt: Packet) -> Packet:
    """Ethernet frame -> Linux SLL (cooked), as a host-side tcpdump yields (no dest MAC)."""
    if Ether not in pkt:
        return pkt
    eth = pkt[Ether]
    sll = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=mac2str(eth.src), proto=eth.type) / eth.payload
    sll.time = pkt.time
    return sll


_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")


def _is_link_local(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in _LINK_LOCAL
    except ValueError:
        return False


def render_vantage(packets: list, v: Vantage) -> list:
    """Project a rendered packet list through one vantage -> that sensor's packet list."""
    net = ipaddress.ip_network(v.nat_subnet, strict=False) if v.nat_subnet else None
    out: list = []
    for p in packets:
        if v.sees_host and IP in p and v.sees_host not in (p[IP].src, p[IP].dst):
            continue  # a host sensor never sees flows it is not an endpoint of
        # A traffic mirror / CNI overlay never carries link-local (169.254/16): the instance
        # metadata service is host-terminated and link-scoped, so IMDS/SSRF traffic can't traverse
        # a mirrorable or overlay path — it appears only on an on-host vantage. (AWS VPC Traffic
        # Mirroring / GCP Packet Mirroring exclude 169.254/16 by construction.)
        if v.vxlan_vni is not None and IP in p and (_is_link_local(p[IP].src) or _is_link_local(p[IP].dst)):
            continue
        q = p.copy()
        _project_ip(q, v, net)
        if v.vlan is not None and Ether in q:
            eth = q[Ether]
            q = (Ether(src=eth.src, dst=eth.dst, type=0x8100)
                 / Dot1Q(vlan=v.vlan, type=eth.type) / eth.payload)
        # Reserialize so deleted lengths/checksums are recomputed; keep the capture time.
        t = float(p.time)
        q = Ether(bytes(q)) if Ether in q else q.__class__(bytes(q))
        q.time = t
        if v.vxlan_vni is not None and Ether in q:
            q = _vxlan_wrap(q, v)  # a mirror/overlay ships the whole frame to a collector VTEP
        elif v.link_type == "linux_sll":
            q = _to_sll(q)
        out.append(q)
    return out


def _vxlan_wrap(inner: Packet, v: Vantage) -> Packet:
    """Encapsulate an Ethernet frame in Ether/IP/UDP(4789)/VXLAN, as a mirror or CNI overlay
    does. The outer UDP source port is a deterministic hash of the inner flow (real VTEPs set
    it from the inner headers for load-balancing entropy)."""
    inner_bytes = bytes(inner)
    sport = 0xC000 | (int.from_bytes(hashlib.sha256(inner_bytes[:34]).digest()[:2], "big") & 0x3FFF)
    # Carry the inner frame as raw bytes: letting scapy re-serialize a parsed inner Ethernet
    # packet inside VXLAN subtly rewrites it (Zeek then flags truncated_IP_len_in_tunnel).
    outer = (Ether(src="02:00:5e:00:53:01", dst="02:00:5e:00:53:02")
             / IP(src=v.vxlan_src, dst=v.vxlan_dst)
             / UDP(sport=sport, dport=4789) / VXLAN(vni=v.vxlan_vni, flags=0x08) / Raw(inner_bytes))
    # Re-parse to normalize lengths/checksums, then stamp the capture time — setting it on
    # `outer` before this re-parse would be lost, leaving scapy to fill wall-clock (nondeterministic).
    wrapped = Ether(bytes(outer))
    wrapped.time = inner.time
    return wrapped


def render_vantages(packets: list, vantages: list) -> dict:
    """Project one rendered incident through every vantage -> {name: packets}."""
    return {v.name: render_vantage(packets, v) for v in vantages}


def standard_vantages(subnet: str, host: Optional[str] = None, *,
                      public_ip: str = "203.0.113.10", vlan: int = 10) -> list:
    """The three sensors a typical enterprise runs, derived from the internal subnet.

    - ``edge-tap``: WAN-side TAP — source-NAT to a public IP, one router hop away.
    - ``core-span``: core-switch SPAN on a trunk — 802.1Q tagged, no NAT.
    - ``host-<ip>``: a host tcpdump — only that host's flows, cooked capture. Added when
      ``host`` is given (e.g. the storyline's victim), so you can see exactly what an
      endpoint sensor would and would not have.
    """
    vs = [
        Vantage("edge-tap", link_type="ethernet", hops=1,
                nat_subnet=subnet, nat_public=public_ip),
        Vantage("core-span", link_type="ethernet", vlan=vlan),
    ]
    if host:
        vs.append(Vantage(f"host-{host}", link_type="linux_sll", sees_host=host))
    return vs


def mirror_vantage(vni: int = 5001, *, collector: str = "10.0.0.99", source: str = "10.0.0.5") -> Vantage:
    """A cloud traffic-mirror session — AWS VPC Traffic Mirroring, GCP Packet Mirroring, or an
    Azure vTAP — which VXLAN-encapsulates the mirrored frames to a collector. Also models a K8s
    VXLAN CNI overlay. Zeek decapsulates it and logs the inner conn plus a tunnel.log entry."""
    return Vantage("vpc-mirror", link_type="ethernet", vxlan_vni=vni,
                   vxlan_src=source, vxlan_dst=collector)
