# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""IP fragmentation — a benign path-MTU artifact and the classic IDS-evasion primitive.

Splitting each oversized IPv4 packet into fragments forces a sensor to *reassemble* before it
can match: real Zeek does (the flow's logs are unchanged), but a signature engine that inspects
per-packet, or reassembles with a different overlap policy, can be evaded. A smaller ``fragsize``
is a stronger reassembly test. The transform is pure and deterministic; the reassembled stream —
and every byte/packet count Zeek derives from sequence space — is identical to the un-fragmented
capture.
"""

from __future__ import annotations

from scapy.layers.inet import IP, fragment
from scapy.layers.l2 import Ether


def fragment_packets(packets: list, fragsize: int = 576) -> list:
    """Fragment every IPv4 packet whose payload exceeds ``fragsize`` bytes into IP fragments.

    ``fragsize`` is the max IP-payload bytes per fragment (rounded down to an 8-byte multiple by
    the fragment offset). IPv6 (extension-header fragmentation) and non-IP frames pass through.
    """
    frag = max(8, (fragsize // 8) * 8)
    out: list = []
    for p in packets:
        if Ether in p and IP in p and len(p[IP].payload) > frag:
            eth = p[Ether]
            for piece in fragment(p[IP], fragsize=frag):
                fr = Ether(src=eth.src, dst=eth.dst) / piece
                fr.time = p.time
                out.append(fr)
        else:
            out.append(p)
    return out
