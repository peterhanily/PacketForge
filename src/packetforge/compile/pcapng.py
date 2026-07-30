# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""pcapng writer with per-packet comments — provenance that survives detachment.

A manifest that can be separated from the capture is an anti-pattern: the capture then
circulates as an unqualified claim, and nothing in it says which bytes rest on evidence and
which were invented to make the wire format well-formed. Co-location, a filename convention
and a repo directory are all things a forwarded file loses.

pcapng solves it. Every Enhanced Packet Block may carry an ``opt_comment``, which Wireshark
shows in the packet detail pane and ``tshark -e frame.comment`` reads back. So the pedigree
travels *inside* the artifact. Zeek reads pcapng through libpcap and ignores the options, so
the validation gate is unaffected — verified: the same capture as pcap and as pcapng yields
byte-identical Zeek logs.

scapy ships ``PcapNgWriter`` but it has no option support, so the blocks are built here. Only
what is needed: a section header, one interface description, and one EPB per packet.
"""

from __future__ import annotations

import struct
from pathlib import Path

# pcapng block types (RFC-track draft, section 4)
_SHB = 0x0A0D0D0A
_IDB = 0x00000001
_EPB = 0x00000006
_OPT_COMMENT = 1
_OPT_END = 0

# Link types, matching CaptureMeta.link_type.
LINKTYPES = {"ethernet": 1, "linux_sll": 113}


def _pad4(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % 4)


def _block(btype: int, body: bytes) -> bytes:
    body = _pad4(body)
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def _options(comment: str) -> bytes:
    if not comment:
        return b""
    raw = comment.encode("utf-8")
    return (struct.pack("<HH", _OPT_COMMENT, len(raw)) + _pad4(raw)
            + struct.pack("<HH", _OPT_END, 0))


def write_pcapng(packets, out_path, *, link_type: str = "ethernet",
                 comments=None, file_comment: str = "") -> int:
    """Write ``packets`` as pcapng, attaching ``comments[i]`` to packet ``i``.

    ``file_comment`` rides on the section header — the one place to say, to anyone who opens
    the file with no other context, what this capture is and is not.
    """
    lt = LINKTYPES.get(link_type)
    if lt is None:
        raise ValueError(f"unsupported link_type {link_type!r}; "
                         f"choose from {sorted(LINKTYPES)}")
    comments = comments or []

    # byte-order magic, version 1.0, section length unknown (-1)
    shb = _block(_SHB, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _options(file_comment))
    # linktype, reserved, snaplen 0 = no limit; default if_tsresol is 10^-6 (microseconds)
    idb = _block(_IDB, struct.pack("<HHI", lt, 0, 0))

    out = [shb, idb]
    for i, pkt in enumerate(packets):
        raw = bytes(pkt)
        # Round exactly as scapy's pcap writer does. Truncating instead put 936 of 2785
        # packets 1 us early and made Zeek's logs differ between the two encodings of the
        # same capture — which would have quietly falsified "same bytes, same analysis".
        sec = int(pkt.time)
        usec = int(round((float(pkt.time) - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        ts = sec * 1_000_000 + usec
        body = (struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(raw), len(raw))
                + _pad4(raw)
                + _options(comments[i] if i < len(comments) else ""))
        out.append(_block(_EPB, body))

    Path(out_path).write_bytes(b"".join(out))
    return len(packets)
