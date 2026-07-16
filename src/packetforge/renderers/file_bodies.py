# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Valid, typed, exactly-sized file bodies for HTTP responses.

When a capture shows ``GET /report.pdf``, a hunter will pull the object out with
Wireshark's "Export Objects" (or tshark ``--export-objects``) and expect a real PDF —
not filler. So response bodies are genuine files of the type implied by the URL: correct
magic bytes and enough structure that ``file(1)`` and format readers recognise them,
padded to the exact byte length the flow declares so volumetrics stay intact.

These are structurally valid containers with benign filler content — not real documents
or executables. A malware "download" is a valid PE header over synthetic bytes; it is
inert, and exists so extraction/scanning tooling has something real to chew on.
"""

from __future__ import annotations

import random
import struct
import zlib

_MIN = 64  # below this we just return filler of the requested type


def _filler(n: int, rng: random.Random) -> bytes:
    return rng.randbytes(max(0, n))


def _pad_to(body: bytes, n: int, filler: bytes) -> bytes:
    """Grow ``body`` to exactly ``n`` bytes by inserting ``filler`` where marked (@@@)."""
    gap = n - (len(body) - 3)  # 3 = len('@@@')
    if gap < 0:
        return body.replace(b"@@@", b"", 1)[:n]
    return body.replace(b"@@@", filler[:gap].ljust(gap, b"A"), 1)


def _pdf(n: int, rng: random.Random) -> bytes:
    head = (b"%PDF-1.7\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
            b"%@@@\n%%EOF\n")
    return _pad_to(head, n, bytes(c for c in _ascii(rng, n) if c != 0x0A))


def _png(n: int, rng: random.Random) -> bytes:
    def chunk(typ: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    idat = chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
    iend = chunk(b"IEND", b"")
    fixed = sig + ihdr + idat + iend
    pad = n - len(fixed) - 12  # 12 = tEXt chunk overhead (len4+type4+crc4)
    if pad < 1:
        return fixed
    text = chunk(b"tEXt", b"Comment\x00" + _ascii(rng, pad - 8).ljust(max(0, pad - 8), b"A"))
    return sig + ihdr + text + idat + iend


def _gif(n: int, rng: random.Random) -> bytes:
    head = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00"
    body = head + b"\x21\xfe@@@\x00" + b"\x3b"  # comment extension + trailer
    return _pad_to(body, n, bytes(c for c in _ascii(rng, n) if c != 0x00))


def _jpeg(n: int, rng: random.Random) -> bytes:
    soi = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    # a COM (comment) marker whose length we size to hit the target
    payload = n - len(soi) - 2 - 4  # 2 = EOI, 4 = COM marker+len
    payload = max(1, payload)
    com = b"\xff\xfe" + struct.pack(">H", payload + 2) + _ascii(rng, payload).ljust(payload, b"A")
    return (soi + com + b"\xff\xd9")[:n] if n >= len(soi) + 6 else soi + b"\xff\xd9"


def _zip(n: int, rng: random.Random) -> bytes:
    name = b"readme.txt"
    fixed = 30 + len(name) + 46 + len(name) + 22  # local hdr + central dir + EOCD
    data = _ascii(rng, max(1, n - fixed))
    crc = zlib.crc32(data) & 0xFFFFFFFF
    local = (b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 0, 0, 0, crc,
             len(data), len(data), len(name), 0) + name + data)
    central = (b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", 20, 20, 0, 0, 0, 0,
               crc, len(data), len(data), len(name), 0, 0, 0, 0, 0, 0) + name)
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + eocd


def _pe(n: int, rng: random.Random) -> bytes:
    # Minimal but file(1)-recognisable PE32 executable: MZ + e_lfanew -> PE\0\0 + COFF.
    e_lfanew = 0x40
    mz = b"MZ" + b"\x90\x00" * 29 + struct.pack("<I", e_lfanew)
    mz = mz.ljust(e_lfanew, b"\x00")
    coff = struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0xE0, 0x0102)  # i386, no sections
    opt = struct.pack("<H", 0x010B) + b"\x00" * 0xDE  # PE32 optional header
    pe = mz + b"PE\x00\x00" + coff + opt
    return (pe + _ascii(rng, n - len(pe)))[:n] if n > len(pe) else pe


def _html(n: int, rng: random.Random) -> bytes:
    body = b"<!doctype html><html><head><title>Document</title></head><body><p>@@@</p></body></html>"
    return _pad_to(body, n, bytes(c for c in _ascii(rng, n) if c not in (0x3C, 0x3E)))


def _ascii(rng: random.Random, n: int) -> bytes:
    if n <= 0:
        return b""
    alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    return bytes(alphabet[b % len(alphabet)] for b in rng.randbytes(n))


_BY_EXT = {
    "pdf": ("application/pdf", _pdf), "png": ("image/png", _png),
    "gif": ("image/gif", _gif), "jpg": ("image/jpeg", _jpeg), "jpeg": ("image/jpeg", _jpeg),
    "zip": ("application/zip", _zip), "exe": ("application/x-msdownload", _pe),
    "dll": ("application/x-msdownload", _pe), "html": ("text/html; charset=utf-8", _html),
    "htm": ("text/html; charset=utf-8", _html),
    # Office Open XML documents are ZIP containers.
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", _zip),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", _zip),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", _zip),
}


def file_for(uri: str, size: int, rng: random.Random) -> tuple:
    """Return (body_bytes, content_type) for ``uri`` at ~``size`` bytes.

    The type follows the URL's extension; unknown/extension-less URLs get valid HTML.
    """
    ext = uri.rsplit(".", 1)[-1].split("?")[0].lower() if "." in uri.rsplit("/", 1)[-1] else ""
    ctype, fn = _BY_EXT.get(ext, ("text/html; charset=utf-8", _html))
    if size < _MIN:
        return _ascii(rng, size), ctype
    return fn(size, rng), ctype
