# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""JA4 (TLS client) and HASSH (SSH client) fingerprints.

JA4 is the modern successor to JA3 (FoxIO, GREASE-safe, sorted so it survives
extension shuffling). HASSH fingerprints an SSH client from its KEXINIT algorithm
lists. Both are computed from the same numeric profiles PacketForge puts on the wire,
so the declared fingerprint and the emitted bytes agree by construction.
"""

from __future__ import annotations

import hashlib

from packetforge.fingerprints.ja3 import is_grease

_SNI_EXT = 0x0000
_ALPN_EXT = 0x0010


def _hex2(v: int) -> str:
    return f"{v:04x}"


def _sha12(s: str) -> str:
    """First 12 hex chars of sha256 (JA4's truncation); '000...' for the empty set."""
    if not s:
        return "000000000000"
    return hashlib.sha256(s.encode(), usedforsecurity=False).hexdigest()[:12]


def ja4(version: int, ciphers: list, extensions: list, *, sni: bool = True,
        alpn: list | None = None, signature_algorithms: list | None = None,
        quic: bool = False) -> str:
    """Compute a JA4 TLS-client fingerprint (``ja4_a_ja4_b_ja4_c``)."""
    cph = [c for c in ciphers if not is_grease(c)]
    ext = [e for e in extensions if not is_grease(e)]
    sig = [s for s in (signature_algorithms or []) if not is_grease(s)]

    ver = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}.get(version, "12")
    proto = "q" if quic else "t"
    sni_c = "d" if sni else "i"
    alpn_c = "00"
    if alpn:
        a = alpn[0]
        alpn_c = (a[0] + a[-1]) if len(a) >= 2 else "00"
    ja4_a = f"{proto}{ver}{sni_c}{min(len(cph), 99):02d}{min(len(ext), 99):02d}{alpn_c}"

    ja4_b = _sha12(",".join(_hex2(c) for c in sorted(cph)))

    ext_for_c = sorted(e for e in ext if e not in (_SNI_EXT, _ALPN_EXT))
    c_input = ",".join(_hex2(e) for e in ext_for_c)
    if sig:
        c_input += "_" + ",".join(_hex2(s) for s in sig)  # sig algs kept in order
    ja4_c = _sha12(c_input)
    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def ja4_from_profile(profile: dict) -> str:
    return ja4(profile.get("tls_version", 771), profile["ciphers"], profile["extensions"],
              sni=True, alpn=profile.get("alpn"),
              signature_algorithms=profile.get("signature_algorithms"))


def hassh(kex: str, encryption: str, mac: str, compression: str) -> str:
    """HASSH = md5(kex;encryption;mac;compression) — the SSH client fingerprint."""
    return hashlib.md5(f"{kex};{encryption};{mac};{compression}".encode(),
                       usedforsecurity=False).hexdigest()
