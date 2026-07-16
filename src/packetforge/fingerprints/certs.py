# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic synthetic X.509 certificates for TLS flows.

Real TLS 1.2 servers present a Certificate in the clear, and a threat hunter will pull
it out of the capture and inspect it. So PacketForge emits a *valid, parseable* X.509
cert whose subject matches the SNI. It is self-signed with one committed synthetic key
and signed with RSA PKCS#1 v1.5 (deterministic), so the DER bytes are byte-identical
across runs given the same inputs — no wall-clock, no random nonce.

This is a fake cert for fake traffic (self-signed, shared key); it is never a real
credential. It exists so `tshark`/Wireshark/openssl can extract and validate a real
certificate structure from the wire.
"""

from __future__ import annotations

import datetime
from functools import lru_cache

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from packetforge.fingerprints.keys.synthetic_key import synthetic_key_der


@lru_cache(maxsize=1)
def _key():
    return serialization.load_der_private_key(synthetic_key_der(), password=None)


def _naive_utc(epoch: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).replace(tzinfo=None)


@lru_cache(maxsize=256)
def synthetic_cert_der(common_name: str, serial: int, not_before_epoch: float,
                       valid_days: int = 365, issuer_cn: str = "") -> bytes:
    """A deterministic DER-encoded self-signed X.509 cert for ``common_name``."""
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)])
    nb = _naive_utc(not_before_epoch)
    na = _naive_utc(not_before_epoch + valid_days * 86400)
    # SAN must be a valid DNS name; fall back to a placeholder if the SNI isn't one.
    dns = common_name if common_name and " " not in common_name else "localhost"
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(max(1, serial))
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
