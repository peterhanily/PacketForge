# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""TLS renderer: a real, Zeek-parseable handshake with a controllable JA3.

Emits ClientHello (SNI + ciphers + extensions from the client profile), ServerHello
(negotiated version + cipher), ChangeCipherSpec + opaque Finished both ways, and
opaque application-data records sized to the spec. Zeek logs the version, cipher, and
SNI to ssl.log; the JA3 is computed from the same numeric profile the ClientHello is
built from, so it agrees with the bytes on the wire by construction.

V1 models TLS 1.2. TLS 1.3 (encrypted handshake, supported_versions) is a refinement.
"""

from __future__ import annotations

import random

from scapy.layers.tls.all import (
    TLS,
    ProtocolName,
    ServerName,
    TLS_Ext_ALPN,
    TLS_Ext_ExtendedMasterSecret,
    TLS_Ext_RenegotiationInfo,
    TLS_Ext_ServerName,
    TLS_Ext_SessionTicket,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedPointFormat,
    TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SupportedVersion_SH,
    TLS_Ext_Unknown,
    TLSClientHello,
    TLSServerHello,
)
from scapy.layers.tls.handshake import (
    TLSCertificate,
    TLSClientKeyExchange,
    TLSServerHelloDone,
    TLSServerKeyExchange,
)
from scapy.layers.tls.keyexchange import ServerECDHNamedCurveParams
from scapy.layers.tls.record import TLSChangeCipherSpec

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.fingerprints.certs import synthetic_cert_der
from packetforge.fingerprints.ja3 import is_grease, ja3_hash, ja3_to_profile
from packetforge.fingerprints.loader import load_ja3_profile
from packetforge.models.flowspec import Flow, TlsL7
from packetforge.renderers.base import RenderResult, filler_bytes

# One RFC 8701 GREASE value; excluded from JA3 so the wire carries it but the
# fingerprint doesn't change.
_GREASE = 0x0A0A

_VERSION_ZEEK = {"TLS1.2": "TLSv12", "TLS1.3": "TLSv13"}

# Zeek/IANA names for the ciphers a server may negotiate here.
_CIPHER_ZEEK = {
    49195: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    49199: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    49196: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    49200: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    52393: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    52392: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    49191: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    49171: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    49172: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    47: "TLS_RSA_WITH_AES_128_CBC_SHA",
    53: "TLS_RSA_WITH_AES_256_CBC_SHA",
    156: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    157: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    4865: "TLS_AES_128_GCM_SHA256",       # TLS 1.3
    4866: "TLS_AES_256_GCM_SHA384",       # TLS 1.3
    4867: "TLS_CHACHA20_POLY1305_SHA256",  # TLS 1.3
}

_TLS13_CIPHERS = [4865, 4866, 4867]

# Reverse map so ingesters can pick a numeric cipher from a Zeek/IANA name.
CIPHER_ID_BY_NAME = {name: cid for cid, name in _CIPHER_ZEEK.items()}


def _build_extension(ext_type: int, profile: dict, server_name: str, grease: bool = False,
                     alpn: list = None):
    if is_grease(ext_type):
        return TLS_Ext_Unknown(type=ext_type, val=b"")
    if ext_type == 0:
        return TLS_Ext_ServerName(servernames=[ServerName(servername=server_name.encode())])
    if ext_type == 23:
        return TLS_Ext_ExtendedMasterSecret()
    if ext_type == 65281:
        return TLS_Ext_RenegotiationInfo()
    if ext_type == 10:
        groups = list(profile["curves"])
        if grease:
            groups = [_GREASE] + groups
        return TLS_Ext_SupportedGroups(groups=groups)
    if ext_type == 11:
        return TLS_Ext_SupportedPointFormat(ecpl=list(profile["point_formats"]))
    if ext_type == 35:
        return TLS_Ext_SessionTicket()
    if ext_type == 13:
        return TLS_Ext_SignatureAlgorithms(sig_algs=list(profile["signature_algorithms"]))
    if ext_type == 16:  # ALPN must carry a protocol list to be well-formed
        names = alpn or ["h2", "http/1.1"]
        return TLS_Ext_ALPN(protocols=[ProtocolName(protocol=n.encode()) for n in names])
    # Any other advertised extension (from an arbitrary reproduced JA3) rides as an
    # opaque extension of the right type — JA3/JA4 key on the type, not the content.
    return TLS_Ext_Unknown(type=ext_type, val=b"")


def _msg_record(rtype: int, version: int, msg: list) -> bytes:
    """A TLS record whose length scapy computes from structured messages."""
    return bytes(TLS(type=rtype, version=version, msg=msg))


def _opaque_record(rtype: int, version: int, payload: bytes) -> bytes:
    """A TLS record with an opaque (e.g. encrypted) body and a correct length field.

    scapy's ``TLS()/Raw()`` leaves the record length at 0, which real parsers reject,
    so the 5-byte record header is written directly: type, version, length, payload.
    """
    return bytes([rtype, (version >> 8) & 0xFF, version & 0xFF,
                  (len(payload) >> 8) & 0xFF, len(payload) & 0xFF]) + payload


def _opaque_records(rtype: int, version: int, payload: bytes) -> bytes:
    """One or more TLS records, each within the 2^14-byte record-size limit (RFC 8446),
    so bulk application data fragments across records the way a real endpoint sends it.
    """
    max_rec = 16384
    if len(payload) <= max_rec:
        return _opaque_record(rtype, version, payload)
    return b"".join(_opaque_record(rtype, version, payload[i:i + max_rec])
                    for i in range(0, len(payload), max_rec))


def render_tls(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: TlsL7 = flow.l7
    # An explicit JA3 string (e.g. reproducing a malware fingerprint seen on the wire)
    # overrides the named client profile.
    profile = ja3_to_profile(spec.ja3) if spec.ja3 else load_ja3_profile(spec.client_profile)
    is13 = spec.version == "TLS1.3"
    legacy = 0x0303  # legacy_version carried on the wire for both 1.2 and 1.3

    grease = bool(profile.get("grease"))
    cipher_list = list(profile["ciphers"])
    ext_types = list(profile["extensions"])
    if is13:
        cipher_list = _TLS13_CIPHERS + cipher_list
        ext_types = ext_types + [43]  # supported_versions advertises 1.3
    if spec.alpn and 16 not in ext_types:
        ext_types.append(16)  # advertise ALPN even if the base profile omits it
    if grease:
        cipher_list = [_GREASE] + cipher_list
        ext_types = [_GREASE] + ext_types

    exts = []
    for t in ext_types:
        if t == 43:
            exts.append(TLS_Ext_SupportedVersion_CH(versions=[0x0304, 0x0303]))
        else:
            exts.append(_build_extension(t, profile, spec.server_name, grease, alpn=spec.alpn))
    client_hello = TLSClientHello(
        version=legacy, gmt_unix_time=int(flow.start_time),
        random_bytes=rng.randbytes(28), ciphers=cipher_list, ext=exts)

    default_cipher = _TLS13_CIPHERS[0] if is13 else int(profile["server_cipher"])
    chosen_cipher = spec.server_cipher if spec.server_cipher is not None else default_cipher
    # The server selects one ALPN protocol; for TLS 1.2 it rides in the clear ServerHello,
    # so Zeek records it as ssl.log next_protocol (in 1.3 it is in encrypted extensions).
    selected_alpn = spec.alpn[0] if spec.alpn else None
    sh_ext = [TLS_Ext_SupportedVersion_SH(version=0x0304)] if is13 else []
    if selected_alpn and not is13:
        sh_ext.append(TLS_Ext_ALPN(protocols=[ProtocolName(protocol=selected_alpn.encode())]))
    server_hello = TLSServerHello(
        version=legacy, gmt_unix_time=int(flow.start_time), random_bytes=rng.randbytes(28),
        cipher=chosen_cipher, ext=sh_ext)

    ch_rec = _msg_record(22, 0x0301, [client_hello])
    sh_rec = _msg_record(22, legacy, [server_hello])
    ccs = _msg_record(20, legacy, [TLSChangeCipherSpec()])
    app_c = _opaque_records(23, legacy, filler_bytes(spec.app_data_orig_bytes, rng))
    app_s = _opaque_records(23, legacy, filler_bytes(spec.app_data_resp_bytes, rng))

    if is13:
        # TLS 1.3: the server's {EncryptedExtensions..Finished} flight and the client
        # Finished are encrypted, so they ride as opaque application_data records; a
        # compatibility ChangeCipherSpec is sent in the clear.
        enc_hs = _opaque_record(23, legacy, rng.randbytes(160))
        fin_c = _opaque_record(23, legacy, rng.randbytes(40))
        messages = [
            TcpMessage(True, ch_rec),
            TcpMessage(False, sh_rec + ccs + enc_hs),
            TcpMessage(True, ccs + fin_c),
        ]
    else:
        # A real TLS 1.2 ECDHE-RSA server flight, carrying a Certificate in the clear so
        # a hunter can extract and validate it: ServerHello, Certificate (deterministic
        # self-signed cert with CN = SNI), ServerKeyExchange (ephemeral ECDH params +
        # RSA signature), ServerHelloDone; then the client's EC-point ClientKeyExchange.
        # The ECDH point and signature bytes are opaque but structurally valid.
        serial = rng.randint(1, 0x7FFFFFFF)
        cert_der = synthetic_cert_der(spec.server_name, serial, flow.start_time - 30 * 86400)
        cert_rec = _msg_record(22, legacy, [TLSCertificate(certs=[(len(cert_der), cert_der)])])
        s_point = b"\x04" + rng.randbytes(64)  # uncompressed secp256r1 point (0x04 || X || Y)
        ske = TLSServerKeyExchange(
            params=ServerECDHNamedCurveParams(named_curve=23, point=s_point),
            sig=b"\x04\x01" + (256).to_bytes(2, "big") + rng.randbytes(256))  # rsa_pkcs1_sha256
        ske_rec = _msg_record(22, legacy, [ske])
        shd_rec = _msg_record(22, legacy, [TLSServerHelloDone()])
        c_point = b"\x04" + rng.randbytes(64)
        cke_rec = _msg_record(22, legacy, [
            TLSClientKeyExchange(exchkeys=bytes([len(c_point)]) + c_point)])
        fin_c = _opaque_record(22, legacy, rng.randbytes(40))
        fin_s = _opaque_record(22, legacy, rng.randbytes(40))
        messages = [
            TcpMessage(True, ch_rec),
            TcpMessage(False, sh_rec + cert_rec + ske_rec + shd_rec),
            TcpMessage(True, cke_rec + ccs + fin_c),
            TcpMessage(False, ccs + fin_s),
        ]
    if spec.app_data_orig_bytes:
        messages.append(TcpMessage(True, app_c))
    if spec.app_data_resp_bytes:
        messages.append(TcpMessage(False, app_s))

    result = build_tcp_flow(
        orig, resp, messages, start_time=flow.start_time, rtt=flow.rtt,
        rng=rng, conn_state=flow.conn_state)

    # JA3 from the actual wire lists (ja3_hash drops GREASE per RFC 8701).
    ja3 = ja3_hash(771, cipher_list, ext_types, profile["curves"], profile["point_formats"])
    conn = dict(result.summary)
    conn["service"] = "ssl"
    conn["proto"] = "tcp"
    expected = {
        "conn": conn,
        "ssl": {
            "version": _VERSION_ZEEK[spec.version],
            "cipher": _CIPHER_ZEEK.get(chosen_cipher, ""),
            "server_name": spec.server_name,
            "ja3": ja3,  # Zeek does not log JA3 without an add-on; carried as ground truth
            # Server-selected ALPN — Zeek's ssl.log next_protocol for TLS 1.2 (blank in 1.3).
            "next_protocol": selected_alpn if (selected_alpn and not is13) else "",
        },
    }
    return RenderResult(packets=result.packets, expected=expected)
