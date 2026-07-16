# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Kerberos renderer: a faithful AS/TGS exchange over TCP/88 (Zeek kerberos.log).

We build the KRB ASN.1 messages offline (no KDC, no keys) using scapy's Kerberos
layer, then carry them over a real TCP conversation via :func:`build_tcp_flow`. The
encryption type is real, so an RC4 downgrade (etype 23) is visible to Zeek's
``kerberos.log`` (``cipher``) and to Suricata's ``krb5.weak_encryption`` — the exact
signal Kerberoasting and AS-REP roasting are hunted by. The ciphertext itself is
opaque and sized; we claim no plaintext.

Determinism: ``till``/``rtime`` are derived from the flow's start time and the nonce
is fixed, so no wall-clock leaks in (unlike scapy's SMB/NTP auto-fill fields).
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

from scapy.asn1.asn1 import (
    ASN1_BOOLEAN,
    ASN1_GENERAL_STRING,
    ASN1_GENERALIZED_TIME,
    ASN1_INTEGER,
)
from scapy.layers.kerberos import (
    EncryptedData,
    Kerberos,
    KerberosTCPHeader,
    KRB_AS_REP,
    KRB_AS_REQ,
    KRB_KDC_REQ_BODY,
    KRB_TGS_REP,
    KRB_TGS_REQ,
    KRB_Ticket,
    PA_PAC_REQUEST,
    PADATA,
    PrincipalName,
)

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, KerberosL7
from packetforge.renderers.base import RenderResult


def _gt(epoch: float) -> ASN1_GENERALIZED_TIME:
    """Deterministic KerberosTime from an epoch (second resolution, UTC)."""
    return ASN1_GENERALIZED_TIME(datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0))


def _default_service(spec: KerberosL7) -> str:
    if spec.service:
        return spec.service
    if spec.request_type == "AS":
        return f"krbtgt/{spec.realm}@{spec.realm}"
    return f"host/host.{spec.realm.lower()}@{spec.realm}"


def _wrap(krb) -> bytes:
    """Serialize a KRB message and prepend the 4-byte Kerberos-over-TCP length."""
    raw = bytes(Kerberos(root=krb))
    return bytes(KerberosTCPHeader(len=len(raw))) + raw


def _as_exchange(spec: KerberosL7, upn: str, spn: str, t: float, rng: random.Random) -> tuple:
    body = KRB_KDC_REQ_BODY(
        kdcOptions="forwardable+renewable+canonicalize+renewable-ok",
        cname=PrincipalName.fromUPN(upn),
        realm=ASN1_GENERAL_STRING(spec.realm),
        sname=PrincipalName.fromSPN(spn),
        till=_gt(t + 36000), rtime=_gt(t + 36000),
        nonce=ASN1_INTEGER(0x1F2E3D4C),
        etype=[ASN1_INTEGER(x) for x in spec.request_etypes],
    )
    padata = [PADATA(padataType=128, padataValue=PA_PAC_REQUEST(includePac=ASN1_BOOLEAN(-1)))]
    if spec.preauth:
        # PA-ENC-TIMESTAMP present => not AS-REP roastable. Opaque encrypted stamp.
        padata.insert(0, PADATA(padataType=2,
                                padataValue=EncryptedData(etype=spec.request_etypes[0],
                                                          cipher=rng.randbytes(52))))
    req = KRB_AS_REQ(pvno=5, msgType=10, reqBody=body, padata=padata)
    # The TGT carries a PAC -> large high-entropy ciphertext; the reply enc-part is small.
    tkt = KRB_Ticket(tktVno=5, realm=spec.realm, sname=PrincipalName.fromSPN(spn),
                     encPart=EncryptedData(etype=spec.etype, kvno=2, cipher=rng.randbytes(1088)))
    rep = KRB_AS_REP(pvno=5, msgType=11, crealm=spec.realm, cname=PrincipalName.fromUPN(upn),
                     ticket=tkt, encPart=EncryptedData(etype=spec.etype, kvno=1, cipher=rng.randbytes(120)))
    return req, rep


def _tgs_exchange(spec: KerberosL7, upn: str, spn: str, t: float, rng: random.Random) -> tuple:
    body = KRB_KDC_REQ_BODY(
        kdcOptions="forwardable+renewable+canonicalize",
        realm=ASN1_GENERAL_STRING(spec.realm),
        sname=PrincipalName.fromSPN(spn),
        till=_gt(t + 36000), rtime=_gt(t + 36000),  # pin rtime; scapy defaults it to now()
        nonce=ASN1_INTEGER(0x2A3B4C5D),
        etype=[ASN1_INTEGER(x) for x in spec.request_etypes],
    )
    req = KRB_TGS_REQ(pvno=5, msgType=12, reqBody=body)
    tkt = KRB_Ticket(tktVno=5, realm=spec.realm, sname=PrincipalName.fromSPN(spn),
                     encPart=EncryptedData(etype=spec.etype, kvno=3, cipher=rng.randbytes(880)))
    rep = KRB_TGS_REP(pvno=5, msgType=13, crealm=spec.realm, cname=PrincipalName.fromUPN(upn),
                      ticket=tkt, encPart=EncryptedData(etype=spec.etype, kvno=1, cipher=rng.randbytes(120)))
    return req, rep


def render_kerberos(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: KerberosL7 = flow.l7
    upn = f"{spec.client}@{spec.realm}"
    spn = _default_service(spec)
    build = _as_exchange if spec.request_type == "AS" else _tgs_exchange
    req, rep = build(spec, upn, spn, flow.start_time, rng)
    messages = [TcpMessage(True, _wrap(req)), TcpMessage(False, _wrap(rep))]
    result = build_tcp_flow(orig, resp, messages, start_time=flow.start_time,
                            rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
    conn = dict(result.summary)
    conn["service"] = "krb_tcp"
    conn["proto"] = "tcp"
    return RenderResult(packets=result.packets, expected={"conn": conn, "produces": "kerberos"})
