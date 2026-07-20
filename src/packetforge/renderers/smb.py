# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""SMB2/3 renderer: negotiate -> session setup -> tree connect (Zeek smb_mapping.log)."""

from __future__ import annotations

import random

from scapy.layers import ntlm as _ntlm
from scapy.layers.netbios import NBTSession
from scapy.packet import Raw
from scapy.layers.smb2 import (
    SMB2_Close_Request,
    SMB2_Close_Response,
    SMB2_Create_Request,
    SMB2_Create_Response,
    SMB2_Header,
    SMB2_Negotiate_Protocol_Request,
    SMB2_Negotiate_Protocol_Response,
    SMB2_Read_Request,
    SMB2_Read_Response,
    SMB2_Session_Setup_Request,
    SMB2_Session_Setup_Response,
    SMB2_Tree_Connect_Request,
    SMB2_Tree_Connect_Response,
    SMB2_Write_Request,
    SMB2_Write_Response,
)

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import Flow, NtlmAuth, SmbL7
from packetforge.renderers.base import RenderResult
from packetforge.renderers.file_bodies import file_for

# NTLMSSP NegotiateFlags. UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | ... — the
# common client/server set; the CHALLENGE/AUTHENTICATE side adds TARGET_INFO | VERSION so
# Zeek reads the TargetInfo AV_PAIRs and the version block.
_NEG_FLAGS = 0xE2088297
_AUTH_FLAGS = 0xE2888215
# STATUS_MORE_PROCESSING_REQUIRED: the status a server returns on the CHALLENGE leg.
_MORE_PROCESSING = 0xC0000016
# SecurityBlob offsets from the start of the SMB2 header: header (64) + the SessionSetup
# fixed structure (request 24, response 8). scapy leaves these at 0, which makes Zeek read
# the NTLM buffer from the wrong base and drop username/domain — so we set them explicitly.
_SS_REQ_BLOB_OFFSET = 88
_SS_RESP_BLOB_OFFSET = 72


def _nb(pkt) -> bytes:
    return bytes(NBTSession() / pkt)


def _ntlm_blobs(spec: NtlmAuth, rng: random.Random):
    """The three NTLMSSP messages (NEGOTIATE, CHALLENGE, AUTHENTICATE) as raw bytes.

    Inert: the LM/NT responses are fixed filler, never a real crackable hash."""
    neg = bytes(_ntlm.NTLM_NEGOTIATE(NegotiateFlags=_NEG_FLAGS))
    chal = bytes(_ntlm.NTLM_CHALLENGE(
        NegotiateFlags=_AUTH_FLAGS,
        ServerChallenge=rng.randbytes(8),  # deterministic per-flow; not a real challenge
        TargetName=spec.server_domain,
        TargetInfo=[
            _ntlm.AV_PAIR(AvId="MsvAvNbDomainName", Value=spec.server_domain),
            _ntlm.AV_PAIR(AvId="MsvAvNbComputerName", Value=spec.server_host),
            _ntlm.AV_PAIR(AvId="MsvAvEOL"),
        ]))
    auth = bytes(_ntlm.NTLM_AUTHENTICATE(
        NegotiateFlags=_AUTH_FLAGS,
        DomainName=spec.domain, UserName=spec.user, Workstation=spec.workstation,
        LmChallengeResponse=b"\x00" * 24,      # inert filler
        NtChallengeResponse=b"\xAA" * 24))     # inert filler — never a real NTLMv2 hash
    return neg, chal, auth


def _ss_req(blob: bytes):
    return SMB2_Session_Setup_Request(SecurityBlobBufferOffset=_SS_REQ_BLOB_OFFSET,
                                      SecurityBlobLen=len(blob)) / Raw(blob)


def _ss_resp(blob: bytes):
    # NB: the response's blob descriptor fields are named differently from the request's
    # (SecurityBufferOffset/SecurityLen vs SecurityBlobBufferOffset/SecurityBlobLen). Using
    # the wrong names leaves them 0, so Zeek/tshark see "no blob" and skip the CHALLENGE.
    return SMB2_Session_Setup_Response(SecurityBufferOffset=_SS_RESP_BLOB_OFFSET,
                                       SecurityLen=len(blob)) / Raw(blob)


def render_smb(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: SmbL7 = flow.l7
    sid = rng.randint(1, 0xFFFFFFFF)
    # Tree id assigned by the tree connect and echoed on every later request, so Zeek can
    # bind each create/read/write to the share it happened on (and keep its path).
    tid = rng.randint(1, 0xFFFF)
    # SMB2 FILETIME (100 ns since 1601). Pin ServerTime/ServerStartTime — scapy fills
    # them with wall-clock time when left None, breaking determinism.
    ft = int((flow.start_time + 11644473600) * 10_000_000)
    messages = [
        TcpMessage(True, _nb(SMB2_Header(Command=0)
                             / SMB2_Negotiate_Protocol_Request(Dialects=[0x0202, 0x0210, 0x0300]))),
        TcpMessage(False, _nb(SMB2_Header(Command=0, Flags=1)
                              / SMB2_Negotiate_Protocol_Response(DialectRevision=spec.dialect,
                                                                ServerTime=ft, ServerStartTime=ft - 10**14))),
    ]

    if spec.ntlm:
        # NTLMSSP session setup: NEGOTIATE -> CHALLENGE (STATUS_MORE_PROCESSING_REQUIRED,
        # SessionId assigned) -> AUTHENTICATE -> success. Zeek reads the victim's captured
        # domain\user and workstation off the AUTHENTICATE into ntlm.log.
        neg, chal, auth = _ntlm_blobs(spec.ntlm, rng)
        messages += [
            TcpMessage(True, _nb(SMB2_Header(Command=1) / _ss_req(neg))),
            TcpMessage(False, _nb(SMB2_Header(Command=1, Flags=1, Status=_MORE_PROCESSING,
                                              SessionId=sid) / _ss_resp(chal))),
            TcpMessage(True, _nb(SMB2_Header(Command=1, SessionId=sid) / _ss_req(auth))),
            TcpMessage(False, _nb(SMB2_Header(Command=1, Flags=1, SessionId=sid)
                                  / SMB2_Session_Setup_Response())),
        ]
    else:
        messages += [
            TcpMessage(True, _nb(SMB2_Header(Command=1) / SMB2_Session_Setup_Request())),
            TcpMessage(False, _nb(SMB2_Header(Command=1, Flags=1, SessionId=sid)
                                  / SMB2_Session_Setup_Response())),
        ]

    messages += [
        TcpMessage(True, _nb(SMB2_Header(Command=3, SessionId=sid)
                             / SMB2_Tree_Connect_Request(Buffer=[("Path", spec.share)]))),
        # Return the real share type: PIPE (2) for IPC$, else DISK (1) for a file share.
        # Without a valid share type Zeek treats the tree mapping as unresolved and drops
        # the share path (smb_mapping.log path stays empty), which blindsides analytics
        # that key on the share name (e.g. BZAR's ADMIN$ test).
        TcpMessage(False, _nb(SMB2_Header(Command=3, Flags=1, TID=tid, SessionId=sid)
                              / SMB2_Tree_Connect_Response(
                                  ShareType=2 if spec.share.upper().endswith("IPC$") else 1))),
    ]

    if spec.read_file:
        # CREATE -> READ -> CLOSE: the READ carries real, typed file content, so it is
        # extractable via Wireshark "Export Objects > SMB" and Zeek's smb_files.log.
        content, _ = file_for(spec.read_file, spec.file_bytes, rng)
        fid = rng.randbytes(16)  # deterministic 16-byte FileId (not scapy's wall-clock GUID)
        messages += [
            TcpMessage(True, _nb(SMB2_Header(Command=5, TID=tid, SessionId=sid)
                                 / SMB2_Create_Request(Buffer=[("Name", spec.read_file)]))),
            TcpMessage(False, _nb(SMB2_Header(Command=5, Flags=1, TID=tid, SessionId=sid)
                                  / SMB2_Create_Response(FileId=fid, EndOfFile=len(content),
                                                        AllocationSize=len(content),
                                                        CreationTime=ft, LastAccessTime=ft,
                                                        LastWriteTime=ft, ChangeTime=ft))),
            TcpMessage(True, _nb(SMB2_Header(Command=8, TID=tid, SessionId=sid)
                                 / SMB2_Read_Request(FileId=fid, Length=len(content)))),
            TcpMessage(False, _nb(SMB2_Header(Command=8, Flags=1, TID=tid, SessionId=sid)
                                  / SMB2_Read_Response(Buffer=[("Data", content)]))),
            TcpMessage(True, _nb(SMB2_Header(Command=6, TID=tid, SessionId=sid)
                                 / SMB2_Close_Request(FileId=fid))),
            TcpMessage(False, _nb(SMB2_Header(Command=6, Flags=1, TID=tid, SessionId=sid)
                                  / SMB2_Close_Response())),
        ]

    if spec.write_file:
        # CREATE -> WRITE -> CLOSE: the WRITE pushes real, typed content originator->
        # responder, so Zeek logs an SMB::FILE_WRITE (lateral tool transfer, T1570).
        content, _ = file_for(spec.write_file, spec.file_bytes, rng)
        wfid = rng.randbytes(16)
        messages += [
            TcpMessage(True, _nb(SMB2_Header(Command=5, TID=tid, SessionId=sid)
                                 / SMB2_Create_Request(Buffer=[("Name", spec.write_file)]))),
            TcpMessage(False, _nb(SMB2_Header(Command=5, Flags=1, TID=tid, SessionId=sid)
                                  / SMB2_Create_Response(FileId=wfid, EndOfFile=len(content),
                                                        AllocationSize=len(content),
                                                        CreationTime=ft, LastAccessTime=ft,
                                                        LastWriteTime=ft, ChangeTime=ft))),
            TcpMessage(True, _nb(SMB2_Header(Command=9, TID=tid, SessionId=sid)
                                 / SMB2_Write_Request(FileId=wfid, Buffer=[("Data", content)]))),
            TcpMessage(False, _nb(SMB2_Header(Command=9, Flags=1, TID=tid, SessionId=sid)
                                  / SMB2_Write_Response(Count=len(content)))),
            TcpMessage(True, _nb(SMB2_Header(Command=6, TID=tid, SessionId=sid)
                                 / SMB2_Close_Request(FileId=wfid))),
            TcpMessage(False, _nb(SMB2_Header(Command=6, Flags=1, TID=tid, SessionId=sid)
                                  / SMB2_Close_Response())),
        ]

    result = build_tcp_flow(orig, resp, messages, start_time=flow.start_time,
                            rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
    conn = dict(result.summary)
    conn["service"] = "smb"
    conn["proto"] = "tcp"
    return RenderResult(packets=result.packets, expected={"conn": conn, "produces": "smb_mapping"})
