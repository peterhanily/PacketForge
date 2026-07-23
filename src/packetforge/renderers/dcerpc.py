# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""DCE-RPC-over-SMB renderer: bind to a well-known MS-RPC interface on a named pipe,
then issue one request per operation (Zeek ``dce_rpc.log`` endpoint + operation).

The SMB2 named-pipe carrier and the DCE-RPC control PDUs (bind / bind-ack) are fully
well-formed, so real Zeek reassembles them with an empty ``weird.log`` and names the
interface + each operation exactly (svcctl::CreateServiceW, samr::SamrEnumerateUsers...).
That is the signal an analytic like BZAR keys on.

Inert by construction: the request/response *stubs* — where an operation's NDR arguments
would sit — are opaque zero filler, never real arguments. A CreateServiceW request here
carries the interface UUID, the opnum, and zero bytes; it contains no service name, no
binary path, and nothing that could create a service. The stubs are *sealed* (RPC packet
privacy, auth_level 6) the way real drsuapi/DCSync and lateral-movement RPC run, so a
dissector treats them as encrypted stub data — Wireshark decodes the whole capture with no
Malformed-Packet exception (a clean ``tshark -z expert``), and Zeek keys on the interface +
opnum from the cleartext header, which are valid. See docs/inert-by-construction.md.
"""

from __future__ import annotations

import random
import uuid

from scapy.layers.dcerpc import (
    CommonAuthVerifier,
    DceRpc5,
    DceRpc5AbstractSyntax,
    DceRpc5Bind,
    DceRpc5BindAck,
    DceRpc5Context,
    DceRpc5PortAny,
    DceRpc5Request,
    DceRpc5Response,
    DceRpc5Result,
    DceRpc5TransferSyntax,
)
from scapy.layers.netbios import NBTSession
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
from scapy.packet import Raw

from packetforge.compile.tcp import Endpoint, TcpMessage, build_tcp_flow
from packetforge.models.flowspec import DceRpcL7, Flow
from packetforge.renderers.base import RenderResult

# NDR 2.0 transfer syntax — the DCE-RPC serialization every one of these binds to.
_NDR = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")

# Well-known MS-RPC interfaces this renderer can bind, keyed by the name in DceRpcL7.
# Values are (interface UUID, (major, minor) version). These UUIDs are public protocol
# identifiers from Microsoft's open specifications — the on-the-wire keys Zeek maps to an
# endpoint name — not capability. Zeek names each interface exactly as the comment shows.
_INTERFACES = {
    "svcctl": ("367abb81-9844-35f1-ad32-98f038001003", (2, 0)),  # MS-SCMR  -> "svcctl"
    "atsvc": ("1ff70682-0a51-30e8-076d-740be8cee98b", (1, 0)),  # MS-TSCH ATSvc -> "atsvc"
    # MS-TSCH ITaskSchedulerService -> Zeek endpoint "ITaskSchedulerService"
    "ITaskSchedulerService": ("86d35949-83c9-4044-b424-db363231fd0c", (1, 0)),
    "srvsvc": ("4b324fc8-1670-01d3-1278-5a47bf6ee188", (3, 0)),  # MS-SRVS -> "srvsvc"
    "samr": ("12345778-1234-abcd-ef00-0123456789ac", (1, 0)),  # MS-SAMR -> "samr"
    "winreg": ("338cd001-2244-31f1-aaaa-900038001003", (1, 0)),  # MS-RRP -> "winreg"
    # MS-WMI IWbemServices -> Zeek endpoint "IWbemServices". Real WMI rides DCOM over
    # ncacn_ip_tcp; we render the IWbemServices bind + ExecMethod opnum (the dce_rpc.log
    # signal BZAR watches) over the uniform SMB-pipe substrate. See the pack docs.
    "IWbemServices": ("9556dc99-828c-11cf-a37e-00aa003240c7", (0, 0)),
    # MS-RPCE endpoint mapper over ncacn_ip_tcp/135 -> Zeek endpoint "epmapper". Real tools
    # ept_map here to resolve a dynamic endpoint before the service RPC.
    "epmapper": ("e1af8308-5d1f-11c9-91a4-08002b14a0fa", (3, 0)),
    # MS-DRSR directory replication over ncacn_ip_tcp -> Zeek endpoint "drsuapi". DRSGetNCChanges
    # (opnum 3) from a non-DC host is the DCSync signal (T1003.006).
    "drsuapi": ("e3514235-4b06-11d1-ab04-00c04fc2dcd2", (4, 0)),
}

# Inert filler sizes (bytes) standing in for the NDR argument / return stubs. Zero bytes:
# provably free of any embedded string, command, path, or payload.
_REQ_STUB = 24
_RESP_STUB = 8


def _nb(pkt) -> bytes:
    return bytes(NBTSession() / pkt)


def _ifver(version: tuple) -> int:
    """Encode a (major, minor) interface version as DCE-RPC's p_syntax if_version int."""
    major, minor = version
    return (minor << 16) + major


def _bind_pdu(if_uuid: uuid.UUID, if_version: int, call_id: int) -> bytes:
    ctx = DceRpc5Context(
        cont_id=0,
        abstract_syntax=DceRpc5AbstractSyntax(if_uuid=if_uuid, if_version=if_version),
        transfer_syntaxes=[DceRpc5TransferSyntax(if_uuid=_NDR, if_version=2)],
    )
    return bytes(DceRpc5(ptype=11, call_id=call_id, pfc_flags=3)
                 / DceRpc5Bind(max_xmit_frag=4280, max_recv_frag=4280, context_elem=[ctx]))


def _bind_ack_pdu(pipe: str, call_id: int) -> bytes:
    result = DceRpc5Result(result=0, reason=0,
                           transfer_syntax=DceRpc5TransferSyntax(if_uuid=_NDR, if_version=2))
    ack = DceRpc5BindAck(max_xmit_frag=4280, max_recv_frag=4280, assoc_group_id=0x1234,
                         sec_addr=DceRpc5PortAny(port_spec=("\\PIPE\\" + pipe + "\x00").encode()),
                         results=[result])
    return bytes(DceRpc5(ptype=12, call_id=call_id, pfc_flags=3) / ack)


def _bind_ack_pdu_tcp(port: int, call_id: int) -> bytes:
    """A bind-ack for ncacn_ip_tcp: the secondary address is the TCP port, not a pipe."""
    result = DceRpc5Result(result=0, reason=0,
                           transfer_syntax=DceRpc5TransferSyntax(if_uuid=_NDR, if_version=2))
    ack = DceRpc5BindAck(max_xmit_frag=4280, max_recv_frag=4280, assoc_group_id=0x1234,
                         sec_addr=DceRpc5PortAny(port_spec=(str(port) + "\x00").encode()),
                         results=[result])
    return bytes(DceRpc5(ptype=12, call_id=call_id, pfc_flags=3) / ack)


def _sealed(call_id: int) -> CommonAuthVerifier:
    """An RPC packet-privacy (sealed) auth trailer — SPNEGO/Negotiate, auth_level 6, the way
    real Windows drsuapi/DCSync and lateral-movement RPC run. Its presence tells a dissector
    the stub is *encrypted*, so Wireshark shows "Encrypted stub data" and does not NDR-decode
    the inert filler (no Malformed-Packet exception), while Zeek still reads the interface and
    opnum from the cleartext header (conn.log service stays ``dce_rpc``, no auth sub-analyzer).
    The 16-byte auth value is opaque filler, deterministic from the call id — never a real
    token. SPNEGO (9), not NTLM (10), so Zeek does not tag an extra ``ntlm`` service."""
    token = b"\x01\x00\x00\x00" + call_id.to_bytes(8, "little") + call_id.to_bytes(4, "little")
    return CommonAuthVerifier(auth_type=9, auth_level=6, auth_pad_length=0,
                              auth_context_id=1, auth_value=token)


def _request_pdu(opnum: int, call_id: int) -> bytes:
    # ptype=0 (request), opnum names the operation; the stub is inert zero filler, sealed
    # (auth_level 6) so it is opaque encrypted stub data, not malformed NDR.
    return bytes(DceRpc5(ptype=0, call_id=call_id, pfc_flags=3, auth_verifier=_sealed(call_id))
                 / DceRpc5Request(opnum=opnum) / Raw(b"\x00" * _REQ_STUB))


def _response_pdu(call_id: int) -> bytes:
    return bytes(DceRpc5(ptype=2, call_id=call_id, pfc_flags=3, auth_verifier=_sealed(call_id))
                 / DceRpc5Response() / Raw(b"\x00" * _RESP_STUB))


def render_dcerpc(flow: Flow, orig: Endpoint, resp: Endpoint, rng: random.Random) -> RenderResult:
    spec: DceRpcL7 = flow.l7
    if spec.interface not in _INTERFACES:
        raise ValueError(
            f"unknown DCE-RPC interface {spec.interface!r} (flow_id={flow.flow_id}); "
            f"known: {sorted(_INTERFACES)}"
        )
    if not spec.operations:
        # A bind with no operations produces no dce_rpc.log row (nothing to detect); the
        # renderer would then emit an unsatisfiable ``produces: dce_rpc`` expectation.
        raise ValueError(
            f"DceRpcL7 requires at least one operation opnum (flow_id={flow.flow_id})"
        )
    if_uuid_str, version = _INTERFACES[spec.interface]
    if_uuid = uuid.UUID(if_uuid_str)
    if_version = _ifver(version)

    if spec.transport == "ncacn_ip_tcp":
        # DCE-RPC directly over TCP (e.g. the endpoint mapper on 135): a bind -> bind-ack, then
        # one request/response per opnum, with no SMB pipe wrapping. Zeek reads the interface and
        # each operation into dce_rpc.log the same way; conn.log service is just "dce_rpc".
        call_id = 1
        msgs = [TcpMessage(True, _bind_pdu(if_uuid, if_version, call_id)),
                TcpMessage(False, _bind_ack_pdu_tcp(resp.port, call_id))]
        for opnum in spec.operations:
            call_id += 1
            msgs += [TcpMessage(True, _request_pdu(opnum, call_id)),
                     TcpMessage(False, _response_pdu(call_id))]
        result = build_tcp_flow(orig, resp, msgs, start_time=flow.start_time,
                                rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
        conn = dict(result.summary)
        conn["service"] = "dce_rpc"
        conn["proto"] = "tcp"
        return RenderResult(packets=result.packets,
                            expected={"conn": conn, "produces": "dce_rpc"})

    sid = rng.randint(1, 0xFFFFFFFF)
    fid = rng.randbytes(16)  # deterministic 16-byte FileId (pipe handle)
    # SMB2 FILETIME (100 ns since 1601), pinned so ServerTime is deterministic (see smb.py).
    ft = int((flow.start_time + 11644473600) * 10_000_000)

    messages = [
        TcpMessage(True, _nb(SMB2_Header(Command=0)
                             / SMB2_Negotiate_Protocol_Request(Dialects=[0x0202, 0x0210, 0x0300]))),
        TcpMessage(False, _nb(SMB2_Header(Command=0, Flags=1)
                              / SMB2_Negotiate_Protocol_Response(DialectRevision=0x0300,
                                                                 ServerTime=ft, ServerStartTime=ft - 10**14))),
        TcpMessage(True, _nb(SMB2_Header(Command=1) / SMB2_Session_Setup_Request())),
        TcpMessage(False, _nb(SMB2_Header(Command=1, Flags=1, SessionId=sid)
                              / SMB2_Session_Setup_Response())),
        # Tree connect to IPC$ (ShareType=2 == PIPE), then open the named pipe.
        TcpMessage(True, _nb(SMB2_Header(Command=3, SessionId=sid)
                             / SMB2_Tree_Connect_Request(Buffer=[("Path", spec.share)]))),
        TcpMessage(False, _nb(SMB2_Header(Command=3, Flags=1, SessionId=sid)
                              / SMB2_Tree_Connect_Response(ShareType=2))),
        TcpMessage(True, _nb(SMB2_Header(Command=5, SessionId=sid)
                             / SMB2_Create_Request(Buffer=[("Name", spec.pipe)]))),
        TcpMessage(False, _nb(SMB2_Header(Command=5, Flags=1, SessionId=sid)
                              / SMB2_Create_Response(FileId=fid, CreationTime=ft, LastAccessTime=ft,
                                                     LastWriteTime=ft, ChangeTime=ft))),
    ]

    # DCE-RPC bind -> bind-ack over the pipe (write request PDU, read the response PDU).
    call_id = 1
    bind = _bind_pdu(if_uuid, if_version, call_id)
    ack = _bind_ack_pdu(spec.pipe, call_id)
    messages += [
        TcpMessage(True, _nb(SMB2_Header(Command=9, SessionId=sid)
                             / SMB2_Write_Request(FileId=fid, Buffer=[("Data", bind)]))),
        TcpMessage(False, _nb(SMB2_Header(Command=9, Flags=1, SessionId=sid)
                              / SMB2_Write_Response(Count=len(bind)))),
        TcpMessage(True, _nb(SMB2_Header(Command=8, SessionId=sid)
                             / SMB2_Read_Request(FileId=fid, Length=1024))),
        TcpMessage(False, _nb(SMB2_Header(Command=8, Flags=1, SessionId=sid)
                              / SMB2_Read_Response(Buffer=[("Data", ack)]))),
    ]

    # One request/response per operation. opnum names the op in Zeek; stub is inert filler.
    for opnum in spec.operations:
        call_id += 1
        req = _request_pdu(opnum, call_id)
        rsp = _response_pdu(call_id)
        messages += [
            TcpMessage(True, _nb(SMB2_Header(Command=9, SessionId=sid)
                                 / SMB2_Write_Request(FileId=fid, Buffer=[("Data", req)]))),
            TcpMessage(False, _nb(SMB2_Header(Command=9, Flags=1, SessionId=sid)
                                  / SMB2_Write_Response(Count=len(req)))),
            TcpMessage(True, _nb(SMB2_Header(Command=8, SessionId=sid)
                                 / SMB2_Read_Request(FileId=fid, Length=1024))),
            TcpMessage(False, _nb(SMB2_Header(Command=8, Flags=1, SessionId=sid)
                                  / SMB2_Read_Response(Buffer=[("Data", rsp)]))),
        ]

    messages += [
        TcpMessage(True, _nb(SMB2_Header(Command=6, SessionId=sid)
                             / SMB2_Close_Request(FileId=fid))),
        TcpMessage(False, _nb(SMB2_Header(Command=6, Flags=1, SessionId=sid)
                              / SMB2_Close_Response())),
    ]

    result = build_tcp_flow(orig, resp, messages, start_time=flow.start_time,
                            rtt=flow.rtt, rng=rng, conn_state=flow.conn_state)
    conn = dict(result.summary)
    # Zeek confirms both analyzers on this connection: SMB (the pipe) and DCE-RPC.
    conn["service"] = "smb,dce_rpc"
    conn["proto"] = "tcp"
    return RenderResult(packets=result.packets,
                        expected={"conn": conn, "produces": "dce_rpc"})
