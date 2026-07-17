# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The BZAR lateral-movement pack: inert-by-construction invariants + a Zeek gate.

Two things are asserted here, both mechanically:

1. **Inert by construction.** The DCE-RPC L7 model carries no operation-argument fields,
   the operations are opnum ints, and the request/response *stubs* on the wire are zero
   filler — never a real command, service binary/path, or payload. A change that tried to
   smuggle a functional payload into a scenario fails these tests.
2. **Labelled + detectable.** Every malicious flow declares its ATT&CK technique and the
   detection it should trip, and (when Zeek is present) really produces the
   ``dce_rpc.log`` endpoint + operation an analytic like BZAR keys on, with an empty
   ``weird.log``.
"""

import random
import struct

import pytest

from packetforge.compile.timeline import compile_flowset
from packetforge.environments import load_environment
from packetforge.models.flowspec import CaptureMeta, DceRpcL7, FlowSet, SmbL7
from packetforge.scenarios import BZAR_PACK, build_attack, list_attacks
from packetforge.validation import validators_available
from scapy.layers.inet import IP
from scapy.packet import Raw

ENV = load_environment("office")
START = 1_700_000_000.0

# Command/LOLBin tokens that would indicate a real capability was smuggled onto the wire.
# The pack renders operation shape only, so none of these may ever appear in any packet.
_FORBIDDEN = [
    b"cmd.exe", b"cmd /c", b"cmd /k", b"powershell", b"pwsh", b"rundll32", b"regsvr32",
    b"certutil", b"bitsadmin", b"mshta", b"wscript", b"cscript", b"wmic", b"net user",
    b"net localgroup", b"whoami", b"schtasks", b"\\System32\\", b"-enc ", b"-EncodedCommand",
]


def _build(name):
    return build_attack(name, ENV, START, random.Random(1))


def _dcerpc_flows(intr):
    return [f for f in intr.flows if isinstance(f.l7, DceRpcL7)]


def _file_transfer_flows(intr):
    return [f for f in intr.flows if isinstance(f.l7, SmbL7) and f.l7.read_file]


def _responder_stream(packets, resp_ip):
    """Concatenate the responder's TCP payloads in order. A file the target returns over
    SMB arrives contiguously in one read response, so its body appears intact here."""
    return b"".join(bytes(p[Raw].load) for p in packets
                    if p.haslayer(Raw) and p[IP].src == resp_ip)


def _dce_pdu_stubs(packets):
    """Yield (kind, stub_bytes) for every DCE-RPC request/response PDU on the wire.

    A connection-oriented DCE-RPC PDU begins ``05 00 <ptype> 03`` (v5, minor 0,
    pfc_flags=FIRST|LAST); request=0x00, response=0x02. The common+type header is 24
    bytes; the stub (where NDR arguments/returns would sit) is the remainder of the frag.
    """
    for p in packets:
        raw = bytes(p[Raw].load) if p.haslayer(Raw) else b""
        i = 0
        while i < len(raw):
            cand = [x for x in (raw.find(b"\x05\x00\x00\x03", i),
                                raw.find(b"\x05\x00\x02\x03", i)) if x != -1]
            if not cand:
                break
            j = min(cand)
            frag_len = int.from_bytes(raw[j + 8:j + 10], "little")
            if frag_len < 24 or j + frag_len > len(raw):
                i = j + 4
                continue
            kind = "request" if raw[j + 2] == 0 else "response"
            yield kind, raw[j + 24:j + frag_len]
            i = j + frag_len


# --------------------------------------------------------------------------- #
# Registration + labelling                                                     #
# --------------------------------------------------------------------------- #
def test_pack_is_registered():
    for name in BZAR_PACK:
        assert name in list_attacks()


@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_builder_declares_technique_and_expected_detection(name):
    intr = _build(name)
    assert intr.flows and intr.ground_truth
    assert all(f.flow_id.startswith("atk-") for f in intr.flows)
    for e in intr.ground_truth:
        assert e.technique.startswith("T1"), e.technique
        # A concrete, checkable detection expectation: the BZAR notice AND the Zeek log
        # signal (dce_rpc endpoint/operations or an smb_files admin-share write).
        assert e.iocs.get("expected_notice", "").startswith("ATTACK::"), e.iocs
        assert ("dce_rpc" in e.iocs) or ("smb_files" in e.iocs), e.iocs


# --------------------------------------------------------------------------- #
# Inert by construction                                                        #
# --------------------------------------------------------------------------- #
def test_dcerpc_requires_operations():
    # A DCE-RPC flow with no operations produces no dce_rpc.log signal; the renderer must
    # reject it up front rather than emit an unsatisfiable expectation.
    from packetforge.compile.timeline import _seed
    from packetforge.fingerprints import resolve_endpoint
    from packetforge.models.flowspec import Flow
    from packetforge.renderers.dcerpc import render_dcerpc

    flow = Flow(flow_id="x", transport="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.9",
                src_port=50000, dst_port=445, start_time=START, conn_state="SF",
                l7=DceRpcL7(interface="svcctl", pipe="svcctl", operations=[]))
    o = resolve_endpoint("10.0.0.5", 50000, "windows_10")
    r = resolve_endpoint("10.0.0.9", 445, "linux")
    with pytest.raises(ValueError, match="at least one operation"):
        render_dcerpc(flow, o, r, _seed(flow, ""))


def test_dcerpc_model_has_no_argument_fields():
    # The model exposes protocol *shape* only: pipe/interface/opnums/labels — never a
    # service binary, command line, task payload, or any operation argument.
    assert set(DceRpcL7.model_fields) == {"kind", "share", "pipe", "interface",
                                          "operations", "op_names"}


@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_operations_are_opnum_ints(name):
    for f in _dcerpc_flows(_build(name)):
        assert f.l7.operations, f.flow_id
        assert all(isinstance(op, int) for op in f.l7.operations)
        assert all(isinstance(n, str) for n in f.l7.op_names)  # labels only


@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_dcerpc_stubs_are_inert_zero_filler(name):
    intr = _build(name)
    comp = compile_flowset(FlowSet(flows=intr.flows))
    stubs = list(_dce_pdu_stubs(comp.packets))
    if _dcerpc_flows(intr):
        assert stubs, f"{name}: expected DCE-RPC request/response PDUs on the wire"
    for kind, stub in stubs:
        assert set(stub) <= {0}, f"{name}: non-inert {kind} stub {stub[:32]!r}"


@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_no_capability_strings_on_the_wire(name):
    intr = _build(name)
    comp = compile_flowset(FlowSet(flows=intr.flows))
    blob = b"".join(bytes(p[Raw].load) for p in comp.packets if p.haslayer(Raw))
    low = blob.lower()
    for tok in _FORBIDDEN:
        assert tok.lower() not in low, f"{name}: forbidden token {tok!r} on the wire"


def test_every_pack_flow_is_a_gated_inert_type():
    # Completeness guard: every malicious flow is one of the two inert types this suite
    # gates — a DCE-RPC operation-shape flow (zero-filler stubs) or an SMB file transfer
    # (inert shell, checked below). A new builder emitting any other flow type — a path
    # that could carry a real payload ungated — fails here.
    for name in sorted(BZAR_PACK):
        for f in _build(name).flows:
            assert isinstance(f.l7, (DceRpcL7, SmbL7)), f"{name}: ungated flow type {f.l7.kind}"


@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_transferred_files_are_inert_shells(name):
    # A "lateral tool transfer" flow (svc.exe to ADMIN$) must carry an inert shell — a
    # valid container header over synthetic printable filler — never a working executable
    # or shellcode. This is checked on the wire, so it holds regardless of how the file
    # body is generated: swapping the filler for a real PE (code section) or shellcode
    # (binary opcodes in the body) fails this test.
    intr = _build(name)
    xfers = _file_transfer_flows(intr)
    for flow in xfers:
        comp = compile_flowset(FlowSet(flows=[flow]))
        stream = _responder_stream(comp.packets, flow.dst_ip)
        mz = stream.find(b"MZ")
        assert mz != -1, f"{name}: expected the transferred file on the wire"
        pe = stream.find(b"PE\x00\x00", mz)
        assert pe != -1, f"{name}: transferred file is not a PE container"
        # NumberOfSections == 0: the shell maps no code/data section, so it cannot execute.
        n_sections = struct.unpack_from("<H", stream, pe + 6)[0]
        assert n_sections == 0, f"{name}: transferred PE has {n_sections} sections (not a shell)"
        # Past the container header, the body is printable filler — no code / shellcode
        # bytes. Non-printable bytes must be confined to the header region (< 512 B).
        body = stream[mz:mz + flow.l7.file_bytes]
        tail = body[512:]
        assert all(0x20 <= b <= 0x7E for b in tail), \
            f"{name}: non-printable bytes past the header (possible embedded code)"


def test_pack_is_byte_deterministic():
    for name in sorted(BZAR_PACK):
        a = compile_flowset(FlowSet(flows=_build(name).flows))
        b = compile_flowset(FlowSet(flows=_build(name).flows))
        assert [bytes(p) for p in a.packets] == [bytes(p) for p in b.packets], name


# --------------------------------------------------------------------------- #
# Zeek round-trip gate — the endpoint+operation must really appear, weird empty #
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark on PATH")
@pytest.mark.parametrize("texture", ["clean", "realistic", "conditioned"])
@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_builder_is_zeek_clean_and_detectable(name, texture, tmp_path):
    # Validate under every texture the composer/corpus ships (clean + the jitter/retransmit
    # and heavy-tailed/large-segment variants), so a framing regression that only surfaces
    # under a non-clean texture is caught, not just the byte-exact ideal flow.
    from packetforge.validation import validate_flowset
    from packetforge.validation.roundtrip import _parse_zeek_log

    intr = _build(name)
    fs = FlowSet(capture=CaptureMeta(texture=texture), flows=intr.flows)
    report = validate_flowset(fs, keep_dir=str(tmp_path))
    # Zeek reassembles cleanly and every flow's conn.log matches what we rendered.
    assert report.zeek_weird == 0, report.summary()
    assert report.zeek_reporter == 0, report.summary()
    assert report.matched_flows == report.total_flows, report.summary()
    assert not report.mismatches, report.summary()

    dce_rows = {(r["endpoint"], r["operation"]) for r in _parse_zeek_log(tmp_path / "dce_rpc.log")}
    smb_names = {r.get("name", "") for r in _parse_zeek_log(tmp_path / "smb_files.log")}
    for e in intr.ground_truth:
        want = e.iocs.get("dce_rpc")
        if want:
            for op in want["operations"]:
                assert (want["endpoint"], op) in dce_rows, \
                    f"{name}: expected dce_rpc {want['endpoint']}::{op}, saw {sorted(dce_rows)}"
        sf = e.iocs.get("smb_files")
        if sf:
            assert sf["name"] in smb_names, f"{name}: expected smb_files {sf['name']}, saw {smb_names}"
