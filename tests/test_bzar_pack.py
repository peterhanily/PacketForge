# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The BZAR lateral-movement pack: inert-by-construction invariants + a Zeek gate.

Two things are asserted here, both mechanically:

1. **Inert by construction.** The DCE-RPC L7 model carries no operation-argument fields,
   the operations are opnum ints, and the request/response *stubs* on the wire are zero
   filler — never a real command, service binary/path, or payload. (PDUs are sealed — RPC
   packet privacy — so an inert auth trailer follows the stub; it is not stub arguments and
   is covered by test_no_capability_strings_on_the_wire.) A change that tried to smuggle a
   functional payload into a scenario fails these tests.
2. **Labelled + detectable.** Every malicious flow declares its ATT&CK technique and the
   detection it should trip, and (when Zeek is present) really produces the
   ``dce_rpc.log`` endpoint + operation an analytic like BZAR keys on, with an empty
   ``weird.log``.
"""

import random
import struct
from pathlib import Path

import pytest

from packetforge.compile.timeline import compile_flowset
from packetforge.environments import load_environment
from packetforge.models.flowspec import CaptureMeta, DceRpcL7, Flow, FlowSet, SmbL7
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


# The inert file-body filler alphabet (renderers/file_bodies.py `_ascii`): letters, digits,
# and space only — no punctuation, so a base64/encoded payload (which needs +/=) cannot pass.
_FILLER_ALPHABET = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")


def _max_ascii_run(data: bytes) -> int:
    best = cur = 0
    for x in data:
        cur = cur + 1 if 0x20 <= x <= 0x7E else 0
        best = max(best, cur)
    return best


def _build(name):
    return build_attack(name, ENV, START, random.Random(1))


def _dcerpc_flows(intr):
    return [f for f in intr.flows if isinstance(f.l7, DceRpcL7)]


def _file_transfer_flows(intr):
    return [f for f in intr.flows
            if isinstance(f.l7, SmbL7) and (f.l7.read_file or f.l7.write_file)]


def _stream_from(packets, src_ip):
    """Concatenate one direction's TCP payloads in order. A transferred file arrives
    contiguously in one read/write, so its body appears intact here. A file the target
    returns (read) is in the responder stream; a file pushed to it (write) is in the
    originator stream."""
    return b"".join(bytes(p[Raw].load) for p in packets
                    if p.haslayer(Raw) and p[IP].src == src_ip)


_DCE_PTYPES = {0, 2, 11, 12}  # request, response, bind, bind_ack


def _dce_pdu_stubs(packets):
    """Yield (kind, stub_bytes) for every DCE-RPC request/response PDU, reassembled across
    TCP segments (so a stub larger than one MSS is still scanned) and matched on ptype
    regardless of pfc_flags. A PDU header is ``05 00 <ptype> <pfc_flags>`` then a 2-byte
    little-endian ``frag_length`` at offset 8; the common+type header is 24 bytes and the
    stub (where NDR arguments/returns would sit) is the rest of the frag. Raises if a PDU's
    declared frag_length runs past the reassembled bytes — a truncated or smuggled stub.

    ACK-only packets carry no payload, so concatenating every payload in packet order keeps
    each PDU (and its segments) contiguous; walking frag_length hops PDU-to-PDU, skipping
    the SMB2 framing between them.
    """
    raw = b"".join(bytes(p[Raw].load) for p in packets if p.haslayer(Raw))
    i, n = 0, len(raw)
    while i + 10 <= n:
        if raw[i] == 0x05 and raw[i + 1] == 0x00 and raw[i + 2] in _DCE_PTYPES:
            frag_len = int.from_bytes(raw[i + 8:i + 10], "little")
            if 24 <= frag_len <= 0xFFFF:
                if i + frag_len > n:
                    raise AssertionError(
                        f"DCE-RPC frag_length {frag_len} runs past the reassembled stream")
                if raw[i + 2] in (0, 2):
                    # Sealed PDUs (auth_length > 0) end with an 8-byte sec_trailer + the
                    # auth value, preceded by any auth pad; strip it so only the NDR stub
                    # is scanned. auth_pad_length is byte 2 of the sec_trailer.
                    auth_len = int.from_bytes(raw[i + 10:i + 12], "little")
                    if auth_len:
                        sectrailer = i + frag_len - 8 - auth_len
                        stub_end = sectrailer - raw[sectrailer + 2]
                    else:
                        stub_end = i + frag_len
                    yield ("request" if raw[i + 2] == 0 else "response"), raw[i + 24:stub_end]
                i += frag_len
                continue
        i += 1


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
        # A concrete, checkable detection expectation: the Zeek log signal (dce_rpc
        # operations or an smb_files admin-share write) is always declared, plus either a
        # BZAR notice (when one fires) or a plain detection note (when it does not).
        assert ("dce_rpc" in e.iocs) or ("smb_files" in e.iocs), e.iocs
        notice = e.iocs.get("expected_notice", "")
        assert notice.startswith("ATTACK::") or e.iocs.get("detection"), e.iocs


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
    # The model exposes protocol *shape* only: pipe/interface/opnums/labels/transport binding —
    # never a service binary, command line, task payload, or any operation argument. `transport`
    # selects ncacn_np vs ncacn_ip_tcp (the wire binding), not a payload.
    assert set(DceRpcL7.model_fields) == {"kind", "share", "pipe", "interface",
                                          "operations", "op_names", "transport"}


@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_operations_are_opnum_ints(name):
    for f in _dcerpc_flows(_build(name)):
        assert f.l7.operations, f.flow_id
        assert all(isinstance(op, int) for op in f.l7.operations)
        assert all(isinstance(n, str) for n in f.l7.op_names)  # labels only


@pytest.mark.parametrize("name", ["remote-service", "psexec-lateral"])
def test_psexec_resolves_endpoint_via_epmapper(name):
    # Real PsExec (sbousseaden/OTRF captures) resolves the target's dynamic RPC endpoint with
    # epmapper::ept_map over ncacn_ip_tcp/135 before the svcctl call; the renderer reproduces it.
    flows = _dcerpc_flows(_build(name))
    epm = [f for f in flows if f.l7.interface == "epmapper"]
    assert epm, f"{name}: expected an epmapper ept_map flow"
    assert epm[0].l7.transport == "ncacn_ip_tcp" and epm[0].dst_port == 135
    assert epm[0].l7.operations == [3]  # ept_map opnum
    # and the svcctl flow now carries the fuller service-install sequence, not just create/start
    svc = [f for f in flows if f.l7.interface == "svcctl"][0]
    for opnum in (16, 6):  # OpenServiceW, QueryServiceStatus — present in real PsExec
        assert opnum in svc.l7.operations, f"{name}: svcctl missing opnum {opnum}"


@pytest.mark.skipif(not validators_available(), reason="requires zeek + tshark")
def test_dcsync_emits_drsuapi_getncchanges(tmp_path):
    # DCSync's Zeek signal is drsuapi::DRSGetNCChanges over ncacn_ip_tcp from a non-DC host,
    # preceded by an epmapper endpoint lookup. (Real DCSync often Kerberos-seals the channel so
    # a real capture yields no dce_rpc.log; the inert build reproduces the detection signal.)
    from packetforge.validation import validate_flowset
    from packetforge.validation.roundtrip import _parse_zeek_log
    intr = _build("dcsync")
    fs = FlowSet(capture=CaptureMeta(), flows=intr.flows)
    report = validate_flowset(fs, keep_dir=str(tmp_path))
    assert report.zeek_weird == 0 and report.zeek_reporter == 0, report.summary()
    assert report.matched_flows == report.total_flows, report.summary()
    rows = {(r["endpoint"], r["operation"], r.get("id.orig_h", ""))
            for r in _parse_zeek_log(tmp_path / "dce_rpc.log")}
    attacker = intr.iocs["attacker"]
    assert any(ep == "drsuapi" and op == "DRSGetNCChanges" and oh == attacker
               for ep, op, oh in rows), f"no DCSync signal from {attacker}: {sorted(rows)}"
    assert any(op == "ept_map" for _, op, _ in rows), "DCSync should resolve the endpoint first"
    # the full Empire DCSync sequence, matched field-for-field to a real capture (OTRF empire_dcsync)
    drs_ops = {op for ep, op, _ in rows if ep == "drsuapi"}
    assert {"DRSBind", "DRSDomainControllerInfo", "DRSCrackNames", "DRSGetNCChanges",
            "DRSUnbind"} <= drs_ops, f"DCSync sequence incomplete: {sorted(drs_ops)}"


def test_dcsync_flow_is_inert():
    # No replicated secret / capability on the wire: drsuapi request stubs are zero filler.
    flows = _dcerpc_flows(_build("dcsync"))
    drs = [f for f in flows if f.l7.interface == "drsuapi"]
    assert drs and 3 in drs[0].l7.operations  # DRSGetNCChanges opnum
    pkts = compile_flowset(FlowSet(capture=CaptureMeta(), flows=_build("dcsync").flows)).packets
    for p in pkts:
        if Raw in p:
            body = bytes(p[Raw].load)
            assert not any(tok.lower() in body.lower() for tok in _FORBIDDEN)


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


def _assert_inert_shell(label, stream, file_bytes):
    # A transferred .exe must be an inert shell — a valid container header over synthetic
    # filler, never a working executable or shellcode. Checked on the wire, so it holds
    # regardless of how the file body is generated.
    mz = stream.find(b"MZ")
    assert mz != -1, f"{label}: expected the transferred file on the wire"
    pe = stream.find(b"PE\x00\x00", mz)
    assert pe != -1, f"{label}: transferred file is not a PE container"
    body = stream[mz:mz + file_bytes]
    pe_rel = pe - mz
    # NumberOfSections == 0: the shell maps no code/data section, so it cannot execute.
    n_sections = struct.unpack_from("<H", body, pe_rel + 6)[0]
    assert n_sections == 0, f"{label}: transferred PE has {n_sections} sections (not a shell)"
    # A standard-sized optional header, whose body (past its 2-byte magic) is all zero:
    # no data directories, no entry point, and no room to hide code by inflating it.
    size_opt = struct.unpack_from("<H", body, pe_rel + 20)[0]
    assert 0 < size_opt <= 0xF0, f"{label}: non-standard SizeOfOptionalHeader {size_opt}"
    header_end = pe_rel + 24 + size_opt
    assert set(body[pe_rel + 26:header_end]) <= {0}, \
        f"{label}: non-zero optional header (possible embedded code)"
    # Everything after the container header is synthetic filler (alnum + space) — not code,
    # not shellcode, and not an encoded (e.g. base64, which uses +/=) payload.
    assert set(body[header_end:]) <= _FILLER_ALPHABET, \
        f"{label}: transferred body past the header is not inert filler"
    # And no command/path string is smuggled into the header region itself.
    assert _max_ascii_run(body[:header_end]) < 6, \
        f"{label}: long ASCII string in the PE header region (possible embedded path/command)"


@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_transferred_files_are_inert_shells(name):
    for flow in _file_transfer_flows(_build(name)):
        comp = compile_flowset(FlowSet(flows=[flow]))
        # A written file rides the originator stream; a read file rides the responder's.
        src = flow.src_ip if flow.l7.write_file else flow.dst_ip
        _assert_inert_shell(name, _stream_from(comp.packets, src), flow.l7.file_bytes)


def test_read_direction_exe_is_also_an_inert_shell():
    # The pack transfers via SMB write; exercise the read path too (an .exe pulled from a
    # share) so the responder-stream branch and the shell property are covered both ways.
    flow = Flow(flow_id="atk-read-exe", transport="tcp", src_ip="10.10.0.40", dst_ip="10.10.0.41",
                src_port=50000, dst_port=445, start_time=START, conn_state="SF",
                l7=SmbL7(share="\\\\10.10.0.41\\Share", read_file="tool.exe", file_bytes=6144))
    comp = compile_flowset(FlowSet(flows=[flow]))
    _assert_inert_shell("read-exe", _stream_from(comp.packets, flow.dst_ip), flow.l7.file_bytes)


def test_pack_is_byte_deterministic():
    # Guards rng/ordering determinism (same seed -> identical bytes). Wall-clock leakage is
    # covered separately by test_determinism.test_no_renderer_reads_wall_clock, which drives
    # each renderer (incl. dcerpc) at clocks years apart.
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
    smb_paths = {r.get("path", "") for r in _parse_zeek_log(tmp_path / "smb_mapping.log")}
    for e in intr.ground_truth:
        want = e.iocs.get("dce_rpc")
        if want:
            for op in want["operations"]:
                assert (want["endpoint"], op) in dce_rows, \
                    f"{name}: expected dce_rpc {want['endpoint']}::{op}, saw {sorted(dce_rows)}"
        sf = e.iocs.get("smb_files")
        if sf:
            assert sf["name"] in smb_names, f"{name}: expected smb_files {sf['name']}, saw {smb_names}"
            # The tool-transfer property: Zeek resolved the tree onto the declared admin
            # share (its path is what BZAR's ADMIN$/C$ test keys on). Enforced here, always,
            # not only in the opt-in BZAR gate.
            assert any(sf["share"] in p for p in smb_paths), \
                f"{name}: expected an SMB tree mapped to {sf['share']}, saw paths {smb_paths}"


# --------------------------------------------------------------------------- #
# BZAR gate — the analytic must actually raise the ATT&CK notice we claim.      #
# Opt-in: point PF_BZAR_PATH at bzar/scripts (or install BZAR via zkg).         #
# --------------------------------------------------------------------------- #
def _bzar_scripts():
    import os
    candidates = [os.environ.get("PF_BZAR_PATH"),
                  "/opt/zeek/share/zeek/site/bzar/scripts",
                  os.path.expanduser("~/.zkg/clones/package/bzar/scripts")]
    for c in candidates:
        if c and (Path(c) / "__load__.zeek").exists():
            return c
    return None


@pytest.mark.skipif(not validators_available() or _bzar_scripts() is None,
                    reason="requires zeek + the BZAR scripts (set PF_BZAR_PATH)")
@pytest.mark.parametrize("name", sorted(BZAR_PACK))
def test_builder_trips_expected_bzar_notice(name, tmp_path):
    """Render the fixture, run Zeek + BZAR, and assert every declared ATT&CK notice fires."""
    import subprocess

    from packetforge.compile.timeline import write_pcap
    from packetforge.validation.roundtrip import _parse_zeek_log

    intr = _build(name)
    pcap = tmp_path / "c.pcap"
    write_pcap(FlowSet(flows=intr.flows), pcap)
    subprocess.run(["zeek", "-r", str(pcap), _bzar_scripts(), "FilteredTraceDetection::enable=F"],
                   cwd=str(tmp_path), capture_output=True, text=True, check=False)
    fired = {r.get("note", "") for r in _parse_zeek_log(tmp_path / "notice.log")}
    expected = {e.iocs["expected_notice"] for e in intr.ground_truth if e.iocs.get("expected_notice")}
    for want in expected:
        assert want in fired, f"{name}: expected BZAR notice {want}, saw {sorted(fired) or '(none)'}"
