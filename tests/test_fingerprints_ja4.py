# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase D: JA4/HASSH fingerprints + byte-exact JA3 verified by an external tool."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from packetforge.fingerprints.ja3 import ja3_hash
from packetforge.fingerprints.ja4 import hassh, ja4, ja4_from_profile
from packetforge.fingerprints.loader import load_ja3_profile

REPO = Path(__file__).resolve().parent.parent


def test_ja4_structure_and_determinism():
    curl = load_ja3_profile("curl")
    fp = ja4_from_profile(curl)
    a, b, c = fp.split("_")
    assert a.startswith("t12d")           # TCP, TLS1.2, SNI present
    assert a[4:6] == f"{len(curl['ciphers']):02d}"   # cipher count
    assert len(b) == 12 and len(c) == 12
    assert ja4_from_profile(curl) == fp   # deterministic


def test_ja4_discriminates_clients():
    assert ja4_from_profile(load_ja3_profile("curl")) != \
        ja4_from_profile(load_ja3_profile("generic_browser"))


def test_ja4_grease_is_excluded():
    # adding a GREASE cipher/extension must not change the JA4
    base = ja4(771, [49200, 49196], [0, 11, 10], signature_algorithms=[1027])
    withg = ja4(771, [0x0a0a, 49200, 49196], [0x1a1a, 0, 11, 10], signature_algorithms=[1027])
    assert base == withg


def test_hassh_matches_ssh_renderer_kexinit():
    # HASSH must be computed from the same lists the SSH renderer puts on the wire
    from packetforge.renderers.ssh import _KEX_LISTS
    kex, enc_c2s, mac_c2s, comp_c2s = _KEX_LISTS[0], _KEX_LISTS[2], _KEX_LISTS[4], _KEX_LISTS[6]
    h = hassh(kex, enc_c2s, mac_c2s, comp_c2s)
    assert len(h) == 32 and all(ch in "0123456789abcdef" for ch in h)
    # deterministic + sensitive to the algorithm set
    assert h == hassh(kex, enc_c2s, mac_c2s, comp_c2s)
    assert h != hassh(kex, "aes128-ctr", mac_c2s, comp_c2s)


def _have_pyja3():
    return (Path(sys.executable).parent / "ja3").exists() or bool(shutil.which("ja3"))


def _tshark_ja4(pcap):
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-Y", "tls.handshake.type==1", "-T", "fields",
         "-e", "tls.handshake.ja4"], capture_output=True, text=True).stdout
    return out.strip().splitlines()[0].strip() if out.strip() else ""


@pytest.mark.skipif(not shutil.which("tshark"), reason="requires tshark on PATH")
def test_ja4_is_byte_exact_to_wireshark(tmp_path):
    """Our JA4 must equal what Wireshark/tshark computes natively for the same ClientHello."""
    from packetforge.compile.timeline import write_pcap
    from packetforge.fingerprints.ja4 import ja4_from_profile
    from packetforge.models.flowspec import CaptureMeta, Flow, FlowSet, TlsL7

    for profile_name in ("generic_browser", "curl"):
        flow = Flow(flow_id="t", transport="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.9",
                    src_port=50000, dst_port=443, start_time=1700000000.0, conn_state="SF",
                    l7=TlsL7(server_name="x.example", client_profile=profile_name))
        pcap = tmp_path / f"{profile_name}.pcap"
        write_pcap(FlowSet(capture=CaptureMeta(), flows=[flow]), pcap)
        theirs = _tshark_ja4(pcap)
        if not theirs:
            pytest.skip("this tshark build does not emit tls.handshake.ja4")
        ours = ja4_from_profile(load_ja3_profile(profile_name))
        assert ours == theirs, f"{profile_name}: ours={ours} tshark={theirs}"


@pytest.mark.skipif(not _have_pyja3(), reason="requires the external pyja3 tool")
def test_ja3_is_byte_exact_to_external_tool(tmp_path):
    """The JA3 PacketForge declares == what an independent tool reads off the wire."""
    from packetforge.compile.timeline import write_pcap
    from packetforge.models.flowspec import CaptureMeta, Flow, FlowSet, TlsL7

    import json
    for profile_name in ("curl", "generic_browser"):
        prof = load_ja3_profile(profile_name)
        want = ja3_hash(prof.get("tls_version", 771), prof["ciphers"], prof["extensions"],
                        prof["curves"], prof["point_formats"])
        flow = Flow(flow_id="t", transport="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.9",
                    src_port=50000, dst_port=443, start_time=1700000000.0, conn_state="SF",
                    l7=TlsL7(server_name="x.example", client_profile=profile_name))
        pcap = tmp_path / f"{profile_name}.pcap"
        write_pcap(FlowSet(capture=CaptureMeta(), flows=[flow]), pcap)
        ja3_bin = str(Path(sys.executable).parent / "ja3")
        out = subprocess.run([ja3_bin, "--json", str(pcap)], capture_output=True, text=True).stdout
        digests = {e["ja3_digest"] for e in json.loads(out)}
        assert want in digests, f"{profile_name}: internal {want} not in external {digests}"
