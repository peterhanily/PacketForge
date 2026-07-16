# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Captures survive a full forensic toolchain: Wireshark-grade dissection with no
malformed packets, and extractable artifacts (files, certs) that are valid on the wire.
"""
import random
import subprocess

import pytest

from packetforge.validation import validators_available


def _tshark(pcap, *args):
    return subprocess.run(["tshark", "-r", str(pcap), *args],
                          capture_output=True, text=True, check=False).stdout


def test_synthetic_cert_is_deterministic_and_matches_cn():
    from cryptography import x509

    from packetforge.fingerprints.certs import synthetic_cert_der
    a = synthetic_cert_der("secure.example", 42, 1700000000.0)
    b = synthetic_cert_der("secure.example", 42, 1700000000.0)
    assert a == b  # deterministic (fixed key, RSA PKCS#1 v1.5, no wall-clock)
    cert = x509.load_der_x509_certificate(a)
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "secure.example"
    assert synthetic_cert_der("other.example", 42, 1700000000.0) != a


def test_file_bodies_have_valid_magic_and_exact_size():
    from packetforge.renderers.file_bodies import file_for
    magic = {"/a.pdf": b"%PDF-", "/a.png": b"\x89PNG", "/a.gif": b"GIF89a",
             "/a.jpg": b"\xff\xd8\xff", "/a.zip": b"PK\x03\x04", "/a.exe": b"MZ"}
    for uri, sig in magic.items():
        body, ctype = file_for(uri, 3000, random.Random(1))
        assert body.startswith(sig), f"{uri}: bad magic {body[:6]!r}"
        assert len(body) == 3000, f"{uri}: size {len(body)} != 3000"
    # unknown extension -> valid HTML
    body, ctype = file_for("/api/status", 900, random.Random(1))
    assert b"<html" in body.lower() and "html" in ctype


@pytest.mark.skipif(not validators_available(), reason="requires tshark on PATH")
def test_no_malformed_packets_across_protocols(tmp_path):
    """A rich multi-protocol capture must dissect with zero malformed packets."""
    from packetforge.compile.timeline import write_pcap
    from packetforge.compose import compose_scenario
    from packetforge.environments import load_environment
    from packetforge.scenarios import build_attack

    env = load_environment("office")
    intr = build_attack("kerberoasting", env, 1700000100.0, random.Random(3))
    fs = compose_scenario(env, start_time=1700000000.0, noise_flows=250, seed=3,
                          storyline=intr.flows, texture="realistic")
    pcap = tmp_path / "rich.pcap"
    write_pcap(fs, pcap)
    malformed = _tshark(pcap, "-Y", "_ws.malformed").strip()
    assert malformed == "", f"malformed packets present:\n{malformed[:500]}"


@pytest.mark.skipif(not validators_available(), reason="requires tshark on PATH")
def test_tls_certificate_extractable_and_valid(tmp_path):
    from cryptography import x509

    from packetforge.compile.timeline import write_pcap
    from packetforge.models.flowspec import CaptureMeta, Flow, FlowSet, TlsL7

    flow = Flow(flow_id="t", transport="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.9",
                src_port=50000, dst_port=443, start_time=1700000000.0, conn_state="SF",
                l7=TlsL7(server_name="mail.corp.example", version="TLS1.2"))
    pcap = tmp_path / "tls.pcap"
    write_pcap(FlowSet(capture=CaptureMeta(), flows=[flow]), pcap)

    # a Certificate handshake message (type 11) is present
    assert _tshark(pcap, "-Y", "tls.handshake.type == 11").strip()
    # extract the cert bytes and validate the X.509
    hexstr = _tshark(pcap, "-Y", "tls.handshake.certificate", "-T", "fields",
                     "-e", "tls.handshake.certificate").strip().splitlines()[0].replace(":", "")
    der = bytes.fromhex(hexstr)
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "mail.corp.example"  # cert subject matches the SNI


@pytest.mark.skipif(not validators_available(), reason="requires tshark on PATH")
def test_http_object_exports_as_valid_file(tmp_path):
    from packetforge.compile.timeline import write_pcap
    from packetforge.models.flowspec import CaptureMeta, Flow, FlowSet, HttpL7

    flow = Flow(flow_id="h", transport="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.9",
                src_port=50001, dst_port=80, start_time=1700000000.0, conn_state="SF",
                l7=HttpL7(method="GET", host="files.example", uri="/report.pdf",
                          status=200, response_body_len=4096))
    pcap = tmp_path / "http.pcap"
    write_pcap(FlowSet(capture=CaptureMeta(), flows=[flow]), pcap)
    outdir = tmp_path / "objs"
    outdir.mkdir()
    _tshark(pcap, "--export-objects", f"http,{outdir}", "-q")
    files = list(outdir.iterdir())
    assert files, "no HTTP object exported"
    assert files[0].read_bytes().startswith(b"%PDF-"), "exported object is not a valid PDF"


@pytest.mark.skipif(not validators_available(), reason="requires tshark on PATH")
def test_smb_file_read_exports_valid_file(tmp_path):
    from packetforge.compile.timeline import write_pcap
    from packetforge.models.flowspec import CaptureMeta, Flow, FlowSet, SmbL7

    flow = Flow(flow_id="s", transport="tcp", src_ip="10.10.0.30", dst_ip="10.10.0.20",
                src_port=50002, dst_port=445, start_time=1700000000.0, conn_state="SF",
                l7=SmbL7(share="\\\\FILESRV\\HR", read_file="payroll.zip", file_bytes=6000))
    pcap = tmp_path / "smb.pcap"
    write_pcap(FlowSet(capture=CaptureMeta(), flows=[flow]), pcap)
    assert _tshark(pcap, "-Y", "_ws.malformed").strip() == ""
    outdir = tmp_path / "so"
    outdir.mkdir()
    _tshark(pcap, "--export-objects", f"smb,{outdir}", "-q")
    files = [f for f in outdir.iterdir() if f.stat().st_size > 0]
    assert files, "no SMB object exported"
    assert files[0].read_bytes().startswith(b"PK\x03\x04"), "exported SMB object is not a valid zip"


@pytest.mark.skipif(not validators_available(), reason="requires tshark on PATH")
def test_ftp_data_channel_transfers_valid_file(tmp_path):
    from packetforge.compile.timeline import write_pcap
    from packetforge.models.flowspec import CaptureMeta, Flow, FlowSet, FtpL7

    flow = Flow(flow_id="f", transport="tcp", src_ip="10.10.0.30", dst_ip="10.10.0.50",
                src_port=50003, dst_port=21, start_time=1700000000.0, conn_state="SF",
                l7=FtpL7(user="admin", retrieve_file="database.zip", file_bytes=9000))
    pcap = tmp_path / "ftp.pcap"
    write_pcap(FlowSet(capture=CaptureMeta(), flows=[flow]), pcap)
    assert _tshark(pcap, "-Y", "_ws.malformed").strip() == ""
    # tshark correlates the PASV data connection to the RETR
    assert "database.zip" in _tshark(pcap, "-Y", "ftp-data")
    # the file streamed over the data connection is a valid zip
    stream = _tshark(pcap, "-Y", "ftp-data", "-T", "fields", "-e", "tcp.stream").split()[0]
    payload = _tshark(pcap, "-Y", f"tcp.stream=={stream} && ip.src==10.10.0.50 && tcp.len>0",
                      "-T", "fields", "-e", "tcp.payload").replace("\n", "").strip()
    assert bytes.fromhex(payload).startswith(b"PK\x03\x04"), "FTP-transferred file is not a valid zip"
