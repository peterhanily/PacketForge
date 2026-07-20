# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Real-C2 fingerprint reproduction: inert beacons that trip real published detections."""

import hashlib

import pytest

from packetforge.c2_fingerprints import HTTP_C2_FAMILIES, JA3_FAMILIES
from packetforge.detect import suricata_available
from packetforge.environments import load_environment
from packetforge.malware_transfer import build_http_c2_reference, real_families
from packetforge.validation import validators_available

REPO = __import__("pathlib").Path(__file__).resolve().parent.parent
ET_JA3 = REPO / "detection" / "etopen" / "rules" / "emerging-ja3.rules"


def test_ja3_family_strings_hash_to_their_rule_hash():
    # Each vendored JA3 string is the real preimage of the ET rule's ja3.hash MD5 — so a
    # rendered ClientHello that reproduces the string trips the real rule.
    for name, fam in JA3_FAMILIES.items():
        assert hashlib.md5(fam["ja3"].encode()).hexdigest() == fam["ja3_md5"], name


def test_real_families_are_registered():
    assert set(real_families()) == set(JA3_FAMILIES)


@pytest.mark.parametrize("family", sorted(HTTP_C2_FAMILIES))
def test_http_c2_beacon_carries_the_family_signature(family):
    env = load_environment("office")
    fs = build_http_c2_reference(family, env, seed=1, beacons=10, noise_flows=3)
    beacons = [f for f in fs.flows if f.flow_id.startswith(f"c2-{family}")]
    assert beacons, "no beacon flows rendered"
    uris = " ".join(b.l7.uri for b in beacons)
    fam = HTTP_C2_FAMILIES[family]
    if "uri_scheme" in fam:                       # Sliver: extension-encoded type + nonce
        assert "_=" in uris and any(ext in uris for ext in fam["uri_scheme"])
    elif "query_param" in fam:                    # Mythic: /index?q=<base64>
        assert f"{fam['get_uri']}?{fam['query_param']}=" in uris
    else:                                         # CS / Havoc: default URI set
        wanted = fam.get("get_uris") or fam.get("uris")
        assert any(u in uris for u in wanted)
    # request markers (Havoc's X-Havoc header, everyone's UA)
    assert all(b.l7.user_agent == fam.get("user_agent", "Mozilla/5.0") for b in beacons)
    for k, v in fam.get("req_headers", {}).items():
        assert beacons[0].l7.request_headers.get(k) == v


@pytest.mark.skipif(not (suricata_available() and validators_available()),
                    reason="requires suricata + tshark on PATH")
@pytest.mark.skipif(not ET_JA3.exists(), reason="ET Open ja3 ruleset not present")
@pytest.mark.parametrize("family", sorted(JA3_FAMILIES))
def test_real_family_beacon_trips_real_et_rule(family, tmp_path):
    from packetforge.malware_transfer import malware_transfer_proof
    rep = malware_transfer_proof(load_environment("office"), family, ET_JA3, seed=2,
                                 workdir=str(tmp_path))
    # the inert beacon reproduces the family JA3 and the SAME real ET rule fires on both
    # the reference and its independently-rebuilt analog — detection transfers, zero malware.
    assert rep.reproduced, rep.render()
    assert rep.same_verdict, rep.render()
    assert any("JA3 Hash" in s for s in rep.reference_alerts), rep.render()
