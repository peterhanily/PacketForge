# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""JA3 computation."""

import hashlib

from packetforge.fingerprints.ja3 import is_grease, ja3_hash, ja3_string


def test_ja3_string_format():
    s = ja3_string(771, [49199, 47], [0, 10, 11], [29, 23], [0])
    assert s == "771,49199-47,0-10-11,29-23,0"


def test_ja3_hash_is_md5_of_string():
    s = ja3_string(771, [49199, 47], [0, 10, 11], [29, 23], [0])
    assert ja3_hash(771, [49199, 47], [0, 10, 11], [29, 23], [0]) == hashlib.md5(s.encode()).hexdigest()


def test_grease_values_excluded():
    # 0x0a0a (2570) and 0x1a1a (6682) are GREASE and must drop out.
    assert is_grease(0x0A0A)
    assert is_grease(0x1A1A)
    assert not is_grease(49199)
    s = ja3_string(771, [0x0A0A, 49199], [0x1A1A, 0], [], [])
    assert s == "771,49199,0,,"


def _profile_ja3(name):
    from packetforge.fingerprints.loader import load_ja3_profile
    p = load_ja3_profile(name)
    return ja3_hash(p["tls_version"], p["ciphers"], p["extensions"], p["curves"], p["point_formats"])


def test_profile_ja3_is_stable():
    h1 = _profile_ja3("generic_browser")
    assert h1 == _profile_ja3("generic_browser") and len(h1) == 32


def test_profiles_have_distinct_ja3():
    # JA3 is only a useful pivot if different client types fingerprint differently.
    assert _profile_ja3("generic_browser") != _profile_ja3("curl")
