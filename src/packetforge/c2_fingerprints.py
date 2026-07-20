# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Vendored real-C2 network fingerprints — the transfer-proof ground truth.

Reproducing a real malware family's observable network **signal** (its JA3, its HTTP-C2 URI
scheme, its named pipes) in an otherwise-inert flow lets a *real, published* detection rule
fire on synthetic traffic — proving a detection tuned on real malware also catches ours,
with **zero malware, no real C2, benign payloads**. This is "reproduce the detection signal,
never the offensive capability" applied to the transfer-proof question.

The values below are **facts** (fingerprints, hashes, URI paths), gathered from public /
CC0-licensed threat intel and cited per entry. A JA3 MD5 is not invertible, so each JA3
family carries a real preimage *string* (from the trisul ja3fingerprint.json corpus, which
ET's own rules reference) that is MD5-verified to match the ET Open rule's hash.

Sources:
- ET Open ``emerging-ja3.rules`` (the ``ja3.hash`` SIDs) — Emerging Threats / Proofpoint.
- trisulnsm ``ja3fingerprint.json`` (raw JA3 strings paired with hashes) — the corpus ET cites.
- abuse.ch SSLBL JA3 blocklist (CC0) — hash+family list.
- Cobalt Strike malleable-C2 defaults (Unit 42; The DFIR Report). Sliver HTTP(S)-C2 wiki
  (BishopFox). Mythic ``http`` profile ``builder.go`` (MythicC2Profiles). Havoc profile docs.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# JA3 families: a real ClientHello JA3 string whose MD5 matches a STANDALONE ET Open
# ``ja3.hash`` rule (fires on the client hello alone). Rendering a TLS beacon with this JA3
# trips the real rule. MD5-verified against the rule hash.
# --------------------------------------------------------------------------- #
JA3_FAMILIES = {
    "metasploit_ssl_scanner": {
        "label": "Metasploit SSL Scanner",
        "ja3": "769,49172-49162-57-56-136-135-49167-49157-53-132-49171-49161-51-50-154-153-"
               "69-68-49166-49156-47-150-65-49169-49159-49164-49154-5-4-49170-49160-22-19-"
               "49165-49155-10-21-18-9-255,11-10-35-15,14-13-25-11-12-24-9-10-22-23-8-6-7-"
               "20-21-4-5-18-19-1-2-3-15-16-17,0-1-2",
        "ja3_md5": "6825b330bf9de50ccc8745553cb61b2f",
        "et_sid": 2028304,
        "sni": "scan-probe.example",
        "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
    },
    "metasploit_ccs_scanner": {
        "label": "Metasploit CCS (heartbleed) Scanner",
        "ja3": "769,49172-49162-49186-49185-57-56-136-135-135-49167-53-132-49170-49160-49180-"
               "49179-22-19-49165-49155-10-49171-49161-49183-49182-51-50-154-153-69-68-49166-"
               "49156-47-150-65-49169-49159-49164-49154-5-4-21-18-9-20-17-8-6-3-255,,,",
        "ja3_md5": "950ccdd64d360a7b24c70678ac116a44",
        "et_sid": 2028302,
        "sni": "ccs-probe.example",
        "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
    },
    "dridex": {
        "label": "Dridex (banking trojan) TLS C2",
        "ja3": "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,65281-5-10-11,23-24,0",
        "ja3_md5": "67f762b0ffe3aad00dfdb0e4b1acd8b5",
        "et_sid": 2028365,
        "sni": "secure.node-metrics.example",
        "technique": "T1071.001 Web Protocols (banking-trojan C2)",
    },
    "gootkit": {
        "label": "Gootkit TLS C2",
        "ja3": "769,49169-49159-49164-49154-5-49172-49162-57-56-136-135-49167-49157-53-132-"
               "49171-49161-51-50-69-68-49166-49156-47-65-49170-49160-22-19-49165-49155-10-"
               "255,0-11-10-35-13172,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-"
               "3-15-16-17,0-1-2",
        "ja3_md5": "a34e8a810b5f390fc7aa5ed711fa6993",
        "et_sid": 2028373,
        "sni": "cdn.gtk-metrics.example",
        "technique": "T1071.001 Web Protocols (info-stealer C2)",
    },
}

# --------------------------------------------------------------------------- #
# HTTP-C2 framework families: the observable HTTP signature (default URIs, headers, UA) that
# URI/header-based detections key on. JARM / JA3S are carried as INTEL METADATA only — JARM is
# an active-scan fingerprint, never present in a passive beacon, so it is documented, not rendered.
# --------------------------------------------------------------------------- #
HTTP_C2_FAMILIES = {
    "cobalt_strike": {
        "label": "Cobalt Strike (stock malleable-C2 profile)",
        "get_uris": ["/ca", "/dpixel", "/__utm.gif", "/pixel.gif", "/g.pixel", "/updates.rss",
                     "/fwlink", "/cm", "/cx", "/visit.js", "/load", "/push", "/ptj", "/ga.js",
                     "/activity", "/IE9CompatViewList.xml"],
        "post_uri": "/submit.php?id=",
        "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like "
                      "Gecko) Chrome/55.0.2883.87 Safari/537.36",
        "smb_pipes": ["msagent_42", "status_18", "MSSE-6543-server", "postex_ssh_9241"],
        "ja3s": "649d6810e8392f63dc311eecb6b7098b",   # intel: team-server ServerHello
        "jarm": "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",  # intel only
        "interval": 60.0, "jitter_pct": 0,
        "technique": "T1071.001 Web Protocols (Cobalt Strike Beacon)",
    },
    "sliver": {
        "label": "Sliver (default HTTP(S) C2)",
        # Sliver encodes the message type in the file extension; 2-8 random segments + a `_=` nonce.
        "uri_scheme": {".woff": "stager", ".js": "poll", ".html": "keyx",
                       ".php": "session", ".png": "close"},
        "cert_issuer_cn": "operators", "cert_subject_cn": "multiplayer",
        "jarm": "28d28d28d00028d00043d28d28d43d47390d982d099a542ccbc90628951062",  # intel only
        "interval": 60.0, "jitter_pct": 0,
        "technique": "T1071.001 Web Protocols (Sliver implant)",
    },
    "mythic": {
        "label": "Mythic (default http profile)",
        "get_uri": "/index", "post_uri": "/data", "query_param": "q",
        "server_header": "NetDNA-cache/2.2",
        "user_agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
        "interval": 10.0, "jitter_pct": 23,
        "technique": "T1071.001 Web Protocols (Mythic agent)",
    },
    "havoc": {
        "label": "Havoc (Demon default profile)",
        "uris": ["/funny_cat.gif", "/index.php", "/test.txt", "/helloworld.js"],
        "req_headers": {"X-Havoc": "true", "X-Havoc-Agent": "Demon"},
        "resp_headers": {"X-IsHavocFramework": "true"},
        "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like "
                      "Gecko) Chrome/96.0.4664.110 Safari/537.36",
        "interval": 60.0, "jitter_pct": 15,
        "technique": "T1071.001 Web Protocols (Havoc Demon)",
    },
}


def list_real_families() -> list:
    return sorted(JA3_FAMILIES) + sorted(HTTP_C2_FAMILIES)
