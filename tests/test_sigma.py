# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Phase C: Sigma-over-Zeek evaluator (his logs, his rule language)."""

from packetforge.sigma import (
    SigmaRule, _eval_condition, _match_selection, load_sigma, run_sigma,
)

REPO = __import__("pathlib").Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO / "detection" / "sigma"


def _write_kerberos_log(d, rows):
    """Write a minimal Zeek kerberos.log TSV the parser understands."""
    fields = ["ts", "id.orig_h", "request_type", "cipher"]
    lines = ["#separator \\x09", "#fields\t" + "\t".join(fields),
             "#types\ttime\taddr\tstring\tstring"]
    for r in rows:
        lines.append("\t".join(str(r.get(f, "-")) for f in fields))
    (d / "kerberos.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_selection_and_list_or_and_modifiers():
    rec = {"request_type": "TGS", "cipher": "rc4-hmac", "service": "MSSQLSvc/db"}
    assert _match_selection(rec, {"request_type": "TGS", "cipher": "rc4-hmac"})
    assert not _match_selection(rec, {"request_type": "AS"})
    assert _match_selection(rec, {"cipher": ["aes256", "rc4-hmac"]})       # list = OR
    assert _match_selection(rec, {"service|contains": "MSSQL"})            # modifier
    assert not _match_selection(rec, {"service|startswith": "HTTP"})


def test_condition_grammar():
    det = {"a": {"request_type": "TGS"}, "b": {"cipher": "rc4-hmac"}}
    rec = {"request_type": "TGS", "cipher": "rc4-hmac"}
    assert _eval_condition("a and b", rec, det)
    assert _eval_condition("a or b", {"request_type": "TGS", "cipher": "aes"}, det)
    assert not _eval_condition("a and b", {"request_type": "TGS", "cipher": "aes"}, det)
    assert _eval_condition("a and not c", rec, {**det, "c": {"cipher": "aes"}})
    assert _eval_condition("all of them", rec, det)


def test_kerberoasting_rule_fires_on_burst_only(tmp_path):
    rule = load_sigma(SIGMA_DIR / "kerberoasting_rc4_tgs_burst.yml")
    assert rule.technique == "T1558.003" and rule.service == "kerberos"
    # 8 RC4 TGS from one host -> over the threshold of 5
    _write_kerberos_log(tmp_path, [{"id.orig_h": "10.0.0.9", "request_type": "TGS",
                                    "cipher": "rc4-hmac"} for _ in range(8)])
    assert run_sigma(rule, tmp_path).fired

    # benign AES auth -> silent
    _write_kerberos_log(tmp_path, [{"id.orig_h": "10.0.0.9", "request_type": "TGS",
                                    "cipher": "aes256-cts-hmac-sha1-96"} for _ in range(8)])
    assert not run_sigma(rule, tmp_path).fired

    # a couple RC4 tickets (below threshold) -> silent (no false alarm on noise)
    _write_kerberos_log(tmp_path, [{"id.orig_h": "10.0.0.9", "request_type": "TGS",
                                    "cipher": "rc4-hmac"} for _ in range(3)])
    assert not run_sigma(rule, tmp_path).fired


def test_aggregation_is_per_source():
    rule = SigmaRule(title="t", service="kerberos",
                     detection={"selection": {"request_type": "TGS", "cipher": "rc4-hmac"}},
                     condition="selection | count() by id.orig_h > 5")
    import tempfile
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    # 4 hosts with 3 each: 12 total but none over 5 individually -> silent
    rows = [{"id.orig_h": f"10.0.0.{h}", "request_type": "TGS", "cipher": "rc4-hmac"}
            for h in range(4) for _ in range(3)]
    _write_kerberos_log(d, rows)
    assert not run_sigma(rule, d).fired
