# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Sigma-over-Zeek — evaluate Sigma rules against the Zeek logs a capture produces.

This is a detection engineer's native surface: their logs (Zeek), their rule language
(Sigma). Because PacketForge generates the attack AND the ground truth, a Sigma rule can
be scored the honest way — fires on the attack's Zeek records, silent on the benign
ones.

A deliberately small Sigma subset, covering what real Zeek Sigma rules use:
- ``logsource.service`` selects the Zeek log (kerberos, dns, http, ssl, smb, conn).
- selections: ``field[/modifier]: value | [values]`` — modifiers ``contains``,
  ``startswith``, ``endswith``, ``re``; a list is OR; multiple fields are AND.
- conditions: ``sel``, ``a and b``, ``a or b``, ``not a``, ``1 of them``, ``all of them``,
  and an aggregation tail ``| count() by <field> > <N>`` (the burst/threshold idiom).
Zeek field names are used directly (``request_type``, ``cipher``, ``id.orig_h``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from packetforge.validation.roundtrip import _parse_zeek_log

_SERVICE_LOG = {
    "kerberos": "kerberos.log", "dns": "dns.log", "http": "http.log",
    "ssl": "ssl.log", "tls": "ssl.log", "smb": "smb_mapping.log", "conn": "conn.log",
}


@dataclass
class SigmaRule:
    title: str
    service: str
    detection: dict
    condition: str
    level: str = "medium"
    technique: str = ""

    @property
    def logfile(self) -> str:
        return _SERVICE_LOG.get(self.service, f"{self.service}.log")


@dataclass
class SigmaResult:
    rule: SigmaRule
    matched_records: list = field(default_factory=list)
    groups: dict = field(default_factory=dict)   # for aggregations: group-key -> count
    fired: bool = False


def load_sigma(path: str | Path) -> SigmaRule:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    ls = doc.get("logsource", {})
    tags = doc.get("tags", []) or []
    tech = next((t.split(".", 1)[1] for t in tags if t.startswith("attack.t")), "")
    return SigmaRule(
        title=doc.get("title", Path(path).stem),
        service=ls.get("service", ls.get("category", "conn")),
        detection=doc["detection"],
        condition=str(doc["detection"].get("condition", "selection")),
        level=doc.get("level", "medium"),
        technique=tech.upper(),
    )


def _match_value(record_val: str, spec, modifier: str) -> bool:
    values = spec if isinstance(spec, list) else [spec]
    rv = (record_val or "").lower()
    for v in values:
        v = str(v).lower()
        if modifier == "contains" and v in rv:
            return True
        if modifier == "startswith" and rv.startswith(v):
            return True
        if modifier == "endswith" and rv.endswith(v):
            return True
        if modifier == "re" and re.search(str(v), record_val or ""):
            return True
        if modifier == "" and rv == v:
            return True
    return False


def _match_selection(record: dict, selection: dict) -> bool:
    """A selection is an AND over its fields; a list value is an OR; `field|mod` applies."""
    for key, spec in selection.items():
        field_name, _, modifier = key.partition("|")
        if not _match_value(record.get(field_name, ""), spec, modifier):
            return False
    return True


def _eval_condition(condition: str, record: dict, detection: dict) -> bool:
    """Evaluate the (pre-aggregation) boolean condition for one record.

    Supports the common Sigma forms without eval: a bare selection name, ``not X``,
    ``all of them`` / ``N of them``, and flat ``and``/``or`` chains over selection
    names (with optional ``not`` before a name). Precedence beyond that is not modelled.
    """
    names = [k for k in detection if k != "condition"]

    def sel(n: str) -> bool:
        return n in detection and _match_selection(record, detection[n])

    c = condition.strip()
    if c in ("all of them", "all of selection*"):
        return all(sel(n) for n in names)
    if c in ("1 of them", "any of them", "1 of selection*"):
        return any(sel(n) for n in names)

    # Split on 'or' (lowest precedence), then 'and' within each clause.
    for or_clause in re.split(r"\bor\b", c):
        ok = True
        for term in re.split(r"\band\b", or_clause):
            term = term.strip().strip("()").strip()
            negate = term.startswith("not ")
            name = term[4:].strip() if negate else term
            val = sel(name)
            if negate:
                val = not val
            if not val:
                ok = False
                break
        if ok:
            return True
    return False


def run_sigma(rule: SigmaRule, zeek_dir: str | Path) -> SigmaResult:
    records = _parse_zeek_log(Path(zeek_dir) / rule.logfile)
    result = SigmaResult(rule=rule)
    base_cond, _, agg = rule.condition.partition("|")
    matched = [r for r in records if _eval_condition(base_cond, r, rule.detection)]
    result.matched_records = matched

    agg = agg.strip()
    if agg:
        # form: count() by <field> > <N>
        m = re.match(r"count\(\)\s+by\s+([\w.]+)\s*>\s*(\d+)", agg)
        if m:
            gfield, thresh = m.group(1), int(m.group(2))
            groups: dict = {}
            for r in matched:
                groups[r.get(gfield, "")] = groups.get(r.get(gfield, ""), 0) + 1
            result.groups = groups
            result.fired = any(cnt > thresh for cnt in groups.values())
            return result
    result.fired = bool(matched)
    return result


def evaluate_pcap_with_sigma(pcap: str | Path, rules_dir: str | Path,
                             workdir: str | Path | None = None) -> list:
    """Run Zeek on a pcap, then evaluate every Sigma rule in ``rules_dir`` against it."""
    import tempfile

    from packetforge.validation.roundtrip import _run_zeek

    wd = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="pf_sigma_"))
    wd.mkdir(parents=True, exist_ok=True)
    _run_zeek(Path(pcap), wd)
    results = []
    for rp in sorted(Path(rules_dir).glob("*.yml")) + sorted(Path(rules_dir).glob("*.yaml")):
        results.append(run_sigma(load_sigma(rp), wd))
    return results
