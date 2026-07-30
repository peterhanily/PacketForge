# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 4 — correspondence.

The load-bearing test is `test_v1_fails_on_exactly_what_the_postmortem_confirmed`: the two
shipped reconstructions are a natural experiment, and the gate must reproduce their known
outcome from their own sources. If that ever flips, either the gate has stopped working or
one of the samples has been quietly edited.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from packetforge.models.flowspec import load_flowset
from packetforge.warrant import (
    Claim, ClaimSet, SourceRef, check, confidence_term, load_claimset, write_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
V1_CLAIMS = ROOT / "flows" / "openai-hf-exploitgym.claims.yaml"
V1_FLOWS = ROOT / "flows" / "openai-hf-exploitgym.yaml"
V2_CLAIMS = ROOT / "flows" / "openai-hf-exploitgym-v2.claims.yaml"
V2_FLOWS = ROOT / "flows" / "openai-hf-exploitgym-v2.yaml"


def _check(claims: Path, flows: Path):
    return check(load_claimset(claims), load_flowset(flows).flows)


def _mini(**kw) -> ClaimSet:
    base = dict(
        subject="test", cutoff="2026-01-01",
        sources=[SourceRef(id="S1", title="t", self_described_confidence="final",
                           about_own_infrastructure=True)],
        claims=[],
    )
    base.update(kw)
    return ClaimSet(**base)


def _obs(cid, **kw) -> Claim:
    kw.setdefault("source", "S1")
    kw.setdefault("quote", "q")
    return Claim(id=cid, text=cid, stance="observed", **kw)


# --------------------------------------------------------------------------- #
# The natural experiment                                                       #
# --------------------------------------------------------------------------- #


def test_v1_fails_on_exactly_what_the_postmortem_confirmed():
    """Sample 18 must fail, and fail on the four fabrications and the missing scale."""
    rep = _check(V1_CLAIMS, V1_FLOWS)
    assert not rep.ok

    codes = {f.code for f in rep.fails}
    assert "unlicensed-flow" in codes        # the invented flows
    assert "unaccounted-claim" in codes      # the ignored source claims
    assert "floor-violated" in codes         # span / failure-fraction / host count
    assert "resolves-open-question" in codes  # rendering an open question as fact

    unlicensed = {f.detail.split()[0] for f in rep.fails if f.code == "unlicensed-flow"}
    # The stage-2 pull and the SSH hop are the two the post-mortem most squarely refuted.
    assert {"s1_tls_stage2_pull", "s3_ssh_node"} <= unlicensed

    # And the magnitude claims that were sitting unread in the source.
    unaccounted = {f.detail.split()[0] for f in rep.fails if f.code == "unaccounted-claim"}
    assert {"C10", "C11"} <= unaccounted      # ">17,000 events", "decoy activity"

    assert rep.census["claims_unaccounted"] >= 10
    assert rep.census["flow_stance_mix"].get("UNLICENSED") == 4


def test_v2_passes_with_its_gaps_declared():
    """Sample 19 must pass — every flow licensed, every claim rendered or declared."""
    rep = _check(V2_CLAIMS, V2_FLOWS)
    assert rep.ok, [f.detail for f in rep.fails]
    assert not rep.warns, [f.detail for f in rep.warns]
    assert rep.census["claims_unaccounted"] == 0
    assert "UNLICENSED" not in rep.census["flow_stance_mix"]
    # The honest half: gaps are declared, not absent.
    assert len(rep.gaps) >= 5


def test_v1_third_party_preliminary_source_is_flagged():
    """The OpenAI 'production database' claim is the trap; the gate must name it."""
    rep = _check(V1_CLAIMS, V1_FLOWS)
    assert any(f.code == "third-party-preliminary" for f in rep.warns)


# --------------------------------------------------------------------------- #
# Individual checks                                                            #
# --------------------------------------------------------------------------- #


def test_unlicensed_flow_fails():
    cs = _mini(claims=[_obs("C1", renders=[])], )
    cs.claims[0].unmodelled_reason = "n/a"
    rep = check(cs, load_flowset(V1_FLOWS).flows)
    assert any(f.code == "unlicensed-flow" for f in rep.fails)


def test_illustrative_flow_is_licensed_without_a_claim():
    flows = load_flowset(V1_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=[], unmodelled_reason="nothing to render")])
    rep = check(cs, flows)
    assert not [f for f in rep.fails if f.code == "unlicensed-flow"]
    assert rep.census["flow_stance_mix"]["illustrative"] == len(flows)


def test_declared_gap_suppresses_its_own_quantity_check():
    """A declared gap is the honest artifact; a silent shortfall is the failure."""
    flows = load_flowset(V1_FLOWS).flows
    q = {"kind": "floor", "value": 999, "unit": "flows"}
    silent = _mini(illustrative_flows=[f.flow_id for f in flows],
                   claims=[_obs("C1", quantifier=q, renders=[flows[0].flow_id])])
    assert any(f.code == "floor-violated" for f in check(silent, flows).fails)

    declared = _mini(illustrative_flows=[f.flow_id for f in flows],
                     claims=[_obs("C1", quantifier=q, renders=[],
                                  unmodelled_reason="cannot be shown at this vantage")])
    rep = check(declared, flows)
    assert not [f for f in rep.fails if f.code == "floor-violated"]
    assert any(f.code == "quantity-declared-unmodelled" for f in rep.findings)


def test_unmeasurable_unit_warns_until_a_measurement_note_exists():
    flows = load_flowset(V1_FLOWS).flows
    q = {"kind": "floor", "value": 17000, "unit": "attacker-actions"}
    cs = _mini(illustrative_flows=[f.flow_id for f in flows[1:]],
               claims=[_obs("C1", quantifier=q, renders=[flows[0].flow_id])])
    assert any(f.code == "unmeasurable-quantifier" for f in check(cs, flows).warns)

    cs.claims[0].measurement_note = "carried in the manifest; not implied by the flow count"
    assert not [f for f in check(cs, flows).warns if f.code == "unmeasurable-quantifier"]


def test_resolving_an_open_question_fails():
    flows = load_flowset(V1_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows[1:]],
               claims=[Claim(id="C1", text="not established", stance="source-unresolved",
                             source="S1", quote="we are still assessing",
                             renders=[flows[0].flow_id])])
    assert any(f.code == "resolves-open-question" for f in check(cs, flows).fails)


def test_citation_asymmetry_is_enforced_both_ways():
    flows = load_flowset(V1_FLOWS).flows
    ill = [f.flow_id for f in flows]
    # observed without a citation -> fail
    cs = _mini(illustrative_flows=ill,
               claims=[Claim(id="C1", text="t", stance="observed", unmodelled_reason="x")])
    assert any(f.code == "missing-citation" for f in check(cs, flows).fails)
    # assumption WITH a citation -> also fail; an assumption with a source is a judgment
    cs = _mini(illustrative_flows=ill,
               claims=[Claim(id="C1", text="t", stance="assumption", source="S1",
                             unmodelled_reason="x")])
    assert any(f.code == "citation-on-assumption" for f in check(cs, flows).fails)


def test_dangling_references_fail():
    flows = load_flowset(V1_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=["no_such_flow"])])
    codes = {f.code for f in check(cs, flows).fails}
    assert "dangling-render" in codes

    cs = _mini(illustrative_flows=["no_such_flow"] + [f.flow_id for f in flows],
               claims=[_obs("C1", renders=[], unmodelled_reason="x")])
    assert "dangling-illustrative" in {f.code for f in check(cs, flows).fails}


def test_unknown_source_fails():
    flows = load_flowset(V1_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[Claim(id="C1", text="t", stance="observed", source="NOPE",
                             quote="q", unmodelled_reason="x")])
    assert any(f.code == "unknown-source" for f in check(cs, flows).fails)


@pytest.mark.parametrize("value,term", [
    (None, "Not Specified"), (0, "Speculation"), (30, "Doubtful"),
    (50, "Even Odds"), (70, "Probable"), (90, "Very Probable"), (100, "Certainty"),
])
def test_confidence_words_are_rendered_from_the_number(value, term):
    """Store the number, render the words — so the two cannot drift apart."""
    assert confidence_term(value) == term


# --------------------------------------------------------------------------- #
# The manifest is generated, and says the honest thing                         #
# --------------------------------------------------------------------------- #


def test_manifest_is_deterministic_and_leads_with_the_gaps(tmp_path):
    cs = load_claimset(V2_CLAIMS)
    rep = check(cs, load_flowset(V2_FLOWS).flows)
    a_md, a_js = tmp_path / "a.md", tmp_path / "a.json"
    b_md, b_js = tmp_path / "b.md", tmp_path / "b.json"
    write_manifest(cs, rep, a_md, a_js)
    write_manifest(cs, rep, b_md, b_js)
    assert a_md.read_bytes() == b_md.read_bytes()
    assert a_js.read_bytes() == b_js.read_bytes()

    text = a_md.read_text()
    assert "not ground truth" in text
    # gaps outrank the packets: they appear before the claim register
    assert text.index("## What is NOT modelled") < text.index("## Claim register")

    payload = json.loads(a_js.read_text())
    assert payload["synthetic"] is True and payload["mode"] == "reconstruction"
    assert payload["verdict"] == "pass"
    assert payload["unmodelled"]


def test_shipped_manifests_match_a_fresh_render(tmp_path):
    """Documentation must not drift from the artifact (the CIC-IDS2017 failure)."""
    from packetforge.warrant import load_answer_key, score
    for claims, flows, sample, key in (
        (V1_CLAIMS, V1_FLOWS, "18-openai-hf-exploitgym",
         ROOT / "flows" / "openai-hf-exploitgym.answerkey.yaml"),
        (V2_CLAIMS, V2_FLOWS, "19-openai-hf-exploitgym-v2", None),
    ):
        sample_dir = ROOT / "samples" / sample
        if not sample_dir.exists():
            pytest.skip("sample gallery not generated")
        shipped = sample_dir / "CLAIMS.md"
        # Not a skip: if the sample is present its warranting layer must be too, or a build
        # that silently dropped the manifest would leave the whole suite green.
        assert shipped.exists(), f"{sample} ships no CLAIMS.md — the warrant step did not run"
        shipped_json = sample_dir / "CLAIMS.json"
        assert shipped_json.exists(), f"{sample} ships no CLAIMS.json"
        cs = load_claimset(claims)
        rep = check(cs, load_flowset(flows).flows)
        fresh = tmp_path / f"{sample}.md"
        scored = score(cs, load_answer_key(key)) if key else None
        fresh_json = tmp_path / f"{sample}.json"
        write_manifest(cs, rep, fresh, fresh_json, score_result=scored)
        assert fresh.read_text() == shipped.read_text(), \
            f"{sample}/CLAIMS.md has drifted from its claim set — re-run scripts/make-samples.sh"
        assert fresh_json.read_text() == shipped_json.read_text(), \
            f"{sample}/CLAIMS.json has drifted — re-run scripts/make-samples.sh"


def test_warrant_metadata_cannot_change_rendered_bytes(tmp_path):
    """Gate 4 is metadata. It must never touch a packet."""
    from packetforge.compile.timeline import write_pcap
    fs = load_flowset(V2_FLOWS)
    out = tmp_path / "a.pcap"
    write_pcap(fs, out)
    before = out.read_bytes()
    check(load_claimset(V2_CLAIMS), fs.flows)     # run the gate over the same flows
    write_pcap(load_flowset(V2_FLOWS), tmp_path / "b.pcap")
    assert (tmp_path / "b.pcap").read_bytes() == before


# --------------------------------------------------------------------------- #
# Phase 2 — field-level marking                                                #
# --------------------------------------------------------------------------- #


def test_facts_are_fields_not_flows():
    """The unit must be the value a reader checks in a Zeek log, not the flow."""
    from packetforge.warrant import flow_facts
    flows = load_flowset(V2_FLOWS).flows
    facts = flow_facts(flows[0])
    assert "src_ip" in facts and "dst_port" in facts
    assert any(f.startswith("l7.") for f in facts)     # payload fields, individually
    assert "flow_id" not in facts                       # identity asserts nothing


def test_unmarked_fields_fail_safe_to_fabricated():
    """VERIS's absence discipline: a blank marking must never read as a positive claim."""
    flows = load_flowset(V2_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=[], unmodelled_reason="x")])
    rep = check(cs, flows)                              # no field_markings at all
    mix = rep.census["field_class_mix"]
    assert mix["observed"] == 0 and mix["judgment"] == 0
    assert mix["fabricated"] == rep.census["network_facts"] - mix["aleatoric"]


def test_marking_precedence_exact_flow_beats_wildcard():
    from packetforge.warrant import FieldMarking, FieldMarkings, resolve_marking
    fm = FieldMarkings(marks=[
        FieldMarking(selectors=["*.dst_ip"], icd203="fabricated"),
        FieldMarking(selectors=["imds_token.dst_ip"], icd203="observed", claim_ref="P05"),
    ])
    assert resolve_marking(fm, "imds_token", "dst_ip").icd203 == "observed"
    assert resolve_marking(fm, "other_flow", "dst_ip").icd203 == "fabricated"
    # a container selector covers everything beneath it
    fm2 = FieldMarkings(marks=[FieldMarking(selectors=["*.l7"], icd203="fabricated")])
    assert resolve_marking(fm2, "x", "l7.user_agent").icd203 == "fabricated"
    assert resolve_marking(fm2, "x", "dst_ip") is None


def test_dangling_selector_fails():
    """STIX requires a selector to address a property that is actually present."""
    from packetforge.warrant import FieldMarking, FieldMarkings
    flows = load_flowset(V2_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=[], unmodelled_reason="x")],
               field_markings=FieldMarkings(marks=[
                   FieldMarking(selectors=["*.no_such_field"], icd203="fabricated")]))
    assert any(f.code == "dangling-selector" for f in check(cs, flows).fails)


def test_marking_citation_asymmetry():
    from packetforge.warrant import FieldMarking, FieldMarkings
    flows = load_flowset(V2_FLOWS).flows
    base = dict(illustrative_flows=[f.flow_id for f in flows],
                claims=[_obs("C1", renders=[], unmodelled_reason="x")])
    # observed without a claim_ref -> fail
    cs = _mini(**base, field_markings=FieldMarkings(marks=[
        FieldMarking(selectors=["*.dst_ip"], icd203="observed")]))
    assert any(f.code == "marking-without-citation" for f in check(cs, flows).fails)
    # fabricated WITH a claim_ref -> fail; a fabricated value rests on nothing by definition
    cs = _mini(**base, field_markings=FieldMarkings(marks=[
        FieldMarking(selectors=["*.dst_ip"], icd203="fabricated", claim_ref="C1")]))
    assert any(f.code == "fabricated-with-citation" for f in check(cs, flows).fails)
    # claim_ref pointing nowhere -> fail
    cs = _mini(**base, field_markings=FieldMarkings(marks=[
        FieldMarking(selectors=["*.dst_ip"], icd203="judgment", claim_ref="NOPE")]))
    assert any(f.code == "unknown-claim-ref" for f in check(cs, flows).fails)


def test_epistemic_surface_excludes_aleatoric_and_fabricated():
    """Only epistemic detail can be shown wrong by a fuller account."""
    rep = _check(V2_CLAIMS, V2_FLOWS)
    c = rep.census
    mix = c["field_class_mix"]
    assert c["epistemic_surface"] == mix["observed"] + mix["judgment"] + mix["assumption"]
    assert c["epistemic_surface"] < c["network_facts"]     # aleatoric + fabricated excluded


def test_shipped_reconstructions_report_an_honest_field_census():
    """Both captures are overwhelmingly authored, and must say so."""
    v1 = _check(V1_CLAIMS, V1_FLOWS).census
    v2 = _check(V2_CLAIMS, V2_FLOWS).census
    for c in (v1, v2):
        observed = c["field_class_mix"]["observed"]
        # under 5% of what is on the wire is actually in the public record
        assert 0 < observed < 0.05 * c["network_facts"]
    # the richer source base buys more sourced facts, in absolute terms
    assert v2["field_class_mix"]["observed"] > v1["field_class_mix"]["observed"]


# --------------------------------------------------------------------------- #
# Phase 3 — artifact class, and provenance that survives detachment            #
# --------------------------------------------------------------------------- #


def test_declaring_an_exercise_downgrades_findings_rather_than_hiding_them():
    """ENFSI §1.4: the remedy for thin sourcing is a smaller claim, not hedging prose."""
    cs = load_claimset(V1_CLAIMS)
    flows = load_flowset(V1_FLOWS).flows
    strict = check(cs, flows)
    assert not strict.ok and any(f.code == "class-not-earned" for f in strict.fails)

    cs.artifact_class = "exercise"
    relaxed = check(cs, flows)
    assert relaxed.ok                                   # an exercise claims no correspondence
    assert len(relaxed.warns) >= len(strict.fails)      # but every finding is still reported
    assert any(f.code == "artifact-class" for f in relaxed.findings)


def test_reconstruction_must_carry_a_source_summary():
    flows = load_flowset(V1_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=[], unmodelled_reason="x")])
    assert any(f.code == "missing-source-summary" for f in check(cs, flows).fails)
    cs.artifact_class = "exercise"
    assert not [f for f in check(cs, flows).fails]


def test_pcapng_carries_provenance_and_zeek_still_agrees(tmp_path):
    """The manifest must not be detachable — and the gate must not notice the difference."""
    pytest.importorskip("scapy")
    from packetforge.compile.timeline import write_pcap
    from packetforge.validation.roundtrip import validators_available
    from packetforge.warrant import write_provenance_pcapng

    cs = load_claimset(V2_CLAIMS)
    fs = load_flowset(V2_FLOWS)
    rep = check(cs, fs.flows)
    ng = tmp_path / "prov.pcapng"
    n = write_provenance_pcapng(cs, fs, rep, ng)
    assert n > 0 and ng.stat().st_size > 0

    if not validators_available():
        pytest.skip("needs zeek + tshark")
    import subprocess
    out = subprocess.run(["tshark", "-r", str(ng), "-T", "fields", "-e", "frame.comment"],
                         capture_output=True, text=True)
    comments = [c for c in out.stdout.splitlines() if c.strip()]
    assert len(comments) == n
    assert all(c.startswith("SYNTHETIC") for c in comments)
    assert any("claim=P05" in c for c in comments)      # the IMDS claim, by id

    # Same capture as pcap: Zeek must derive the identical connections from both.
    plain = tmp_path / "plain.pcap"
    write_pcap(fs, plain)

    def conns(p):
        d = tmp_path / ("z" + p.stem)
        d.mkdir()
        subprocess.run(["zeek", "-D", "-C", "-r", str(p.resolve()),
                        "FilteredTraceDetection::enable=F"], cwd=d, capture_output=True)
        log = d / "conn.log"
        return sum(1 for line in log.read_text().splitlines() if not line.startswith("#"))

    assert conns(ng) == conns(plain)


def test_unlicensed_flows_are_visible_in_band(tmp_path):
    """A capture forwarded without its manifest must still admit what it does not know."""
    from packetforge.warrant import write_provenance_pcapng
    cs = load_claimset(V1_CLAIMS)
    fs = load_flowset(V1_FLOWS)
    ng = tmp_path / "v1.pcapng"
    write_provenance_pcapng(cs, fs, check(cs, fs.flows), ng)
    blob = ng.read_bytes()
    assert b"NONE-UNLICENSED" in blob                   # the four fabrications, in the file
    assert b"NOT EVIDENCE OF ANYTHING" in blob          # the section header


# --------------------------------------------------------------------------- #
# Phase 4 — pre-registration and scoring                                       #
# --------------------------------------------------------------------------- #

V1_KEY = ROOT / "flows" / "openai-hf-exploitgym.answerkey.yaml"


def test_murphy_decomposition_is_an_exact_identity():
    """BS = REL - RES + UNC holds only when grouped by distinct forecast value."""
    from packetforge.warrant import load_answer_key, score
    res = score(load_claimset(V1_CLAIMS), load_answer_key(V1_KEY))
    m = res["summary"]["murphy"]
    assert m["identity_holds"] is True
    assert m["grouped_by"] == "distinct forecast value"
    assert abs(m["reliability"] - m["resolution"] + m["uncertainty"]
               - res["summary"]["mean_brier"]) < 1e-9


def test_log_score_rewards_and_punishes_the_right_way():
    from packetforge.warrant import AnswerKey, Prediction, score
    cs = _mini(claims=[_obs("C1", renders=[], unmodelled_reason="x")], predictions=[
        Prediction(id="A", text="confident and right", probability=0.9, baseline=0.5),
        Prediction(id="B", text="confident and wrong", probability=0.9, baseline=0.5),
        Prediction(id="C", text="honestly uncertain, wrong", probability=0.5, baseline=0.5),
    ])
    rows = {r["id"]: r for r in score(cs, AnswerKey(
        outcomes={"A": "true", "B": "false", "C": "false"}))["rows"]}
    assert rows["A"]["log_score"] > 0                       # beat the prior
    assert rows["B"]["log_score"] < rows["C"]["log_score"]   # confident-wrong is worst
    assert rows["C"]["log_score"] == 0                       # matching the prior scores zero


def test_a_confident_miss_is_bounded_not_infinite():
    """Selten's objection: clip, or one wrong certainty destroys the whole score."""
    from packetforge.warrant import AnswerKey, Prediction, score
    cs = _mini(claims=[_obs("C1", renders=[], unmodelled_reason="x")],
               predictions=[Prediction(id="A", text="certain and wrong",
                                       probability=1.0, baseline=0.5)])
    row = score(cs, AnswerKey(outcomes={"A": "false"}))["rows"][0]
    assert row["log_score"] > -600 and row["log_score"] < -500


def test_unresolved_predictions_are_carried_not_scored():
    """A forward register with nothing resolved must produce no score at all."""
    from packetforge.warrant import AnswerKey, score
    cs = load_claimset(V2_CLAIMS)
    assert cs.predictions, "sample 19 should carry a forward prediction register"
    res = score(cs, AnswerKey(source="nothing has landed yet"))
    assert res["summary"]["resolved"] == 0
    assert res["summary"]["unresolved"] == len(cs.predictions)
    assert "mean_log_score" not in res["summary"]


def test_sample_18_scores_far_worse_than_ignorance():
    """The measurement the whole exercise exists to produce."""
    from packetforge.warrant import load_answer_key, score
    s = score(load_claimset(V1_CLAIMS), load_answer_key(V1_KEY))["summary"]
    assert s["resolved"] == 14
    assert s["mean_log_score"] < -100          # confidently wrong, over and over
    # Zero. The one apparent hit was a restatement of a source, not a prediction, and the
    # gate now refuses to score that.
    assert s["beat_ignorance"] == 0
    assert s["mean_brier"] > 1.0               # worse than always saying 50/50
    # The error is miscalibration, not lack of discrimination.
    assert s["murphy"]["reliability"] > s["murphy"]["resolution"]


def test_answer_key_records_that_it_is_retrospective():
    """These probabilities were reconstructed, not pre-registered, and must say so."""
    from packetforge.warrant import load_answer_key
    key = load_answer_key(V1_KEY)
    assert "RETROSPECTIVE" in key.note
    assert "NOT pre-registered" in key.note


# --------------------------------------------------------------------------- #
# The hole the audit found: a coherent-but-vacuous claim set must not PASS     #
# --------------------------------------------------------------------------- #


def test_a_storyline_about_nothing_cannot_pass_as_a_reconstruction():
    """The accounting checks alone are gameable.

    Declare every flow illustrative, declare the one claim unmodelled, and a capture that
    asserts nothing passed with zero findings — a bare "PASS" on an artifact with no sourced
    facts, which is the misleading-precision failure this gate exists to prevent. A
    reconstruction must be *about* something.
    """
    from packetforge.warrant import SourceRef
    flows = load_flowset(ROOT / "flows" / "c2_beacon.yaml").flows
    vacuous = ClaimSet(
        subject="something entirely invented", cutoff="2026-01-01",
        source_summary="I have no sources.",
        sources=[SourceRef(id="NONE", title="nothing")],
        illustrative_flows=[f.flow_id for f in flows],
        claims=[Claim(id="Z1", text="nothing is claimed", stance="assumption",
                      unmodelled_reason="not modelling anything")],
    )
    rep = check(vacuous, flows)
    assert not rep.ok
    codes = {f.code for f in rep.fails}
    assert "nothing-sourced" in codes and "nothing-rendered" in codes
    assert rep.census["sourced_fraction"] == 0.0

    # Declared honestly as an exercise, it is fine — that is the correct label for it.
    vacuous.artifact_class = "exercise"
    assert check(vacuous, flows).ok


def test_a_pass_is_never_reported_without_the_sourced_fraction():
    """A gate verdict says the accounting is coherent, not that the capture is right."""
    rep = _check(V2_CLAIMS, V2_FLOWS)
    assert rep.ok
    assert 0 < rep.census["sourced_fraction"] < 0.05     # honest: ~2.6%
    md = render_manifest_text(V2_CLAIMS, V2_FLOWS)
    assert "of the network facts here appear in a cited source" in md
    assert "does **not** say the capture is right" in md


def render_manifest_text(claims, flows) -> str:
    from packetforge.warrant import render_manifest
    cs = load_claimset(claims)
    return render_manifest(cs, check(cs, load_flowset(flows).flows))


# --------------------------------------------------------------------------- #
# Regressions for defects the adversarial audit found                          #
# --------------------------------------------------------------------------- #


def test_one_bad_selector_beside_a_good_one_still_fails():
    """The check was per-marking, so a typo hid behind a working selector."""
    from packetforge.warrant import FieldMarking, FieldMarkings
    flows = load_flowset(V2_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=[], unmodelled_reason="x")],
               field_markings=FieldMarkings(marks=[
                   FieldMarking(selectors=["*.src_ip", "*.utterly_made_up"],
                                icd203="fabricated")]))
    bad = [f for f in check(cs, flows).fails if f.code == "dangling-selector"]
    assert len(bad) == 1 and "utterly_made_up" in bad[0].detail


def test_observed_cannot_be_self_declared():
    """A field cannot be better-sourced than the claim it points at."""
    from packetforge.warrant import FieldMarking, FieldMarkings
    flows = load_flowset(V2_FLOWS).flows
    # a claim with no source at all, cited by an 'observed' marking
    cs = _mini(sources=[], illustrative_flows=[f.flow_id for f in flows],
               claims=[Claim(id="C1", text="t", stance="assumption",
                             unmodelled_reason="x")],
               field_markings=FieldMarkings(marks=[
                   FieldMarking(selectors=["*.src_ip"], icd203="observed", claim_ref="C1")]))
    rep = check(cs, flows)
    assert any(f.code == "unsourced-marking" for f in rep.fails)
    assert rep.census["sourced_fraction"] == 0.0 or not rep.ok


def test_failure_is_measured_from_the_wire_not_from_flow_names():
    """Renaming flows must not change a measured magnitude."""
    from packetforge.warrant import MEASURES
    flows = load_flowset(V2_FLOWS).flows
    before = MEASURES["failed-flow-fraction"](flows)
    for f in flows:
        f.flow_id = f.flow_id.replace("denied", "refused").replace("blocked", "stopped")
    assert MEASURES["failed-flow-fraction"](flows) == before


def test_explicitly_authored_defaults_are_still_facts():
    """conn_state: SF written by hand is an assertion, not an absence."""
    from packetforge.warrant import flow_facts
    # a TCP flow whose conn_state the author wrote out, even though SF is the default
    flow = next(f for f in load_flowset(V1_FLOWS).flows if f.transport == "tcp")
    assert flow.conn_state == "SF"
    assert "conn_state" in flow_facts(flow)


def test_a_restatement_of_a_source_is_not_a_prediction():
    """Scoring a prediction whose fields are all 'observed' inflates the result."""
    from packetforge.warrant import FieldMarking, FieldMarkings, Prediction
    flows = load_flowset(V2_FLOWS).flows
    fid = flows[0].flow_id
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=[], unmodelled_reason="x")],
               field_markings=FieldMarkings(
                   aleatoric_fields=[],
                   marks=[FieldMarking(selectors=[f"{fid}"], icd203="observed", claim_ref="C1")]),
               predictions=[Prediction(id="P1", text="restates the source",
                                       probability=0.9, renders=[fid])])
    assert any(f.code == "prediction-is-not-a-prediction" for f in check(cs, flows).fails)


def test_a_claim_set_that_is_mostly_gaps_is_not_a_reconstruction():
    """Laundering a failure into a pass by declaring everything unmodelled."""
    flows = load_flowset(V1_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs(f"C{i}", renders=[], unmodelled_reason=f"reason {i}")
                       for i in range(9)] + [_obs("C9", renders=[flows[0].flow_id])])
    codes = {f.code for f in check(cs, flows).fails}
    assert "mostly-unmodelled" in codes


def test_boilerplate_gap_reasons_are_flagged():
    flows = load_flowset(V1_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=[flows[0].flow_id]),
                       _obs("C2", renders=[], unmodelled_reason="not modelled at this vantage"),
                       _obs("C3", renders=[], unmodelled_reason="not modelled at this vantage")])
    assert any(f.code == "boilerplate-gap-reason" for f in check(cs, flows).warns)


def test_a_retrospective_register_is_never_called_pre_registered():
    """The exact failure this project exists to prevent, applied to itself."""
    cs = load_claimset(V1_CLAIMS)
    assert cs.predictions_pre_registered is False
    md = render_manifest_text(V1_CLAIMS, V1_FLOWS)
    assert "RETROSPECTIVE, not pre-registered" in md
    assert "Pre-registered predictions" not in md
    assert "not** a measurement of calibration" in md


def test_the_answer_keys_caveat_reaches_the_manifest():
    from packetforge.warrant import load_answer_key, render_manifest, score
    cs = load_claimset(V1_CLAIMS)
    rep = check(cs, load_flowset(V1_FLOWS).flows)
    sc = score(cs, load_answer_key(ROOT / "flows" / "openai-hf-exploitgym.answerkey.yaml"))
    assert "RETROSPECTIVE" in sc["summary"]["note"]
    assert "RETROSPECTIVE" in render_manifest(cs, rep, sc)


def test_pcapng_and_pcap_yield_identical_zeek_logs(tmp_path):
    """Timestamp truncation made 936 of 2785 packets 1us early; Zeek noticed."""
    import subprocess
    from packetforge.compile.timeline import write_pcap
    from packetforge.validation.roundtrip import validators_available
    from packetforge.warrant import write_provenance_pcapng
    if not validators_available():
        pytest.skip("needs zeek")
    cs, fs = load_claimset(V2_CLAIMS), load_flowset(V2_FLOWS)
    ng, pc = tmp_path / "a.pcapng", tmp_path / "a.pcap"
    write_provenance_pcapng(cs, fs, check(cs, fs.flows), ng)
    write_pcap(load_flowset(V2_FLOWS), pc)

    def logs(path):
        d = tmp_path / ("z" + path.suffix.lstrip("."))
        d.mkdir()
        subprocess.run(["zeek", "-D", "-C", "-r", str(path.resolve()),
                        "FilteredTraceDetection::enable=F"], cwd=d, capture_output=True)
        out = {}
        for name in ("conn", "ssl", "dns", "http"):
            f = d / f"{name}.log"
            if f.exists():
                # drop the uid column, which is a per-run identifier
                out[name] = [ "\t".join(ln.split("\t")[:1] + ln.split("\t")[2:])
                              for ln in f.read_text().splitlines() if not ln.startswith("#")]
        return out

    a, b = logs(ng), logs(pc)
    assert a and a.keys() == b.keys()
    for name in a:
        assert a[name] == b[name], f"{name}.log differs between pcapng and pcap encodings"


def test_correspondence_composes_into_the_scorecard():
    """The fourth gate must actually fold into the existing scorecard, not just exist."""
    from packetforge.scorecard import build_scorecard, compare_scorecards
    v1 = build_scorecard(meta={}, correspondence=_check(V1_CLAIMS, V1_FLOWS))
    v2 = build_scorecard(meta={}, correspondence=_check(V2_CLAIMS, V2_FLOWS))
    assert v1["verdict"] == "fail" and v2["verdict"] == "pass"
    assert v1["gates"]["correspondence"]["unlicensed_flows"] == 4
    assert v2["gates"]["correspondence"]["claims_unaccounted"] == 0
    assert any("Correspondence:" in g for g in v1["honest_gaps"])
    assert not [g for g in v2["honest_gaps"] if "Correspondence:" in g]
    # and the CI regression path sees it
    diffs = {r["metric"]: r["status"] for r in compare_scorecards(v2, v1)}
    assert diffs["correspondence: unlicensed flows"] == "regressed"
    assert diffs["correspondence: unaccounted claims"] == "regressed"


def test_licensing_alone_is_not_correspondence_so_claims_assert_content():
    """An audit repointed every port to 1337 and blanked every hostname; the unchanged claim
    set still passed, because licensing was pure flow-id bookkeeping."""
    import copy
    cs = load_claimset(V2_CLAIMS)
    fs = load_flowset(V2_FLOWS)
    assert check(cs, fs.flows).ok
    assert check(cs, fs.flows).census["content_checked_flows"] > 20

    mutated = copy.deepcopy(fs.flows)
    for f in mutated:
        if f.transport == "tcp":
            f.dst_port = 1337
    rep = check(cs, mutated)
    assert not rep.ok
    assert any(f.code == "expectation-violated" for f in rep.fails)


def test_a_vacuous_expectation_is_rejected():
    """An expectation no licensed flow can satisfy would silently prove nothing."""
    flows = load_flowset(V2_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows[1:]],
               claims=[_obs("C1", renders=[flows[0].flow_id],
                            expects={"l7.nonexistent_field": "x"})])
    assert any(f.code == "expectation-unsatisfied" for f in check(cs, flows).fails)


def test_an_exercise_looks_like_an_exercise(tmp_path):
    """Downgrading the class must change what a reader sees, not just the exit code."""
    from packetforge.warrant import render_manifest
    cs = load_claimset(V2_CLAIMS)
    flows = load_flowset(V2_FLOWS).flows
    cs.artifact_class = "exercise"
    md = render_manifest(cs, check(cs, flows))
    assert md.startswith("# Exercise claims")
    assert "NOT A RECONSTRUCTION" in md
    assert "This is a reconstruction, not ground truth" not in md


def test_an_explicit_marking_beats_the_aleatoric_list():
    """The list used to short-circuit and silently discard the author's own marking."""
    from packetforge.warrant import FieldMarking, FieldMarkings
    flows = load_flowset(V2_FLOWS).flows
    cs = _mini(illustrative_flows=[f.flow_id for f in flows],
               claims=[_obs("C1", renders=[], unmodelled_reason="x")],
               field_markings=FieldMarkings(
                   aleatoric_fields=["src_ip"],
                   marks=[FieldMarking(selectors=["*.src_ip"], icd203="fabricated")]))
    rep = check(cs, flows)
    assert rep.census["field_class_mix"]["aleatoric"] == 0
    assert any(f.code == "aleatoric-shadowed-by-marking" for f in rep.warns)


def test_murphy_identity_survives_high_precision_probabilities():
    """Comparing against a rounded Brier made the identity spuriously fail."""
    from packetforge.warrant import AnswerKey, Prediction, score
    probs = [0.149, 0.834, 0.753, 0.265, 0.496, 0.452]
    cs = _mini(claims=[_obs("C1", renders=[], unmodelled_reason="x")],
               predictions=[Prediction(id=f"P{i}", text="t", probability=p)
                            for i, p in enumerate(probs)])
    key = AnswerKey(outcomes={f"P{i}": ("true" if i % 2 else "false")
                              for i in range(len(probs))})
    assert score(cs, key)["summary"]["murphy"]["identity_holds"] is True


def test_a_baseline_cannot_be_pushed_to_mint_points():
    from pydantic import ValidationError
    from packetforge.warrant import Prediction
    with pytest.raises(ValidationError):
        Prediction(id="X", text="t", probability=0.9, baseline=1e-9)


def test_duplicate_and_double_declared_flows_fail():
    flows = load_flowset(V1_FLOWS).flows
    dup = flows + [flows[0]]
    cs = _mini(illustrative_flows=[f.flow_id for f in dup],
               claims=[_obs("C1", renders=[], unmodelled_reason="x")])
    assert any(f.code == "duplicate-flow-id" for f in check(cs, dup).fails)

    cs2 = _mini(illustrative_flows=[f.flow_id for f in flows],
                claims=[_obs("C1", renders=[flows[0].flow_id])])
    assert any(f.code == "licensed-and-illustrative" for f in check(cs2, flows).fails)


# --------------------------------------------------------------------------- #
# Indicator hygiene — no real third party may be labelled attacker infra       #
# --------------------------------------------------------------------------- #


def test_no_allocated_address_is_published_as_an_indicator():
    """A synthetic capture must never put a real organisation's address in an IOC file.

    This shipped once: 170.130.183.204 (Eonix Corporation) was emitted as `c2_ip` in two
    samples, and 2606:4700:8ac0::66 (Cloudflare) as the IPv6 C2. The generator drew from
    unrestricted public space.
    """
    import glob
    import ipaddress
    import json as _json

    from packetforge.scenarios import WELL_KNOWN_SERVICE_ADDRS

    doc = [ipaddress.ip_network(n) for n in
           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    offenders = []
    for path in glob.glob(str(ROOT / "samples" / "*" / "GROUND_TRUTH.json")):
        blob = _json.dumps(_json.load(open(path)))
        for token in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b",
                                    blob)):
            try:
                addr = ipaddress.ip_address(token)
            except ValueError:
                continue
            if addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_loopback:
                continue
            if any(addr in n for n in doc) or token in WELL_KNOWN_SERVICE_ADDRS:
                continue
            offenders.append(f"{Path(path).parent.name}: {token}")
    assert not offenders, (
        "allocated address published as an indicator: " + ", ".join(sorted(offenders))
        + " — use RFC 5737/3849, or add it to WELL_KNOWN_SERVICE_ADDRS with a reason")


def test_every_well_known_exception_carries_a_reason():
    from packetforge.scenarios import WELL_KNOWN_SERVICE_ADDRS
    for addr, why in WELL_KNOWN_SERVICE_ADDRS.items():
        assert len(why) > 30, f"{addr} needs a real justification, not {why!r}"


def test_no_registrable_domain_is_used_as_attacker_infrastructure():
    """Invented C2 names must sit on RFC 2606 reserved TLDs, not squattable ones.

    An unregistered second-level domain and a live platform's user-content space both shipped
    in committed Zeek logs as command-and-control; anyone could have registered the former and
    inherited a repository pointing at it.
    """
    import glob

    from packetforge.scenarios import SOURCED_INCIDENT_HOSTS, WELL_KNOWN_SERVICE_DOMAINS

    RESERVED = {"example", "invalid", "test", "local", "localhost", "internal", "arpa"}
    NOT_HOSTS = {"md", "json", "yaml", "yml", "py", "sh", "log", "pcap", "pcapng", "svc",
                 "gz", "exe", "dll", "xlsx", "pdf", "zip", "txt", "conf", "c", "h5", "ecr"}
    allowed = set(WELL_KNOWN_SERVICE_DOMAINS) | SOURCED_INCIDENT_HOSTS
    host_re = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b")

    offenders = set()
    for path in glob.glob(str(ROOT / "samples" / "*" / "GROUND_TRUTH.md")) + \
            glob.glob(str(ROOT / "samples" / "*" / "RECONSTRUCTION.md")):
        for host in host_re.findall(Path(path).read_text()):
            labels = host.split(".")
            if labels[-1] in RESERVED or labels[-1] in NOT_HOSTS:
                continue
            if host.endswith((".example.com", ".example.net", ".example.org")):
                continue
            if host in allowed or any(host.endswith("." + a) for a in allowed):
                continue
            offenders.add(f"{Path(path).parent.name}: {host}")
    assert not offenders, (
        "registrable / unreserved names used as infrastructure: " + ", ".join(sorted(offenders))
        + " — move them to an RFC 2606 reserved TLD, or add them to WELL_KNOWN_SERVICE_DOMAINS "
          "/ SOURCED_INCIDENT_HOSTS with a reason")


def test_every_domain_exception_carries_a_reason():
    from packetforge.scenarios import WELL_KNOWN_SERVICE_DOMAINS
    for host, why in WELL_KNOWN_SERVICE_DOMAINS.items():
        assert len(why) > 30, f"{host} needs a real justification, not {why!r}"
