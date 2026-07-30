# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 4 — is the capture warranted by the sources it was built from?

**What this checks, precisely.** Two things, and it is worth being exact because an earlier
draft of this docstring overclaimed and an audit caught it:

1. *Completeness and referential soundness of the claim register* — every rendered flow is
   licensed by a claim, every claim is rendered or declared unmodelled, citations exist where
   the class requires them, and magnitudes a source pins down are met.
2. *Content, but only where a claim says so* — a claim may carry ``expects`` predicates over
   the flows it licenses, and those are checked against the rendered values.

**What it does not establish.** A PASS does not mean the capture is a correct account of the
incident. Anything a claim does not pin down is unconstrained: before ``expects`` existed, an
audit repointed every port in sample 19 to 1337 and blanked every hostname, and the unchanged
claim set still passed. The census reports ``content_checked_flows`` so a reader can see how
much of the capture any claim actually asserts something about — and the sourced fraction so
they can see how little of it appears in a cited source at all.

The other three gates all ask a version of *is this like real traffic?*

  validity   does real Zeek reproduce what we rendered?
  realism    can an adversary tell synthetic flows from real ones?
  detection  do detections behave the same on both?

None of them can say anything about whether a capture that depicts a named, real incident is
warranted by the sources it was built from. A capture can be
byte-perfect under Zeek, indistinguishable under a C2ST, and still be a fabrication. That
is not hypothetical: sample 18 passed all three and scored ~1 of 20 on substantive network
facts when the incident's technical post-mortem landed four days later.

The failure was not thin sources. It was that invented detail and evidence-backed detail
were rendered at identical fidelity, with nothing in the artifact distinguishing them, so a
reader's default was to treat all of it as evidenced. This module makes that distinction
explicit and checkable, in both directions:

  forward   every rendered flow is licensed by a claim, or declared illustrative
  backward  every claim is rendered, or explicitly declared unmodelled with a reason
  quantity  claims carrying a floor/ceiling are measured against the artifact
  conflict  no flow asserts resolution of something a source left open
  sourcing  claims are cited where the class requires it, and not where it forbids it

Two modes exist and only one is checkable. In **emulation** mode something was actually
run, so ground truth is the executor's own log. In **reconstruction** mode nobody ran
anything — the referent is someone else's incident, seen only through prose, and no ground
truth exists at all. What exists is a warranted claim set. This module is for that mode;
for emulation it is vacuous and should not be run.

Vocabulary is adopted rather than invented. Claim stances follow ICD 203's analytic
tradecraft split (observed / judgment / assumption), plus ``technology-default`` for
behaviour entailed by a named stack rather than by a document, and ``source-unresolved``
for the case a source explicitly flags as not established. ``confidence`` is a STIX
integer 0-100 so it is comparable with any STIX consumer; the words are rendered from the
number rather than stored, so the two cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "0.1"

# ICD 203 analytic tradecraft, plus two a packet generator needs.
STANCES = ("observed", "judgment", "assumption", "technology-default", "source-unresolved")

# Stances that MUST carry a source + quote (ICD 206's citation trigger rule), and those
# that must NOT — an assumption citing a source is a category error, and the asymmetry is
# what makes the rule checkable rather than decorative.
_NEEDS_CITATION = {"observed", "judgment", "source-unresolved"}
_FORBIDS_CITATION = {"assumption"}

# STIX confidence -> the ICD 203 words. Stored as the number; rendered as the words.
_CONFIDENCE_TERMS = [
    (0, "Speculation"), (20, "Very Doubtful"), (40, "Doubtful"),
    (60, "Even Odds"), (80, "Probable"), (99, "Very Probable"), (100, "Certainty"),
]


def confidence_term(value: Optional[int]) -> str:
    if value is None:
        return "Not Specified"
    for hi, term in _CONFIDENCE_TERMS:
        if value <= hi:
            return term
    return "Certainty"


# --------------------------------------------------------------------------- #
# The claim set — a versioned document, like the Flow IR itself.               #
# --------------------------------------------------------------------------- #


class SourceRef(BaseModel):
    """One document the reconstruction rests on.

    ``sha256`` is of the retrieved prose, not the URL. It is the difference between "the
    vendor said X" and "here is the document, and here is proof it has since changed" —
    which is not academic: one of sample 18's two sources was edited after that capture
    was built against it.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    org: str = ""
    url: str = ""
    published: str = ""
    retrieved: str = ""
    sha256: Optional[str] = None
    # A source that describes itself as preliminary, about someone else's infrastructure,
    # is the weakest kind of licence. Recorded so the check can say so out loud.
    self_described_confidence: Literal["final", "preliminary", "unknown"] = "final"
    about_own_infrastructure: bool = True


class Quantifier(BaseModel):
    """A magnitude a source pins down — "several clusters", "more than 17,000 events"."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["floor", "ceiling"]
    value: float
    unit: str


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    text: str
    stance: Literal["observed", "judgment", "assumption",
                    "technology-default", "source-unresolved"]
    source: str = ""
    quote: str = ""
    confidence: Optional[int] = Field(default=None, ge=0, le=100)  # STIX 0-100
    quantifier: Optional[Quantifier] = None
    renders: list[str] = Field(default_factory=list)   # flow_ids
    # Non-empty means "we deliberately did not render this, and here is why". A declared
    # gap is a first-class output, not a failure — see the quantity check.
    unmodelled_reason: str = ""
    # Required when a quantifier names a unit no capture can testify to.
    measurement_note: str = ""
    # Checkable predicates over every flow this claim licenses: a dotted field path mapped to
    # a literal, or to "~regex". Without this, licensing is pure flow-id bookkeeping — an
    # audit repointed every port to 1337 and blanked every hostname in sample 19, and the
    # unchanged claim set still passed. A claim whose quoted span names a port, host or
    # protocol should carry one.
    expects: dict = Field(default_factory=dict)


class FieldMarking(BaseModel):
    """STIX 2.1 ``granular_markings``, retyped for the Flow IR.

    ``selectors`` address individual *facts* — the values a reader would check in Zeek's
    conn/dns/http/ssl output — as ``<flow_id>.<dotted.path>``, with ``*`` for the flow part
    to mark a field across every flow. A selector ending at a container (``*.l7``) covers
    everything beneath it. STIX's own rule is enforced: a selector must address something
    that is actually present, so a typo fails the gate rather than silently marking nothing.

    Marking lives in the claim set rather than on ``Flow`` itself. The storyline YAML is the
    human-authored artifact and has to stay readable, the claim set is already the warranting
    layer, and the only consumer that would need provenance *inside* a Flow object is an
    upstream emitter producing it — which does not exist yet. If one appears, this model moves
    onto ``Flow`` unchanged.
    """

    model_config = ConfigDict(extra="forbid")

    selectors: list[str]
    # ICD 203 analytic tradecraft, plus the class a packet generator needs: bytes present
    # only because the wire format requires a value.
    icd203: Literal["observed", "judgment", "assumption", "fabricated"]
    # NASA-STD-7009B input pedigree — grades traceability, not accuracy, so it is assignable
    # by an author who does not know the answer. L4 traceable to the real system ... L0 none.
    pedigree: Literal["L0", "L1", "L2", "L3", "L4"] = "L0"
    # PAV derivation verbs: the verb encodes how much was invented between source and field.
    derivation: Optional[Literal["retrievedFrom", "importedFrom",
                                 "derivedFrom", "sourceAccessedAt"]] = None
    claim_ref: str = ""
    # Hüllermeier & Waegeman: aleatoric = the network genuinely varies and any plausible draw
    # is fine; epistemic = the source did not say and we chose. Only epistemic detail can be
    # wrong when a post-mortem lands, so only epistemic detail is worth scoring.
    uncertainty: Literal["epistemic", "aleatoric"] = "epistemic"
    note: str = ""


class FieldMarkings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Fields where any plausible draw is fine — excluded from the epistemic surface rather
    # than marked one by one. Anything NOT listed here and NOT marked defaults to fabricated.
    aleatoric_fields: list[str] = Field(
        default_factory=lambda: ["src_port", "rtt", "seg_bytes", "start_time"])
    marks: list[FieldMarking] = Field(default_factory=list)


class ClaimSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    mode: Literal["reconstruction", "emulation"] = "reconstruction"
    # ENFSI's rule (BPM-FIT-01 §1.4): where the source base will not carry an evaluative
    # report, the remedy is to downgrade what the artifact claims to be — not to add hedging
    # prose to something still labelled a reconstruction. An `exercise` makes no claim about
    # correspondence, so correspondence findings become advisory; but it also may not be
    # described as a reconstruction of the incident.
    artifact_class: Literal["reconstruction", "exercise"] = "reconstruction"
    # Whether the prediction register below was written BEFORE any answer existed. A
    # retrospective register is a demonstration of the mechanism, never a measurement of
    # calibration, and the manifest must not imply otherwise.
    predictions_pre_registered: bool = False
    predictions_registered_at: str = ""
    subject: str
    cutoff: str = ""
    field_markings: Optional[FieldMarkings] = None
    # ICD 206's Source Summary Statement: one paragraph on what the reconstruction rests
    # on and where it is thin, written before the render.
    source_summary: str = ""
    sources: list[SourceRef] = Field(default_factory=list)
    # Flows that assert nothing about the incident and exist only for texture.
    illustrative_flows: list[str] = Field(default_factory=list)
    claims: list[Claim]
    predictions: list[Prediction] = Field(default_factory=list)


class Prediction(BaseModel):
    """A commitment the reconstruction makes *beyond* its sources, stated as a probability.

    Claims record what a source says; predictions record what the render asserts anyway —
    the port, the protocol, the outcome, the scale. These are the only things a later source
    can show to be wrong, and rendering a single confident value for one of them is itself a
    high-probability assertion whether or not anybody wrote a number down.

    Pre-registering them turns the next disclosure into a measurement rather than an
    argument.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    text: str
    probability: float = Field(ge=0.0, le=1.0)
    # The uninformed prior this is scored against. 0.5 for a coin flip, 1/N for an N-way
    # choice, the empirical base rate where one exists — "C2 runs over HTTPS" must not be
    # scored against 0.5. Pre-declared, so it cannot be tuned after the answer arrives.
    baseline: float = Field(default=0.5, ge=0.02, le=0.98)
    # Why this baseline and not another. Unrationalised baselines are a free parameter that
    # sets the score: pricing a documented protocol default as a coin flip banks points for
    # nothing.
    baseline_rationale: str = ""
    renders: list[str] = Field(default_factory=list)
    resolves_with: str = ""


class AnswerKey(BaseModel):
    """Outcomes for a prediction register, from a source that appeared after the cutoff."""

    model_config = ConfigDict(extra="forbid")

    subject: str = ""
    source: str = ""
    resolved_at: str = ""
    note: str = ""
    # id -> true | false | unresolved
    outcomes: dict = Field(default_factory=dict)


def load_claimset(path) -> ClaimSet:
    import yaml
    return ClaimSet.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# Measurement — what a capture can actually testify to.                        #
# --------------------------------------------------------------------------- #

_FAILED_STATES = {"S0", "REJ", "RSTR", "RSTO"}


def _is_failed(f) -> bool:
    """Wire-visible failure only.

    An earlier version also matched "denied"/"blocked"/"timeout" in the flow_id, which meant
    the one numeric floor sample 19 enforced was satisfied by *naming* rather than by packets:
    renaming fifteen flows changed the measured value from 0.25 to 0.11 without touching a
    byte. Application-layer denial under TLS is genuinely invisible here — that is a finding
    about the vantage, not something a measure should paper over.
    """
    if f.transport == "udp":
        return False
    return f.conn_state in _FAILED_STATES


def _internal(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_link_local


MEASURES = {
    "flows": lambda fl: float(len(fl)),
    "distinct-dst-ips": lambda fl: float(len({f.dst_ip for f in fl})),
    "distinct-external-dst-ips": lambda fl: float(len({f.dst_ip for f in fl
                                                       if not _internal(f.dst_ip)})),
    "distinct-internal-src-ips": lambda fl: float(len({f.src_ip for f in fl
                                                       if _internal(f.src_ip)})),
    "capture-span-seconds": lambda fl: (max(f.start_time for f in fl)
                                        - min(f.start_time for f in fl)) if fl else 0.0,
    "failed-flow-fraction": lambda fl: (sum(1 for f in fl if _is_failed(f)) / len(fl)) if fl else 0.0,
}

# Units no packet capture can testify to. Naming one is not an error — it is a statement
# that the claim belongs in the manifest rather than in the packets. Silently converting an
# action count into a flow count *is* the error, and it is what sample 18 did with "more
# than 17,000 recorded events" -> 16 flows.
UNMEASURABLE = {
    "attacker-actions": "an action count is not a flow count; no capture can testify to it",
    "clusters": "cluster identity is not on the wire; distinct-dst-ips counts API endpoints",
    "credentials": "credential counts are not observable in encrypted traffic",
    "c2-endpoints": "only endpoints actually contacted are observable",
    "hosts-compromised": "compromise is a control-plane fact; only hosts that originate "
                         "traffic are observable",
    "application-layer-denials": "under TLS an authorization denial is indistinguishable from a "
                                 "success except by response size; it is not a countable event",
}


# --------------------------------------------------------------------------- #
# Field-level facts and their markings                                         #
# --------------------------------------------------------------------------- #

# Structural fields — they identify the flow rather than assert anything about the incident.
_NOT_A_FACT = {"flow_id", "expect", "expected_alert"}


def flow_facts(flow) -> list:
    """Every *fact* a flow asserts, as a dotted path.

    Only fields the author actually wrote. ``exclude_unset`` rather than
    ``exclude_defaults``: a field explicitly authored at its default value — ``conn_state: SF``,
    ``dst_os: linux`` — is still an assertion, and excluding it made those facts invisible to
    the census and impossible to mark.
    """
    def walk(d: dict, prefix: str = "") -> list:
        out = []
        for k, v in d.items():
            path = f"{prefix}{k}"
            if isinstance(v, dict):
                out.extend(walk(v, path + "."))
            else:
                out.append(path)
        return out

    dumped = flow.model_dump(exclude_unset=True, exclude_none=True)
    return [p for p in walk(dumped) if p.split(".")[0] not in _NOT_A_FACT]


def _selector_score(sel: str, flow_id: str, fact: str):
    """How well a selector matches (flow_id, fact); None if it does not. Higher wins."""
    head, _, path = sel.partition(".")
    if head != "*" and head != flow_id:
        return None
    if path and not (fact == path or fact.startswith(path + ".")):
        return None
    # exact flow beats wildcard; a deeper path beats a shallower one
    return (1 if head != "*" else 0, len(path.split(".")) if path else 0)


def resolve_marking(fm: Optional[FieldMarkings], flow_id: str, fact: str):
    """The most specific marking for a fact, or None if nothing marks it."""
    if fm is None:
        return None
    best = None
    best_score = None
    for m in fm.marks:
        for sel in m.selectors:
            score = _selector_score(sel, flow_id, fact)
            if score is not None and (best_score is None or score > best_score):
                best, best_score = m, score
    return best


# --------------------------------------------------------------------------- #
# The check                                                                    #
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    level: str      # FAIL | WARN | INFO
    code: str
    detail: str


@dataclass
class WarrantReport:
    findings: list = field(default_factory=list)
    census: dict = field(default_factory=dict)
    subject: str = ""
    cutoff: str = ""

    @property
    def fails(self) -> list:
        return [f for f in self.findings if f.level == "FAIL"]

    @property
    def warns(self) -> list:
        return [f for f in self.findings if f.level == "WARN"]

    @property
    def gaps(self) -> list:
        return [f for f in self.findings if f.code == "unmodelled"]

    @property
    def ok(self) -> bool:
        return not self.fails


def check(cs: ClaimSet, flows: list) -> WarrantReport:
    """Check a rendered FlowSet's flows against the claim set that licenses them."""
    rep = WarrantReport(subject=cs.subject, cutoff=cs.cutoff)
    by_id = {f.flow_id: f for f in flows}
    sources = {s.id: s for s in cs.sources}
    add = rep.findings.append

    # ---- structural sanity -------------------------------------------------
    seen_ids: set = set()
    for c in cs.claims:
        if c.id in seen_ids:
            add(Finding("FAIL", "duplicate-claim-id", f"{c.id} appears more than once"))
        seen_ids.add(c.id)
        if c.stance in _NEEDS_CITATION and not (c.source and c.quote):
            add(Finding("FAIL", "missing-citation",
                        f"{c.id} is '{c.stance}' and must cite a source and a quoted span"))
        if c.stance in _FORBIDS_CITATION and c.source:
            add(Finding("FAIL", "citation-on-assumption",
                        f"{c.id} is an assumption and must not cite a source "
                        f"(it cites {c.source!r}); an assumption with a source is a judgment"))
        if c.source and c.source not in sources:
            add(Finding("FAIL", "unknown-source",
                        f"{c.id} cites source {c.source!r}, which is not in sources[]"))
        for fid in c.renders:
            if fid not in by_id:
                add(Finding("FAIL", "dangling-render",
                            f"{c.id} renders {fid!r}, which is not in the flowset"))

    # ---- forward: every flow licensed --------------------------------------
    licensed: dict = {}
    for c in cs.claims:
        for fid in c.renders:
            licensed.setdefault(fid, []).append(c)

    dupes = {f.flow_id for f in flows if sum(1 for g in flows if g.flow_id == f.flow_id) > 1}
    for fid in sorted(dupes):
        add(Finding("FAIL", "duplicate-flow-id",
                    f"{fid} appears more than once in the flowset; facts are double-counted and "
                    f"a selector cannot address one of them unambiguously"))
    illustrative = set(cs.illustrative_flows)
    for fid in sorted(illustrative & set(licensed)):
        add(Finding("FAIL", "licensed-and-illustrative",
                    f"{fid} is both declared illustrative and licensed by a claim — it either "
                    f"asserts something or it does not"))
    for fid in illustrative:
        if fid not in by_id:
            add(Finding("FAIL", "dangling-illustrative",
                        f"illustrative_flows names {fid!r}, which is not in the flowset"))
    for f in flows:
        if f.flow_id in licensed or f.flow_id in illustrative:
            continue
        add(Finding("FAIL", "unlicensed-flow",
                    f"{f.flow_id} ({f.src_ip} -> {f.dst_ip}:{f.dst_port}) is rendered, but no "
                    f"claim licenses it and it is not declared illustrative"))

    # ---- backward: every claim rendered or declared unmodelled -------------
    for c in cs.claims:
        if c.stance == "source-unresolved":
            continue                       # handled by the conflict check
        if c.renders:
            continue
        if c.unmodelled_reason:
            add(Finding("INFO", "unmodelled", f"{c.id}: {c.text} — {c.unmodelled_reason}"))
            continue
        add(Finding("FAIL", "unaccounted-claim",
                    f"{c.id} is neither rendered nor declared unmodelled: {c.text}"))

    # ---- conflict: never resolve what a source left open -------------------
    for c in cs.claims:
        if c.stance == "source-unresolved" and c.renders:
            add(Finding("FAIL", "resolves-open-question",
                        f"{c.id} is flagged by {c.source or 'its source'} as NOT established, "
                        f"but flows {c.renders} render it as fact: {c.text}"))

    # ---- content: does the flow actually look like what the claim says? ----
    def _at(d: dict, path: str):
        cur = d
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return _MISSING
            cur = cur[part]
        return cur

    content_checked: set = set()
    _satisfied: set = set()
    for c in cs.claims:
        if not c.expects:
            continue
        for fid in c.renders:
            f = by_id.get(fid)
            if f is None:
                continue
            content_checked.add(fid)
            dumped = f.model_dump(exclude_none=True)
            for path, want in c.expects.items():
                got = _at(dumped, path)
                if got is _MISSING:
                    # Not applicable: a claim usually licenses a name lookup as well as the
                    # session it precedes, and the lookup carries no server_name. Silence here
                    # is safe only because an expectation no licensed flow can satisfy is
                    # caught below.
                    continue
                _satisfied.add((c.id, path))
                if isinstance(want, str) and want.startswith("~"):
                    import re as _re
                    if not _re.search(want[1:], str(got)):
                        add(Finding("FAIL", "expectation-violated",
                                    f"{c.id} expects {path} to match /{want[1:]}/ on {fid}; "
                                    f"the flow has {got!r}. Quote: \"{c.quote[:90]}\""))
                elif str(got) != str(want):
                    add(Finding("FAIL", "expectation-violated",
                                f"{c.id} expects {path}={want!r} on {fid}; the flow has {got!r}. "
                                f"Quote: \"{c.quote[:90]}\""))

    for c in cs.claims:
        for path, want in (c.expects or {}).items():
            if (c.id, path) not in _satisfied:
                add(Finding("FAIL", "expectation-unsatisfied",
                            f"{c.id} expects {path}={want!r}, but no flow it licenses carries "
                            f"that field at all — the expectation is vacuous"))

    # ---- quantity ----------------------------------------------------------
    # A declared gap suppresses its own quantity check, deliberately: the failure mode being
    # prevented is *silent* under-rendering, not declared under-rendering. An author who
    # writes "the source says eleven nodes, this vantage shows two, and here is why" has
    # produced the honest artifact. One who quietly renders one and says nothing has not.
    for c in cs.claims:
        q = c.quantifier
        if q is None:
            continue
        if c.unmodelled_reason:
            add(Finding("INFO", "quantity-declared-unmodelled",
                        f"{c.id}: {q.kind}={q.value:g} {q.unit} not enforced — declared unmodelled"))
            continue
        if q.unit in UNMEASURABLE:
            if c.renders and not c.measurement_note:
                add(Finding("WARN", "unmeasurable-quantifier",
                            f"{c.id} carries {q.kind}={q.value:g} {q.unit} — {UNMEASURABLE[q.unit]}. "
                            f"Carry it in the manifest, or add a measurement_note describing the "
                            f"mapping from the source's units to what is rendered."))
            continue
        if q.unit not in MEASURES:
            add(Finding("FAIL", "unknown-unit",
                        f"{c.id}: no measure defined for unit {q.unit!r}"))
            continue
        actual = MEASURES[q.unit](flows)
        if q.kind == "floor" and actual < q.value:
            add(Finding("FAIL", "floor-violated",
                        f"{c.id}: source gives a floor of {q.value:g} {q.unit}; the artifact has "
                        f"{actual:g}. Quote: \"{c.quote}\""))
        elif q.kind == "ceiling" and actual > q.value:
            add(Finding("FAIL", "ceiling-violated",
                        f"{c.id}: ceiling {q.value:g} {q.unit}; the artifact has {actual:g}"))

    # ---- sourcing: name the weak licences ----------------------------------
    _rank = {s: i for i, s in enumerate(("observed", "technology-default", "judgment",
                                         "assumption", "source-unresolved"))}
    for fid, cl in sorted(licensed.items()):
        best = min(cl, key=lambda c: _rank.get(c.stance, 99))
        if best.stance == "assumption":
            add(Finding("WARN", "assumption-only",
                        f"{fid} is licensed only by an assumption ({best.id}) — no source "
                        f"supports it"))
            continue
        src = sources.get(best.source)
        if src and src.self_described_confidence == "preliminary" and not src.about_own_infrastructure:
            add(Finding("WARN", "third-party-preliminary",
                        f"{fid} rests on {best.id}, a self-described preliminary claim by "
                        f"{src.org or src.id} about another organisation's infrastructure. "
                        f"Prefer rendering the attempt over the outcome."))

    # ---- field-level marking ----------------------------------------------
    # The unit is the value a reader would check in a Zeek log, not the flow. A manifest that
    # marks a whole flow is decorative: Splunk's attack_data labels an entire Sysmon log as
    # "the T1003.001 artifact", which is why it can answer "did my search fire?" but not "what
    # fraction of what I claimed is actually there?".
    fm = cs.field_markings
    aleatoric = set(fm.aleatoric_fields) if fm else set()
    facts = [(f.flow_id, fact) for f in flows for fact in flow_facts(f)]
    field_mix = {"observed": 0, "judgment": 0, "assumption": 0,
                 "fabricated": 0, "aleatoric": 0}
    _invalid_marks: set = set()
    claim_ids = {c.id for c in cs.claims}

    if fm is not None:
        for m in fm.marks:
            # Per SELECTOR, not per marking: a garbage selector sitting beside a good one used
            # to pass silently, which is exactly the typo this check exists to catch.
            for sel in m.selectors:
                if not any(_selector_score(sel, flow_id, fact) is not None
                           for flow_id, fact in facts):
                    add(Finding("FAIL", "dangling-selector",
                                f"selector {sel!r} addresses nothing present in the flowset; "
                                f"STIX requires a selector to refer to a property that exists"))
            if m.icd203 in ("observed", "judgment") and not m.claim_ref:
                add(Finding("FAIL", "marking-without-citation",
                            f"marking {m.selectors} is '{m.icd203}' and must name a claim_ref"))
            if m.icd203 == "fabricated" and m.claim_ref:
                add(Finding("FAIL", "fabricated-with-citation",
                            f"marking {m.selectors} is 'fabricated' but cites {m.claim_ref!r}; "
                            f"a fabricated value rests on no evidence by definition"))
            if m.icd203 == "observed" and m.pedigree not in ("L3", "L4"):
                add(Finding("FAIL", "pedigree-too-low",
                            f"marking {m.selectors} is 'observed' at pedigree {m.pedigree}; a "
                            f"value taken from a source is traceable to it (L3/L4) by definition"))
            if m.icd203 == "observed" and m.derivation not in ("retrievedFrom", "importedFrom"):
                add(Finding("FAIL", "derivation-not-source-anchored",
                            f"marking {m.selectors} is 'observed' but its derivation is "
                            f"{m.derivation!r}; an observed value is retrieved or restated from a "
                            f"source, not derived from one"))
            if m.icd203 == "fabricated" and m.pedigree != "L0":
                add(Finding("FAIL", "pedigree-overclaimed",
                            f"marking {m.selectors} is 'fabricated' at pedigree {m.pedigree}; "
                            f"a value resting on nothing is L0"))
            if m.claim_ref and m.claim_ref not in claim_ids:
                add(Finding("FAIL", "unknown-claim-ref",
                            f"marking {m.selectors} cites claim {m.claim_ref!r}, which does not exist"))
            elif m.icd203 in ("observed", "judgment") and m.claim_ref:
                # A field cannot be better-sourced than the claim it points at. Without this,
                # `observed` is a self-declared label and `sourced_fraction` counts the author's
                # own opinion of their work.
                c = next((x for x in cs.claims if x.id == m.claim_ref), None)
                if c is not None and not (c.source in sources and c.quote):
                    _invalid_marks.add(id(m))
                    add(Finding("FAIL", "unsourced-marking",
                                f"marking {m.selectors} is '{m.icd203}' via claim {c.id}, but that "
                                f"claim carries no source in sources[] and/or no quoted span — the "
                                f"field inherits no licence"))

    for flow_id, fact in facts:
        # Resolve the explicit marking FIRST. Testing aleatoric_fields first meant a list entry
        # silently discarded an author's own marking — and matching on the last path component
        # anywhere in the tree made that easy to do by accident.
        mk = resolve_marking(fm, flow_id, fact)
        if mk is None and (fact in aleatoric or fact.split(".")[-1] in aleatoric):
            field_mix["aleatoric"] += 1
            continue
        if mk is not None and (fact in aleatoric or fact.split(".")[-1] in aleatoric):
            add(Finding("WARN", "aleatoric-shadowed-by-marking",
                        f"{flow_id}.{fact} is listed in aleatoric_fields but also explicitly "
                        f"marked '{mk.icd203}'; the marking wins"))
        # VERIS's absence discipline: a blank marking must never read as a positive claim, so
        # unmarked resolves to the weakest class. Forgetting to mark fails safe. A marking that
        # failed its own sourcing check does not get to inflate the sourced fraction either.
        if mk is not None and id(mk) in _invalid_marks:
            mk = None
        field_mix[mk.icd203 if mk else "fabricated"] += 1

    # ---- prediction register hygiene ---------------------------------------
    for pred in cs.predictions:
        if not pred.renders:
            continue
        marks = [resolve_marking(fm, fid, fact)
                 for fid in pred.renders for fact in
                 (flow_facts(by_id[fid]) if fid in by_id else [])]
        marks = [m for m in marks if m is not None]
        if marks and all(m.icd203 == "observed" for m in marks):
            add(Finding("FAIL", "prediction-is-not-a-prediction",
                        f"{pred.id} predicts something every one of its rendered fields is "
                        f"already marked 'observed' — that is a restatement of a source, not a "
                        f"commitment beyond it, and scoring it inflates the result"))

    # ---- artifact class ----------------------------------------------------
    # The accounting checks above are necessary but not sufficient, and on their own they are
    # gameable: declare every flow illustrative, declare the one claim unmodelled, and a
    # storyline about nothing passes with zero findings. That is a real hole — a bare "PASS"
    # on an artifact with no sourced facts is precisely the misleading-precision failure this
    # gate exists to prevent, reintroduced by the gate itself. So a reconstruction must also
    # be *about* something: at least one fact drawn from a cited source, and at least one
    # claim that actually reaches the wire. An artifact with neither is an exercise.
    if cs.artifact_class == "reconstruction":
        if field_mix["observed"] == 0:
            add(Finding("FAIL", "nothing-sourced",
                        "declared a RECONSTRUCTION but no field is marked 'observed' — nothing "
                        "in this capture is drawn from a cited source, so it reconstructs "
                        "nothing. Downgrade artifact_class to 'exercise'."))
        if not any(c.renders for c in cs.claims):
            add(Finding("FAIL", "nothing-rendered",
                        "declared a RECONSTRUCTION but no claim renders any flow — every flow is "
                        "illustrative or unlicensed, so the capture depicts no claim at all."))
    if cs.artifact_class == "reconstruction" and cs.claims:
        gap_frac = sum(1 for c in cs.claims
                       if not c.renders and c.unmodelled_reason) / len(cs.claims)
        if gap_frac > 0.5:
            add(Finding("FAIL", "mostly-unmodelled",
                        f"{gap_frac:.0%} of claims are declared unmodelled. A declared gap is "
                        f"honest; a claim set that is mostly gaps is not a reconstruction of "
                        f"anything. Downgrade artifact_class to 'exercise'."))
        reasons = [c.unmodelled_reason.strip().lower() for c in cs.claims
                   if c.unmodelled_reason]
        dupes = {r for r in reasons if reasons.count(r) > 1}
        if dupes:
            add(Finding("WARN", "boilerplate-gap-reason",
                        f"{len(dupes)} unmodelled_reason string(s) are reused verbatim across "
                        f"claims — boilerplate is the tell that a gap was declared to pass the "
                        f"gate rather than to inform a reader"))
    if cs.artifact_class == "reconstruction" and not cs.source_summary:
        add(Finding("FAIL", "missing-source-summary",
                    "an artifact claiming to be a reconstruction must carry a source summary "
                    "naming what it rests on and where the source base is thin"))
    if cs.artifact_class == "exercise":
        # Findings stay visible, but stop being build-breaking: an exercise never claimed
        # correspondence in the first place.
        for f in rep.findings:
            if f.level == "FAIL":
                f.level = "WARN"
        add(Finding("INFO", "artifact-class",
                    "declared an EXERCISE: correspondence findings are advisory. This artifact "
                    "must not be described as a reconstruction of the incident."))
    elif rep.fails:
        add(Finding("FAIL", "class-not-earned",
                    f"declared a RECONSTRUCTION but {len(rep.fails)} correspondence findings "
                    f"stand. Either license the unaccounted material, or downgrade "
                    f"artifact_class to 'exercise' — hedging prose is not the remedy."))

    # ---- census ------------------------------------------------------------
    stance_mix: dict = {}
    for fid in by_id:
        if fid in licensed:
            key = min((c.stance for c in licensed[fid]), key=lambda s: _rank.get(s, 99))
        elif fid in illustrative:
            key = "illustrative"
        else:
            key = "UNLICENSED"
        stance_mix[key] = stance_mix.get(key, 0) + 1

    accounted = sum(1 for c in cs.claims
                    if c.renders or c.unmodelled_reason or c.stance == "source-unresolved")
    rep.census = {
        "mode": cs.mode,
        "flows": len(flows),
        "claims": len(cs.claims),
        "claims_rendered": sum(1 for c in cs.claims if c.renders),
        "claims_unmodelled": sum(1 for c in cs.claims
                                 if not c.renders and c.unmodelled_reason),
        "claims_accounted": accounted,
        "claims_unaccounted": len(cs.claims) - accounted,
        "flow_stance_mix": stance_mix,
        "network_facts": len(facts),
        "field_class_mix": field_mix,
        # Only epistemic detail can be wrong when a fuller account lands: aleatoric variation
        # is not a claim, and a fabricated value already says it rests on nothing. This number
        # is the artifact's actual exposure.
        "epistemic_surface": field_mix["observed"] + field_mix["judgment"] + field_mix["assumption"],
        # The number a bare "PASS" must never be reported without. A gate verdict says the
        # accounting is coherent; this says how much of the artifact is actually evidence.
        "sourced_fraction": round(field_mix["observed"] / len(facts), 4) if facts else 0.0,
        # Licensing alone is flow-id bookkeeping. This counts the flows a claim actually
        # asserts something checkable about.
        "content_checked_flows": len(content_checked),
        "failed_flow_fraction": round(MEASURES["failed-flow-fraction"](flows), 3),
        "capture_span_hours": round(MEASURES["capture-span-seconds"](flows) / 3600.0, 2),
        "sources": len(cs.sources),
    }
    return rep


# --------------------------------------------------------------------------- #
# The manifest — generated, never hand-written.                                #
# --------------------------------------------------------------------------- #


def _census_block(census: dict) -> list:
    mix = census["flow_stance_mix"]
    mix_s = " · ".join(f"{v} {k}" for k, v in sorted(mix.items(), key=lambda kv: -kv[1]))
    fmix = census.get("field_class_mix", {})
    fmix_s = " · ".join(f"{v} {k}" for k, v in fmix.items() if v)
    return [
        f"- **{census['flows']} flows**: {mix_s}",
        f"- **{census['claims']} source claims**: {census['claims_rendered']} rendered · "
        f"{census['claims_unmodelled']} declared unmodelled · "
        f"{census['claims_unaccounted']} unaccounted",
        f"- **{census.get('network_facts', 0)} network facts**: {fmix_s or 'unmarked'}",
        f"- **epistemic surface: {census.get('epistemic_surface', 0)}** — the facts that could "
        f"be shown wrong by a fuller account. The rest is either aleatoric variation or already "
        f"declared to rest on nothing.",
        f"- **{census['failed_flow_fraction']:.0%}** of flows are the actor failing · "
        f"span **{census['capture_span_hours']}h** · **{census['sources']}** sources",
    ]


def render_manifest(cs: ClaimSet, rep: WarrantReport, score_result=None) -> str:
    """The human manifest: census first, gaps second, the claim register last.

    Order is deliberate. The gap list stayed correct when the packets did not — so it
    outranks them.
    """
    exercise = cs.artifact_class == "exercise"
    downgraded = sum(1 for f in rep.findings
                     if f.level == "WARN" and f.code not in _ADVISORY_CODES) if exercise else 0
    verdict = ("ADVISORY" if exercise and rep.warns else "PASS") if rep.ok else "FAIL"
    out = [
        (f"# Exercise claims — {cs.subject}" if exercise
         else f"# Reconstruction claims — {cs.subject}"),
        "",
        ("> **SYNTHETIC, AND AN EXERCISE — NOT A RECONSTRUCTION.** This artifact makes no claim to\n"
         "> correspond to any real incident; correspondence findings below are advisory and were\n"
         "> NOT met. It must not be described as a reconstruction."
         if exercise else
         "> **SYNTHETIC. This is a reconstruction, not ground truth.** Nobody ran this incident;"),
        ("" if exercise else
         "> the referent is a real event seen only through the sources listed below."),
        "> Every address, byte count, and port choice for a redacted service is invented. This",
        "> file is generated from the claim set and the rendered flows — do not edit it by hand.",
        "",
        f"**Information cutoff: {cs.cutoff}** · correspondence gate: **{verdict}** "
        f"({len(rep.fails)} fail, {len(rep.warns)} warn"
        + (f", {downgraded} downgraded from fail because this is an exercise)" if downgraded
           else ")"),
        "",
        f"> A gate verdict says the *accounting* is coherent — every flow licensed, every claim "
        f"rendered or declared. It does **not** say the capture is right. "
        f"**{rep.census.get('sourced_fraction', 0.0):.1%} of the network facts here appear in a "
        f"cited source**; the rest are inferred, authored, or aleatoric variation.",
        "",
        "## Census",
        "",
        "_Counts describe the **storyline** — the attack flows this claim set licenses. The "
        "`capture.pcap` beside it composes that storyline into ambient background traffic, or "
        "renders a time-slice of it, so its connection count is different by design._",
        "",
    ]
    out += _census_block(rep.census)
    out.append("")

    if cs.source_summary:
        out += ["## Source summary", "", cs.source_summary, ""]

    out += ["## What is NOT modelled", ""]
    if rep.gaps:
        out.append("The gap list outranks the packets: it was correct on the day it was written "
                   "and stays correct as the record improves.")
        out.append("")
        for g in rep.gaps:
            out.append(f"- {g.detail}")
    else:
        out.append("_Nothing declared unmodelled._")
    out.append("")

    if rep.fails or rep.warns:
        out += ["## Gate findings", ""]
        for f in rep.fails + rep.warns:
            out.append(f"- **{f.level}** `{f.code}` — {f.detail}")
        out.append("")

    out += ["## Sources", "",
            "| id | org | title | published | retrieved | confidence | first-party | sha256 |",
            "|---|---|---|---|---|---|---|---|"]
    for s in cs.sources:
        out.append(f"| `{s.id}` | {s.org} | [{s.title}]({s.url}) | {s.published} | {s.retrieved} "
                   f"| {s.self_described_confidence} | {'yes' if s.about_own_infrastructure else 'no'} "
                   f"| `{(s.sha256 or '—')[:16]}` |")
    out.append("")

    out += ["## Claim register", "",
            "One row per claim. `rendered observable` is what a reader should be able to find in "
            "the Zeek logs; `stance` is how the claim relates to its source.", "",
            "| id | claim | stance | confidence | source | flows | quantifier |",
            "|---|---|---|---|---|---|---|"]
    for c in cs.claims:
        flows_s = ", ".join(f"`{x}`" for x in c.renders) if c.renders else "_(unmodelled)_"
        q = (f"{c.quantifier.kind} {c.quantifier.value:g} {c.quantifier.unit}"
             if c.quantifier else "—")
        out.append(f"| `{c.id}` | {c.text} | {c.stance} | {confidence_term(c.confidence)} "
                   f"| `{c.source or '—'}` | {flows_s} | {q} |")
    out.append("")

    if cs.predictions:
        pre = cs.predictions_pre_registered
        head = ("## Pre-registered predictions" if pre
                else "## Prediction register — RETROSPECTIVE, not pre-registered")
        blurb = ("What this reconstruction commits to *beyond* its sources — the only things a "
                 "later account can show to be wrong. Registered "
                 + (f"on {cs.predictions_registered_at}, before any answer existed, so the next "
                    "disclosure is a measurement rather than an argument."
                    if pre else
                    "**after** the answers were already known. These probabilities were "
                    "reconstructed from what the capture rendered; the score below demonstrates "
                    "the mechanism and is **not** a measurement of calibration."))
        out += [head, "", blurb, "",
                "| id | p | baseline | why that baseline | prediction | resolves with |",
                "|---|---:|---:|---|---|---|"]
        for pr in cs.predictions:
            out.append(f"| `{pr.id}` | {pr.probability:.2f} | {pr.baseline:.2f} "
                       f"| {pr.baseline_rationale or '**unrationalised**'} | {pr.text} "
                       f"| {pr.resolves_with or '—'} |")
        out.append("")

    if score_result and score_result["summary"].get("resolved"):
        s = score_result["summary"]
        out += ["## Score", "",
                f"Resolved by **{s['source']}** ({s['resolved_at']}). "
                f"{s['resolved']} of {s['predictions']} predictions resolved.", ""]
        if s.get("note"):
            out += [f"> {s['note']}", ""]
        out += [
                f"- **mean baseline log score: {s['mean_log_score']:+.1f}** "
                f"(positive beats an uninformed prior; this is the headline)",
                f"- beat the prior on **{s['beat_ignorance']}**, did worse on "
                f"**{s['worse_than_ignorance']}**",
                f"- mean Brier **{s['mean_brier']}** of a possible 2.0",
                f"- Murphy: reliability {s['murphy']['reliability']} − resolution "
                f"{s['murphy']['resolution']} + uncertainty {s['murphy']['uncertainty']}",
                "", "| id | p | outcome | log score | prediction |", "|---|---:|---|---:|---|"]
        for r in score_result["rows"]:
            if not r["resolved"]:
                continue
            out.append(f"| `{r['id']}` | {r['probability']:.2f} | "
                       f"{'TRUE' if r['outcome'] else 'FALSE'} | {r['log_score']:+.1f} "
                       f"| {r['text']} |")
        out.append("")

    out += ["## Quoted spans", ""]
    for c in cs.claims:
        if c.quote:
            out.append(f"- `{c.id}` — {c.source}: “{c.quote}”")
    out.append("")
    return "\n".join(out)


def manifest_json(cs: ClaimSet, rep: WarrantReport, score_result=None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "synthetic": True,
        "mode": cs.mode,
        "subject": cs.subject,
        "cutoff": cs.cutoff,
        "disclaimer": ("A reconstruction, not ground truth. Generated from the claim set and the "
                       "rendered flows. Every address, byte count and port choice for a redacted "
                       "service is invented. Do not block, hunt, or report these indicators."),
        "verdict": ("advisory" if cs.artifact_class == "exercise" and rep.warns
                    else "pass") if rep.ok else "fail",
        "artifact_class": cs.artifact_class,
        "census": rep.census,
        "source_summary": cs.source_summary,
        "sources": [s.model_dump() for s in cs.sources],
        "claims": [c.model_dump(exclude_defaults=False) for c in cs.claims],
        "unmodelled": [g.detail for g in rep.gaps],
        "findings": [{"level": f.level, "code": f.code, "detail": f.detail}
                     for f in rep.findings if f.level != "INFO"],
        "predictions": [p.model_dump() for p in cs.predictions],
        "score": score_result,
    }


# --------------------------------------------------------------------------- #
# Scoring — turning the next disclosure into a measurement                      #
# --------------------------------------------------------------------------- #

_ADVISORY_CODES = {"assumption-only", "third-party-preliminary", "unmeasurable-quantifier",
                   "boilerplate-gap-reason", "aleatoric-shadowed-by-marking"}

_MISSING = object()

_CLIP = 0.01   # Selten's unboundedness objection: without a clip one confident miss is -inf


def load_answer_key(path) -> AnswerKey:
    import yaml
    return AnswerKey.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def _reliability(rows: list, bins: int = 5) -> list:
    """Murphy's decomposition needs forecasts grouped; this is also the reliability table."""
    out = []
    for k in range(bins):
        lo, hi = k / bins, (k + 1) / bins
        # half-open [lo, hi), closed at the top bin, so every forecast lands in exactly one
        grp = [r for r in rows if (lo <= r.get("_p", r["probability"]) < hi)
               or (k == bins - 1 and r.get("_p", r["probability"]) == 1.0)]
        if not grp:
            continue
        # Unrounded — the Murphy decomposition is computed from these, and rounding here
        # breaks the REL - RES + UNC identity by ~1e-2, which then silently reads as a bug.
        out.append({
            "bin": f"[{lo:.1f},{hi:.1f}{']' if k == bins - 1 else ')'}",
            "n": len(grp),
            "mean_forecast": sum(r.get("_p", r["probability"]) for r in grp) / len(grp),
            "observed_rate": sum(1 for r in grp if r["outcome"]) / len(grp),
        })
    return out


def score(cs: ClaimSet, key: AnswerKey) -> dict:
    """Score a prediction register against outcomes.

    Headline is the **baseline log score**, ``100 * log2(p_outcome / baseline)``: positive
    beat ignorance, negative did worse than it. The logarithmic rule is the unique proper
    *local* rule, so a prediction is scored only on the probability it put on what actually
    happened — which is exactly the failure being measured here, confident assertion of an
    invented detail. Brier is reported alongside as the diagnostic, with Murphy's
    reliability/resolution/uncertainty decomposition.
    """
    import math

    rows = []
    for p in cs.predictions:
        raw = key.outcomes.get(p.id, "unresolved")
        if raw not in ("true", "false"):
            rows.append({"id": p.id, "text": p.text, "probability": p.probability,
                         "baseline": p.baseline, "outcome": None, "resolved": False,
                         "log_score": None, "brier": None})
            continue
        outcome = raw == "true"
        pr = min(max(p.probability, _CLIP), 1 - _CLIP)
        p_out = pr if outcome else 1 - pr
        base = p.baseline if outcome else 1 - p.baseline
        rows.append({
            "id": p.id, "text": p.text, "probability": p.probability,
            "baseline": p.baseline, "outcome": outcome, "resolved": True,
            "log_score": round(100.0 * math.log2(p_out / base), 1),
            "_brier_raw": 2.0 * (pr - (1.0 if outcome else 0.0)) ** 2,
            # two-outcome sum form, 0 best / 2 worst, as the Good Judgment Project reports it
            "brier": round(2.0 * (pr - (1.0 if outcome else 0.0)) ** 2, 4),
        })

    done = [r for r in rows if r["resolved"]]
    # The decomposition must see the same probabilities the Brier scores did, so clip here too.
    for r in done:
        r["_p"] = min(max(r["probability"], _CLIP), 1 - _CLIP)
    n = len(done)
    summary = {
        "predictions": len(rows),
        "resolved": n,
        "unresolved": len(rows) - n,
        "source": key.source,
        "resolved_at": key.resolved_at,
        "note": key.note,
    }
    if n:
        base_rate = sum(1 for r in done if r["outcome"]) / n
        mean_brier = sum(r["_brier_raw"] for r in done) / n
        summary.update({
            "mean_log_score": round(sum(r["log_score"] for r in done) / n, 1),
            "total_log_score": round(sum(r["log_score"] for r in done), 1),
            "beat_ignorance": sum(1 for r in done if r["log_score"] > 0),
            "worse_than_ignorance": sum(1 for r in done if r["log_score"] < 0),
            "mean_brier": round(mean_brier, 4),
            "base_rate": round(base_rate, 3),
        })
        # Murphy's decomposition is an exact identity only when forecasts are grouped by
        # DISTINCT VALUE. Grouping into intervals leaves a within-bin variance residual, which
        # then reads as a bug in the arithmetic rather than a property of the binning. So:
        # decompose over distinct values, and bin only for the human-readable table.
        groups: dict = {}
        for r in done:
            groups.setdefault(r["_p"], []).append(r)
        rel = sum(len(g) * (p_val - sum(1 for x in g if x["outcome"]) / len(g)) ** 2
                  for p_val, g in groups.items()) / n
        res = sum(len(g) * (sum(1 for x in g if x["outcome"]) / len(g) - base_rate) ** 2
                  for p_val, g in groups.items()) / n
        unc = base_rate * (1 - base_rate)
        summary["murphy"] = {
            "reliability": round(2 * rel, 4), "resolution": round(2 * res, 4),
            "uncertainty": round(2 * unc, 4),
            "identity_holds": abs((rel - res + unc) * 2 - mean_brier) < 1e-9,
            "grouped_by": "distinct forecast value",
        }
        rel_rows = _reliability(done)
        if n < 30 or base_rate in (0.0, 1.0):
            summary["murphy"]["note"] = (
                f"decorative at n={n}, base rate {base_rate:.2f}: resolution and uncertainty are "
                f"undefined or degenerate on a register this small")
        summary["reliability_table"] = [
            {**r, "mean_forecast": round(r["mean_forecast"], 3),
             "observed_rate": round(r["observed_rate"], 3)} for r in rel_rows]
        for r in done:
            r.pop("_p", None)
    for r in rows:
        r.pop("_brier_raw", None)
    return {"summary": summary, "rows": rows}


def render_score(result: dict) -> str:
    s, rows = result["summary"], result["rows"]
    out = [f"PREDICTION SCORE — resolved by {s.get('source') or '(unnamed source)'} "
           f"{s.get('resolved_at', '')}".rstrip(),
           f"  {s['resolved']}/{s['predictions']} predictions resolved "
           f"({s['unresolved']} still open)"]
    if s["resolved"]:
        out += [
            f"  mean baseline log score : {s['mean_log_score']:+.1f}   "
            f"(positive = beat ignorance)",
            f"  beat / worse than prior : {s['beat_ignorance']} / {s['worse_than_ignorance']}",
            f"  mean Brier (0 best, 2 worst): {s['mean_brier']}",
            f"  Murphy: REL {s['murphy']['reliability']} − RES {s['murphy']['resolution']} "
            f"+ UNC {s['murphy']['uncertainty']}  [identity holds: "
            f"{s['murphy']['identity_holds']}]",
            "",
            "  id     p      base  outcome  log     brier  claim",
        ]
        for r in rows:
            if not r["resolved"]:
                out.append(f"  {r['id']:<6} {r['probability']:<6} {r['baseline']:<5} "
                           f"UNRESOLVED")
                continue
            out.append(f"  {r['id']:<6} {r['probability']:<6.2f} {r['baseline']:<5.2f} "
                       f"{'TRUE ' if r['outcome'] else 'FALSE'}   "
                       f"{r['log_score']:>+7.1f} {r['brier']:>6.2f}  {r['text'][:58]}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# In-band provenance — the manifest that cannot be detached                     #
# --------------------------------------------------------------------------- #


def _flow_key(pkt):
    """The 5-tuple of a rendered packet, or None if it has no addresses."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    sp = dp = 0
    for proto in (TCP, UDP):
        layer = pkt.getlayer(proto)
        if layer is not None:
            sp, dp = int(layer.sport), int(layer.dport)
            break
    return (ip.src, sp, ip.dst, dp)


_CLASS_INITIAL = {"observed": "O", "judgment": "J", "assumption": "A",
                  "fabricated": "F", "aleatoric": "-"}


def _flow_comment(cs: ClaimSet, flow, licensed: dict, field_mix: dict) -> str:
    """Terse on purpose.

    The section-header comment carries the subject, cutoff, verdict and source hashes once;
    repeating that on every packet cost a third of the file size for no added information.
    What must be per-packet is the bit that varies — which flow this is, which claim licenses
    it, and how that flow's own fields are classed — plus the word SYNTHETIC, so a packet
    lifted out on its own still says what it is.
    """
    fid = flow.flow_id
    claim = licensed.get(fid)
    if claim is not None:
        src = f"/{claim.source}" if claim.source else ""
        lic = f"claim={claim.id}{src} {claim.stance}"
    elif fid in set(cs.illustrative_flows):
        lic = "claim=none illustrative"
    else:
        lic = "claim=NONE-UNLICENSED"
    mix = field_mix.get(fid, {})
    mix_s = "/".join(f"{v}{_CLASS_INITIAL.get(k, '?')}" for k, v in mix.items() if v) or "unmarked"
    return f"SYNTHETIC | flow={fid} | {lic} | fields {mix_s}"


def _per_flow_field_mix(cs: ClaimSet, flows: list) -> dict:
    fm = cs.field_markings
    aleatoric = set(fm.aleatoric_fields) if fm else set()
    out: dict = {}
    for f in flows:
        counts: dict = {}
        for fact in flow_facts(f):
            if fact.split(".")[-1] in aleatoric or fact in aleatoric:
                key = "aleatoric"
            else:
                mk = resolve_marking(fm, f.flow_id, fact)
                key = mk.icd203 if mk else "fabricated"
            counts[key] = counts.get(key, 0) + 1
        out[f.flow_id] = counts
    return out


def write_provenance_pcapng(cs: ClaimSet, fs, rep: WarrantReport, out_path,
                            salt: str = "") -> int:
    """Render the storyline to pcapng with the warrant travelling inside it.

    Zeek reads pcapng through libpcap and ignores block options, so this is byte-for-byte
    the same capture to every analysis tool — it just also answers "says who?" when opened
    with no manifest beside it.
    """
    from packetforge.compile.pcapng import write_pcapng
    from packetforge.compile.timeline import compile_flowset

    res = compile_flowset(fs, salt=salt)
    idx: dict = {}
    for f in fs.flows:
        idx[(f.src_ip, f.src_port, f.dst_ip, f.dst_port)] = f
        idx[(f.dst_ip, f.dst_port, f.src_ip, f.src_port)] = f

    licensed = {}
    for c in cs.claims:
        for fid in c.renders:
            licensed.setdefault(fid, c)
    field_mix = _per_flow_field_mix(cs, fs.flows)

    comments = []
    for pkt in res.packets:
        flow = idx.get(_flow_key(pkt))
        comments.append(_flow_comment(cs, flow, licensed, field_mix) if flow
                        else "PacketForge SYNTHETIC | flow could not be resolved")

    census = rep.census
    srcs = " ".join(f"{s.id}={(s.sha256 or 'nohash')[:12]}" for s in cs.sources)
    header = (
        f"SYNTHETIC CAPTURE — NOT EVIDENCE OF ANYTHING. "
        f"A {cs.artifact_class} of: {cs.subject}. Information cutoff {cs.cutoff}. "
        f"Generated by PacketForge; no packet here was captured from any real network, and "
        f"every address and byte count is invented. "
        f"Correspondence gate: {'PASS' if rep.ok else 'FAIL'}. "
        f"{census.get('network_facts', 0)} network facts — "
        f"{census.get('field_class_mix', {}).get('observed', 0)} appear in a cited source, "
        f"the rest are inferred, authored, or aleatoric. "
        f"Sources (sha256 of retrieved prose): {srcs}. "
        f"Each packet comment names the claim licensing its flow. Full manifest: CLAIMS.md."
    )
    return write_pcapng(res.packets, out_path, link_type=fs.capture.link_type,
                        comments=comments, file_comment=header)


def write_manifest(cs: ClaimSet, rep: WarrantReport, md_path, json_path=None,
                   score_result=None) -> None:
    import json
    Path(md_path).write_text(render_manifest(cs, rep, score_result) + "\n", encoding="utf-8")
    if json_path:
        Path(json_path).write_text(
            json.dumps(manifest_json(cs, rep, score_result), indent=2) + "\n", encoding="utf-8")
