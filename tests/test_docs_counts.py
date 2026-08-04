# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The documentation states counts. This test keeps them true.

Every number checked here is one a reader can verify with a single command, which is
exactly why a stale one is expensive: it gives a sceptical reader a reason to spot-check
everything else. The docs disagreed with the code (and with each other) about the number
of protocols, environments and samples before this test existed.

The check has two halves, because a pattern-matching test that finds nothing passes
vacuously:

  1. any count stated anywhere in the docs must be the right one, and
  2. docs/capabilities.md, which owns the counts, must state each one at least once.
"""

from __future__ import annotations

import re
import typing
from pathlib import Path

import pytest

from packetforge.environments import list_environments
from packetforge.models.flowspec import L7Spec
from packetforge.scenarios import list_attacks, list_evasions

ROOT = Path(__file__).resolve().parents[1]

# The namequery renderer carries three wire protocols (LLMNR, NBT-NS, mDNS), and the two
# opaque shells are not protocols. That is the whole counting rule, kept in one place.
_OPAQUE = {"opaque_tcp", "opaque_udp"}
_MULTI_PROTOCOL_KINDS = {"namequery": 3}


def _l7_kinds() -> set:
    union = typing.get_args(L7Spec)[0]
    return {typing.get_args(m.model_fields["kind"].annotation)[0]
            for m in typing.get_args(union)}


def _protocol_count() -> int:
    kinds = _l7_kinds() - _OPAQUE
    return sum(_MULTI_PROTOCOL_KINDS.get(k, 1) for k in kinds)


def _sample_dirs() -> list:
    return sorted(p for p in (ROOT / "samples").iterdir()
                  if p.is_dir() and re.match(r"^\d\d-", p.name))


# noun -> (expected value, regex whose first group is the stated number)
COUNTS = {
    "protocols": (_protocol_count(), r"\b(\d+) protocols\b"),
    "environments": (len(list_environments()), r"\b(\d+) environments\b"),
    "attacks": (len(list_attacks()), r"\b(\d+) attacks\b"),
    "evasions": (len(list_evasions()), r"\b(\d+) evasion(?: modifier)?s\b"),
    "samples": (len(_sample_dirs()), r"\b(\d+) (?:sample folders|scenarios|samples)\b"),
}

DOCS = ["README.md", "docs/capabilities.md", "docs/concepts.md", "docs/validation.md",
        "docs/DESIGN.md", "docs/ROADMAP.md", "samples/README.md", "docs/detection-ci.md",
        "detection/README.md", "docs/README.md"]


def _text(rel: str) -> str:
    path = ROOT / rel
    return path.read_text(encoding="utf-8") if path.exists() else ""


@pytest.mark.parametrize("noun", sorted(COUNTS))
def test_every_stated_count_is_current(noun):
    expected, pattern = COUNTS[noun]
    for rel in DOCS:
        for match in re.finditer(pattern, _text(rel)):
            assert int(match.group(1)) == expected, (
                f"{rel} says {match.group(0)!r}; the code says {expected}"
            )


@pytest.mark.parametrize("noun", sorted(COUNTS))
def test_the_reference_page_states_the_count(noun):
    """capabilities.md owns the counts, so a silent omission is a failure too."""
    _, pattern = COUNTS[noun]
    assert re.search(pattern, _text("docs/capabilities.md")), (
        f"docs/capabilities.md no longer states a {noun} count"
    )
