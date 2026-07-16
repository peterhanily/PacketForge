# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Shared renderer types and helpers."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

HTTP_REASONS = {
    200: "OK",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    502: "Bad Gateway",
}


@dataclass
class RenderResult:
    """Packets plus the values a correct parser should read back from them."""

    packets: list = field(default_factory=list)
    # e.g. {"conn": {...}, "http": {...}} — checked against real Zeek by the validator.
    expected: dict = field(default_factory=dict)


def filler_bytes(n: int, rng: random.Random) -> bytes:
    """Deterministic opaque payload of exactly ``n`` bytes."""
    if n <= 0:
        return b""
    return rng.randbytes(n)


_TEXT_ALPHABET = "abcdefghijklmnopqrstuvwxyz      "  # letters + spaces, no CR/LF/NUL/dot


def text_filler(n: int, rng: random.Random) -> bytes:
    """Deterministic printable-ASCII payload of exactly ``n`` bytes.

    Used for text protocol bodies (e.g. SMTP DATA) where random binary would embed
    bare CRs or NULs and trip line-oriented analyzers.
    """
    if n <= 0:
        return b""
    return "".join(rng.choice(_TEXT_ALPHABET) for _ in range(n)).encode("ascii")
