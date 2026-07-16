# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Make the src/ layout importable without an editable install (works on 3.9)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE_FLOWS = REPO_ROOT / "flows" / "c2_beacon.yaml"
