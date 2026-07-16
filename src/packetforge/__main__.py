# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Enable `python -m packetforge`."""

import sys

from packetforge.cli import main

if __name__ == "__main__":
    sys.exit(main())
