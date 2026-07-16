# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Data-driven host/network fingerprints (per-OS TCP, TLS/JA3 client profiles)."""

from packetforge.fingerprints.loader import mac_for_ip, resolve_endpoint

__all__ = ["mac_for_ip", "resolve_endpoint"]
