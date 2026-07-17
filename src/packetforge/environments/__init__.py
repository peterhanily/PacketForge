# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Network environments — the 'kind of tap' a capture comes from.

An environment describes a network's shape: its address plan, MAC vendor, default
host OSes, the ambient service mix a sensor there would see, the capture link type
(SPAN/TAP Ethernet vs a host tcpdump's Linux SLL), and NAT/vantage. The scenario
composer uses it to generate realistic benign background traffic for that network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

_PROFILE_DIR = Path(__file__).parent / "profiles"


class AmbientService(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str  # a renderer kind or a service name the composer maps to a port
    weight: int = 1


class Sensor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vantage: Literal["span", "tap", "host"] = "span"
    nat: Literal["none", "source"] = "none"


class Environment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    link_type: Literal["ethernet", "linux_sll"] = "ethernet"
    subnet: str  # CIDR for internal hosts, e.g. "10.10.0.0/16"
    gateway: str
    dns_server: str
    mac_oui: str  # 3-octet vendor prefix, e.g. "00:50:56"
    default_client_os: str = "windows_10"
    default_server_os: str = "linux"
    # Weighted OS population for internal client hosts (os -> weight). Each host is
    # assigned one OS deterministically, so a real multi-modal fingerprint distribution
    # (window/TTL/SYN-options) appears on the wire instead of a single value. Empty ->
    # every client uses default_client_os.
    client_os_mix: dict[str, int] = Field(default_factory=dict)
    ambient: list[AmbientService] = Field(default_factory=list)
    sensor: Sensor = Field(default_factory=Sensor)


def list_environments() -> list:
    return sorted(p.stem for p in _PROFILE_DIR.glob("*.yaml"))


def load_environment(name: str) -> Environment:
    path = _PROFILE_DIR / f"{name}.yaml"
    if not path.exists():
        raise ValueError(f"unknown environment {name!r}; available: {list_environments()}")
    return Environment.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
