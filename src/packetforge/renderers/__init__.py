# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Per-protocol renderers: L7 spec + resolved endpoints -> packets + expectations.

Each renderer declares, in its ``RenderResult.expected``, exactly what a correct
parser should read back. The validator diffs that against real Zeek. The renderer's
expectations come from the bytes it actually emits, so agreement proves the packets
are both valid and correctly interpreted.
"""

from packetforge.renderers.base import RenderResult
from packetforge.renderers.dhcp import render_dhcp
from packetforge.renderers.dns import render_dns
from packetforge.renderers.ftp import render_ftp
from packetforge.renderers.http import render_http
from packetforge.renderers.icmp import render_icmp
from packetforge.renderers.kerberos import render_kerberos
from packetforge.renderers.ldap import render_ldap
from packetforge.renderers.line_apps import render_imap, render_irc, render_pop3
from packetforge.renderers.modbus import render_modbus
from packetforge.renderers.ntp import render_ntp
from packetforge.renderers.opaque_tcp import render_opaque_tcp
from packetforge.renderers.opaque_udp import render_opaque_udp
from packetforge.renderers.radius import render_radius
from packetforge.renderers.sip import render_sip
from packetforge.renderers.smb import render_smb
from packetforge.renderers.smtp import render_smtp
from packetforge.renderers.snmp import render_snmp
from packetforge.renderers.ssh import render_ssh
from packetforge.renderers.tls import render_tls

# Dispatch table keyed by L7 ``kind``.
RENDERERS = {
    "dns": render_dns,
    "http": render_http,
    "icmp": render_icmp,
    "opaque_tcp": render_opaque_tcp,
    "opaque_udp": render_opaque_udp,
    "smtp": render_smtp,
    "tls": render_tls,
    "dhcp": render_dhcp,
    "ntp": render_ntp,
    "ssh": render_ssh,
    "ftp": render_ftp,
    "snmp": render_snmp,
    "modbus": render_modbus,
    "radius": render_radius,
    "ldap": render_ldap,
    "smb": render_smb,
    "kerberos": render_kerberos,
    "pop3": render_pop3,
    "imap": render_imap,
    "irc": render_irc,
    "sip": render_sip,
}

__all__ = ["RENDERERS", "RenderResult"]
