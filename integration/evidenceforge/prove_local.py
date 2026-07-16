# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Local proof: run FlowSpecEmitter against EvidenceForge's REAL model classes.

Runs in EvidenceForge's own venv (it imports EF's SecurityEvent + contexts), builds a
few canonical events as EF would generate, maps them with the proposed emitter, and
writes a PacketForge FlowSet (flows.json). Nothing is pushed; this only demonstrates
that the emitter fits EF's data model and that the canonical path carries exact bytes.
"""

import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # for flowspec_emitter
from flowspec_emitter import event_to_flow  # noqa: E402

from evidenceforge.events.base import SecurityEvent  # noqa: E402
from evidenceforge.events.contexts import (  # noqa: E402
    DnsContext, HttpContext, NetworkContext, SslContext,
)

ts = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


def ev(net, **ctx):
    return SecurityEvent(timestamp=ts, event_type="connection", network=net, **ctx)


events = [
    ev(NetworkContext(src_ip="10.10.0.30", src_port=51000, dst_ip="10.10.0.10", dst_port=53,
                      protocol="udp", service="dns", orig_bytes=40, resp_bytes=90, conn_state="SF"),
       dns=DnsContext(query="evil.example", query_type="A", answers=["203.0.113.9"], rcode="NOERROR")),
    ev(NetworkContext(src_ip="10.10.0.30", src_port=51001, dst_ip="203.0.113.9", dst_port=80,
                      protocol="tcp", service="http", orig_bytes=180, resp_bytes=520, conn_state="SF"),
       http=HttpContext(method="GET", host="evil.example", uri="/beacon", status_code=200,
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", response_body_len=300)),
    ev(NetworkContext(src_ip="10.10.0.30", src_port=51002, dst_ip="203.0.113.9", dst_port=443,
                      protocol="tcp", service="ssl", orig_bytes=700, resp_bytes=4000, conn_state="SF"),
       ssl=SslContext(version="TLSv12", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                      server_name="secure.evil.example")),
    # a generic app service (no Zeek analyzer) — the canonical event carries EXACT
    # bytes the log-reconstruction path cannot recover for such flows
    ev(NetworkContext(src_ip="10.10.0.30", src_port=51003, dst_ip="10.10.0.20", dst_port=9300,
                      protocol="tcp", service="", orig_bytes=1234, resp_bytes=5678, conn_state="SF")),
]

flows = [f for f in (event_to_flow(e) for e in events) if f]
out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("flows.json")
out.write_text(json.dumps({"schema_version": "0.1", "flows": flows}, indent=2) + "\n")
opaque = flows[-1]["l7"]
print(f"mapped {len(flows)} canonical events -> FlowSet at {out}")
print(f"opaque SMB exact bytes carried: orig={opaque['orig_bytes']} resp={opaque['resp_bytes']}")
