# Example captures

Pre-built, deterministic captures — open the `.pcap` in Wireshark, read the
`GROUND_TRUTH.md` answer key, or open the `.html` forensic report. Regenerate with
`scripts/make-examples.sh`. Every capture scores 100/100 on `packetforge eval` and
is clean under real Zeek.

| Capture | Environment | Link type | Contents |
|---|---|---|---|
| `office-intrusion` | corporate AD LAN | Ethernet (SPAN) | ambient + a phishing→C2→LDAP/SMB→lateral→exfil intrusion (see its `GROUND_TRUTH.md`) |
| `home-baseline` | consumer home LAN | Ethernet | benign background only — no storyline |
| `cloud-intrusion` | cloud VPC | **Linux SLL** (host tcpdump) | same intrusion shape, seen from a host-side capture |
| `ot-plc-traffic` | OT/ICS segment | Ethernet (TAP) | Modbus/TCP polling + minimal IT services |

The `*-intrusion` captures ship a `*.GROUND_TRUTH.md` (kill chain, ATT&CK techniques,
IOCs) and a `*.GROUND_TRUTH.json`. Malicious flows are labelled `atk-*`; everything
else is benign noise a hunter has to separate out.
