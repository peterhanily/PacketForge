# Feasibility Evidence

A proof-of-concept was built and validated with real tooling before any architecture
was committed. This documents the measured result. The generator is
[`../poc/pcap_poc.py`](../poc/pcap_poc.py); the output is `../poc/beacon.pcap`.

## What was done

One hand-authored canonical event — the exact field shape EvidenceForge puts on
`NetworkContext` / `DnsContext` / `HttpContext` — describing an attacker C2 beacon
(a DNS A lookup for `cdn.telemetry-sync.example` followed by an HTTP `GET` to the
resolved IP) was rendered to a real libpcap file with scapy. The renderer received
**only** the L7 facts and the 5-tuple; it was **not** given the Zeek summary fields.
Those were then reconstructed from the packets and compared to what EvidenceForge's
emitter would write.

## Result: real Zeek 8.2.1 independently reproduced every field

`zeek -r beacon.pcap` produced `conn.log`, `dns.log`, `http.log`, `files.log` with
**no `weird.log`, no `reporter.log`, and nothing on stderr** — a fully coherent TCP
stream to Zeek's reassembler.

| Field | EvidenceForge event | Zeek read of the PCAP | Match |
|---|---|---|---|
| `history` | `ShADadFf` | `ShADadFf` | ✅ |
| `conn_state` | `SF` | `SF` | ✅ |
| `orig_bytes` / `resp_bytes` | 167 / 269 | 167 / 269 | ✅ |
| `orig_pkts` / `resp_pkts` | 6 / 4 | 6 / 4 | ✅ |
| `orig_ip_bytes` / `resp_ip_bytes` | 407 / 429 | 407 / 429 | ✅ |
| dns answer == conn dst_ip | 203.0.113.66 | 203.0.113.66 | ✅ |
| http method/host/uri/status | GET / cdn.telemetry-sync… / /api/v2/health / 200 | identical | ✅ |
| carved body MIME | application/octet-stream (gzip magic) | `application/x-gzip` | ✅ |

`tshark -z expert`: **zero** errors, warnings, or malformed packets (only routine
"connection closing" notes).

**Determinism:** two runs produced byte-identical output (same MD5), because every
volatile field (ISN, IP-ID, ephemeral port, packet timing) is seeded from the
connection identity.

## The one instructive discrepancy

Zeek reported `duration = 0.3297`; the event "claimed" `0.3521`. Zeek computes
connection duration its own way. **Lesson baked into the architecture:** volumetric
and timing summaries (`duration`, `*_bytes`, `*_pkts`, `missed_bytes`) must be
*derived from the rendered PCAP*, not authored top-down — the log emitter should agree
with the packets, not the other way around.

## Environment

Python 3.9 + scapy 2.7.0 (generation); Zeek 8.2.1, tshark, tcpdump (validation);
macOS. Nothing here depends on that specific environment.

## Reproduce

```bash
python3 poc/pcap_poc.py                     # writes poc/beacon.pcap, prints the checks
zeek -r poc/beacon.pcap                      # -> conn.log dns.log http.log, no weird.log
tshark -r poc/beacon.pcap -q -z expert       # -> zero errors/warnings
```
