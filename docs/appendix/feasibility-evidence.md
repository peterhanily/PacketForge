# Feasibility evidence

The measured proof of concept that preceded the architecture, from 2026-07. It is a record of one
result, kept because the result is what justified building the rest. The generator is
[`../../poc/pcap_poc.py`](../../poc/pcap_poc.py) and its output is `../../poc/beacon.pcap`.

## What was done

One hand-authored canonical event was rendered to a real libpcap file with scapy. The event used
the exact field shape EvidenceForge puts on its network, DNS and HTTP contexts, and described a C2
beacon: a DNS A lookup for `cdn.telemetry-sync.example`, then an HTTP `GET` to the resolved
address.

The renderer received only the layer-7 facts and the 5-tuple. It was not given the Zeek summary
fields. Those were reconstructed from the packets afterwards and compared against what
EvidenceForge's emitter would have written.

## Result

`zeek -r beacon.pcap` produced `conn.log`, `dns.log`, `http.log` and `files.log`, with no
`weird.log`, no `reporter.log` and nothing on stderr: a fully coherent TCP stream to Zeek's
reassembler.

| Field | EvidenceForge event | Zeek's read of the capture |
|---|---|---|
| `history` | `ShADadFf` | `ShADadFf` |
| `conn_state` | `SF` | `SF` |
| `orig_bytes` / `resp_bytes` | 167 / 269 | 167 / 269 |
| `orig_pkts` / `resp_pkts` | 6 / 4 | 6 / 4 |
| `orig_ip_bytes` / `resp_ip_bytes` | 407 / 429 | 407 / 429 |
| DNS answer against conn `dst_ip` | 203.0.113.66 | 203.0.113.66 |
| HTTP method, host, uri, status | GET, `cdn.telemetry-sync.example`, `/api/v2/health`, 200 | identical |
| carved body MIME | `application/octet-stream` (gzip magic) | `application/x-gzip` |

`tshark -z expert` reported zero errors, warnings and malformed packets, with only routine
connection-closing notes. Two runs produced byte-identical output, because every volatile field
(initial sequence number, IP identifier, ephemeral port, packet timing) is seeded from the
connection identity.

## The instructive discrepancy

Zeek reported `duration = 0.3297` where the event claimed `0.3521`, because Zeek computes
connection duration its own way. That lesson is baked into the architecture: volumetric and timing
summaries (`duration`, `*_bytes`, `*_pkts`, `missed_bytes`) are derived from the rendered capture
rather than authored. The log emitter agrees with the packets, not the other way around.

## Environment

Python 3.9 and scapy 2.7.0 for generation; Zeek 8.2.1, tshark and tcpdump for validation; macOS.

## Reproduce

```bash
python3 poc/pcap_poc.py                  # writes poc/beacon.pcap and prints the checks
zeek -r poc/beacon.pcap                  # conn.log, dns.log, http.log, and no weird.log
tshark -r poc/beacon.pcap -q -z expert   # zero errors and warnings
```
