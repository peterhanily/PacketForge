# Roadmap

What PacketForge does today, what is planned next, and what it will not do. The capability
detail is in [capabilities.md](capabilities.md), and the measured state of each gate is in
[validation.md](validation.md).

## Shipped

- A deterministic compiler from a canonical Flow IR to a `.pcap`. The same input produces byte-identical output, with no LLM calls and no unseeded randomness in the generation path.
- 23 protocols have a protocol-specific renderer, counting the name-query module as its three wire protocols (LLMNR, NBT-NS and mDNS), plus opaque TCP and UDP shells for binary protocols that have no renderer. Real Zeek writes 21 distinct log types across the shipped samples.
- 26 attacks, 9 environments, 5 evasion modifiers and 6 inert malware-shaped families, enumerated by the `list-attacks`, `list-envs`, `list-evasions` and `list-families` subcommands.
- Four gates: the real-Zeek and `tshark -z expert` round trip, a cross-validated gradient-boosted C2ST against a real-vs-real floor, detection behaviour under Suricata and Sigma, and correspondence between a reconstruction and the sources it was built from. See [concepts.md](concepts.md), [validation.md](validation.md) and [correspondence.md](correspondence.md).
- Capture-shape transforms: multi-vantage projection through an edge TAP, a core SPAN and a host tcpdump, VXLAN mirroring for cloud and container overlays, and IPv4 fragmentation.
- A detection-CI surface: deterministic fixtures with benign twins, suricata-verify export, and self-contained bundles. See [detection-ci.md](detection-ci.md).
- 19 sample folders holding 26 capture files, each shipped with the Zeek logs it produces and an answer key. See [the gallery](../samples/).
- An EvidenceForge ingest round trip, which renders EvidenceForge's own logs back to packets and diffs real Zeek's output against the originals.

## Next

Ordered by how often the gap costs a user something, not by effort.

### QUIC and HTTP/3

There is no QUIC and no HTTP/3. A TLS flow can advertise `h2` in its ALPN, but the application data is
sized opaque filler, so there is no HTTP/2 framing either. A detection keyed on QUIC initial
packets or on HTTP/2 frame types has nothing to fire on. QUIC comes first, because a growing
share of real egress is UDP/443 and a capture without it looks dated at a glance.

### IPv6 beyond TCP

IPv6 support covers TCP only. Every UDP renderer and the ICMP renderer hardcode IPv4, so an
IPv6 scenario carries no DNS, no DHCP, no NTP and no ICMPv6. Closing this means threading an
address family through the UDP renderers and adding an ICMPv6 renderer with Neighbor
Discovery.

### A larger client fingerprint library

Two TLS client profiles ship: a generic browser and curl. JA3 (an MD5 over the ClientHello's
numeric fields) and JA4 (its successor, which also fingerprints the server side and non-TLS
protocols) are both computed from the bytes actually on the wire, so the limit is the library
rather than the machinery. Chrome, Firefox, Edge, Go and Python clients, each derived from a
real ClientHello, would make the fingerprint a discriminator instead of a constant.

### S7 and DNP3 renderers

The `ot` environment's ambient mix names `s7` and `dnp3`, but neither has a renderer, so both
fall through to opaque TCP with zero application bytes. An OT capture is thinner than the
environment profile implies. Modbus already has a renderer and is the pattern to copy.

### Overlapping-fragment insertion

`scenario --fragment` splits an oversized IPv4 packet at a byte boundary, and Zeek reassembles
it to the same flows. The evasion that separates one sensor from another is the overlapping
fragment, where two fragments disagree and the reassembly policy decides what each sensor
sees. That is a distinct transform, and it raises a distinct ground-truth question: the answer
key has to say which reading is the true one.

### Tunnelling

GRE, IPsec and WireGuard each carry traffic a sensor may or may not be able to see inside.
VXLAN encapsulation is already in the vantage engine, so the machinery for wrapping and
declaring an outer layer exists.

### A real cloud reference capture

The realism gate scores against real public captures, and none of them are cloud. The four
provider environments (`aws-vpc`, `azure-vnet`, `gcp-vpc`, `oci-vcn`) and the `k8s` overlay
are therefore unvalidated: their protocol conformance is checked, but nothing establishes that
their traffic mix resembles a real VPC. `scripts/cloud-capture/` takes a reference in a
throwaway account. Method and current status are in
[appendix/cloud-baselines.md](appendix/cloud-baselines.md).

### EvidenceForge integration

Not started, and blocked on the maintainer's approval. The design is a small additive
`FlowSpecEmitter` inside EvidenceForge that turns a canonical event into Flow IR, with
PacketForge wired in as an opt-in pcap artifact family gated by the Zeek round trip in CI.
That closes the one gap log reconstruction cannot close: exact payload volumetrics. A local seam
test already proves the consistency guarantee against duck-typed canonical events, so no
EvidenceForge dependency is needed to develop it. Nothing is pushed, proposed or commented
there without explicit approval.

## Out of scope

- **Full-take payload realism for binary protocols.** A protocol without a renderer is an opaque TCP or UDP shell carrying sized filler. The shell reproduces the flow's shape, never its content, and the manifest says which flows are shells.
- **Offensive capability.** An attack scenario reproduces the observable signal a detection keys on and never the technique. DCE-RPC stubs are opnum-only (the operation number without its arguments), transferred files are codeless, and credential material is fixed filler. See [inert-by-construction.md](inert-by-construction.md).
- **Non-determinism.** A generator that cannot reproduce its own output cannot serve as a test fixture, so nothing enters the generation path that is not seeded.
- **Any claim that a capture is real.** `packetforge crossval` establishes that independent tools parse a capture without complaint and agree on its fingerprints. That is not a verdict that the traffic is real. Every sample ships labelled synthetic, and nothing here belongs in a blocklist.
