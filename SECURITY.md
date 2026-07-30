# Security policy

PacketForge generates **synthetic** network captures for detection testing and threat-hunting
practice. It ships no service, listens on no port, and processes no untrusted input in
production. The security surface is therefore unusual, and this file says what we care about.

## Report privately

**security@peterhanily.com** — please do not open a public issue for the first two categories
below.

## What we want to hear about

1. **A shipped capture is not inert.** Every sample is built to be structurally realistic and
   functionally harmless: DCE-RPC and SMB argument stubs are zero filler, NTLM responses are
   fixed bytes rather than crackable hashes, "malware" fingerprints reproduce a published JA3
   and nothing else, and file bodies are typed containers with filler content. If you can show
   that any shipped artifact does something — executes, authenticates, decrypts, or carries a
   usable secret — that is a bug and we want it before anyone else does. See
   [`docs/inert-by-construction.md`](docs/inert-by-construction.md).

2. **An indicator points at something real.** Synthetic captures must never label a real host as
   attacker infrastructure. Addresses should be RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`) or RFC 3849 (`2001:db8::/32`); domains should be RFC 2606 reserved
   (`.example`, `.invalid`, `.test`) or RFC 1918 internal. If you find an allocated address or a
   registrable domain in an attacker role, report it — we have shipped this bug before and fixed
   it, and we would rather hear about the next one quickly.

3. **You are a party to a reconstructed incident.** Samples 18 and 19 reconstruct a real, publicly
   disclosed event from its participants' own published accounts. Every packet in them is
   fabricated. If you represent an organisation named in one and believe it is inaccurate, unfair,
   or should not exist, write to the address above and we will correct or withdraw it.

## What this project is not

It is not a source of threat intelligence. No address, domain, hash or timestamp in this
repository identifies anything real, and none should be entered into a blocklist, a detection
rule, or an intelligence platform. Every sample ships a manifest that says so.

## Scope

Reports about the Python package's own dependency chain are welcome via a normal issue.
