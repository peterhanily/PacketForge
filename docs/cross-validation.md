# Cross-validation & transfer proof

The realism claim shouldn't be self-referential. These commands run a capture through
*independent, real* tools and profile real captures against synthetic analogs.

## Independent validators

Built-in (already required): **Zeek**, **Suricata**, **tshark**. Optional extras make the
panel wider — install them and `crossval` picks them up automatically:

```bash
brew install p0f          # passive OS/TCP fingerprinting (lands in $(brew --prefix)/sbin)
pip install pyja3         # independent JA3 computation
# ensure p0f is reachable:  export PATH="$(brew --prefix)/sbin:$PATH"
```

Arkime and RITA are **not wired in** — both need a datastore (Elasticsearch / MongoDB)
that this project deliberately avoids. RITA-style beaconing analysis runs over the Zeek
logs `crossval` already produces, if you have RITA set up.

## Commands

```bash
# what do independent tools each see? do they agree?
packetforge crossval capture.pcap --flowspec source.yaml   # --flowspec adds JA3 agreement

# profile a REAL capture, synthesize an analog, confirm both parse the same
packetforge transfer-proof real.pcap --env office
```

`crossval` reports, per tool, what it independently parsed (Zeek services, Suricata
app-protocols, tshark protocol layers, p0f OS families, pyja3 JA3 digests) and whether
the JA3 PacketForge *declared* matches what pyja3 read off the wire — byte-for-byte.

`transfer-proof` extracts the real capture's protocol profile, builds an analog with the
same service mix, cross-validates both, and reports the share of the real capture's
protocols the analog reproduced and independent tools confirmed.

> Real captures often carry NIC-offloaded (invalid) checksums; `crossval` runs Zeek with
> `-C` and Suricata with `-k none` so those packets are analyzed rather than discarded.
