# Inert C2 beacon (JA3 fingerprint)

An **inert, synthetic** capture shaped like documented command-and-control: benign office
noise plus a run of HTTPS beacons to one C2, at a fixed cadence, all carrying the **same
distinct JA3** fingerprint. Fake traffic, true labels — no real malware.

**What to look for**
- `zeek/ssl.log` — the beacon SNI `static.cdn-telemetry.example` recurring at a regular
  interval, with a stable JA3. The **fingerprint + cadence** is the top-of-pyramid signal,
  not any single IOC.
- This is the reference used by `packetforge malware-transfer`: profile the JA3 off this
  capture, rebuild an analog, and a `ja3.hash` rule reaches the same verdict on both.

**Reproduce**
```
scripts/make-samples.sh    # builds this malware-transfer reference: office noise + JA3 beacons
```
