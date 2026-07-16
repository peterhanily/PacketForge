# Detection lab

PacketForge generates the attack, the benign background, and the ground truth — so it
can score detections the honest way: *does this rule catch the attack, and stay quiet on
the noise?* Three surfaces, all against real engines.

## 1. Suricata rules — coverage + false-positive benchmark

`example.rules` is a small, TTP-tuned demo ruleset. Point the tools at **your own**
rules to test them.

```bash
# ATT&CK coverage matrix: techniques caught vs missed, per attack, + false positives
packetforge coverage --env office --rules detection/example.rules --md coverage.md

# false-positive rate of a ruleset over an hour of benign traffic
packetforge fp-benchmark --env office --rules /path/to/your.rules --duration 3600

# score one capture against its ground truth
packetforge detect capture.pcap --rules detection/example.rules
```

### Benchmarking against ET Open (a real, large ruleset)

ET Open (~51k rules) is **not vendored** here (size + its own license). Fetch it:

```bash
mkdir -p detection/etopen
curl -o detection/etopen/et.tar.gz \
  https://rules.emergingthreats.net/open/suricata-8.0.3/emerging.rules.tar.gz
tar xzf detection/etopen/et.tar.gz -C detection/etopen
cat detection/etopen/rules/*.rules > detection/etopen/all.rules

packetforge fp-benchmark --env office --rules detection/etopen/all.rules --duration 3600
```

**What to expect (Pyramid of Pain, measured):** ET Open produces ~0 false positives on
the synthetic benign baseline — a clean floor for FP-testing your own rules. But it also
*catches ~none of the synthetic attacks*: ET Open is IOC-dominated, and PacketForge's
attacks use fictional indicators (`evil.example`, RFC-5737 IPs). Synthetic captures
exercise **behavioral / TTP** detection and Sigma-over-Zeek — not IOC feeds. That is the
point, not a bug.

## 2. Sigma over Zeek logs — behavioral rules on the log layer

`sigma/` holds behavioral Sigma rules evaluated against the Zeek logs a capture produces
(a deliberately small Sigma subset: selections, `and`/`or`/`not`, and
`| count() by <field> > N` aggregations).

```bash
packetforge sigma capture.pcap --rules-dir detection/sigma
```

The Kerberoasting rule (RC4 TGS burst) fires on the attack and stays silent on benign
AES AD auth — no IOC, top of the pyramid.

## 3. Detection-CI corpus — regression testing with a known key

A versioned, labeled, content-addressable capture set. Point your ruleset at it on every
change and get a regression answer.

```bash
packetforge corpus-build --out corpus/
packetforge corpus-verify --corpus corpus/ --rules your.rules --save today.json
# later, after a rule change — non-zero exit if a technique regressed or a new FP appeared
packetforge corpus-verify --corpus corpus/ --rules your.rules --baseline today.json
```
