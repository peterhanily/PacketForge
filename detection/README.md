# Detection lab

How to grade a ruleset by hand against generated traffic. PacketForge produces the attack, the
benign background and the ground truth, so a rule can be scored on both halves of the job: does it
catch the technique, and does it stay quiet on normal traffic.

`example.rules` is a small demo ruleset of 11 Suricata rules, used below so the output is
reproducible. Point every command at your own rules instead.

## What these captures test, and what they do not

The Pyramid of Pain ranks indicators by how much it costs an adversary to change them, with file
hashes and IP addresses cheap at the bottom and behaviour expensive at the top. PacketForge sits at
the top by construction, because its indicators are fictional: domains under `example`, addresses
from RFC 5737 and RFC 3849. That shows up in the numbers.

Run ET Open (51,506 enabled rules, fetched as described below) over the 26 attacks in the `office`
environment and it catches 7 of 31 techniques. The 11 hand-written TTP rules in `example.rules`
catch 11 of 31. The seven ET Open hits come from protocol-behaviour rules on SMB admin shares,
WinRM, LLMNR and DoH, not from indicator matches, because there is no indicator here to match.

On the benign side, ET Open fires 225 times over a one-hour benign capture. All 225 come from seven
informational signatures in the `ET INFO`, `ET DYN_DNS` and `ET DNS` categories, which react to
dynamic-DNS and external-IP-lookup domains in the ambient noise. No malware, exploit or trojan rule
fires. Suppress those seven and the floor is zero.

So these captures are useful for two things: developing behavioral and TTP detections, and
measuring a false-positive floor. They are useless for testing an IOC feed. A near-zero score here
says nothing about a feed's quality.

## 1. Suricata rules: coverage and false-positive benchmark

```bash
# ATT&CK coverage matrix: techniques caught vs missed, per attack, plus false positives
packetforge coverage --env office --rules detection/example.rules --md coverage.md

# false-positive rate of a ruleset over an hour of benign traffic
packetforge fp-benchmark --env office --rules /path/to/your.rules --duration 3600

# score one capture against its ground truth
packetforge detect capture.pcap --rules detection/example.rules
```

`coverage` runs the whole attack library by default, which takes a few minutes. Narrow it with
`--attacks` while you iterate:

```console
$ packetforge coverage --env office --rules detection/example.rules \
    --attacks kerberoasting,dns-exfil,port-scan,psexec-lateral,dcsync
ATT&CK coverage — ruleset=detection/example.rules  env=office
  techniques caught: 3/5   false positives (benign): 0

  ATTACK                 CAUGHT MISSED  TECHNIQUES
  kerberoasting               1      0  caught[T1558.003] missed[-]
  dns-exfil                   1      0  caught[T1048.003] missed[-]
  port-scan                   1      0  caught[T1046] missed[-]
  psexec-lateral              0      1  caught[-] missed[T1021.002]
  dcsync                      0      1  caught[-] missed[T1003.006]
```

The full run over all 26 attacks scores 11 of 31 techniques for this ruleset. The 20 misses
concentrate in the SMB and DCE-RPC attacks, which this content-based set has no rule for.

One of those misses is a scoring artifact. The scorer matches alerts to ground truth by comparing
address strings, and on `ipv6-c2` Suricata prints `2001:0db8:0001:0000:0000:0000:0000:0040` where
the ground truth records `2001:db8:1::40`. The C2 SNI rule fires, and the six alerts are counted as
false positives rather than as a catch. Read IPv6 results from the alert list, not the score.

`fp-benchmark` composes an hour of benign traffic in the chosen environment and counts every alert,
since by construction there is nothing to catch:

```console
$ packetforge fp-benchmark --env office --rules detection/example.rules --duration 3600
FP benchmark — ruleset=detection/example.rules  env=office
  benign capture: 4320 flows over 60 min
  false positives: 14  ->  14.0 alerts/hour at this base rate
      14 PF port scan (SYN burst across ports)
```

All 14 come from one threshold rule, sid 9000020, which alerts when a source sends 15 SYN packets in
6 seconds. Busy benign hosts cross that line. A threshold rule trades false positives for coverage
of scan-shaped attacks, and this benchmark prices the trade before production does.

### Benchmarking against ET Open

ET Open is not vendored here, on size and licensing grounds. Fetch it:

```bash
mkdir -p detection/etopen
curl -o detection/etopen/et.tar.gz \
  https://rules.emergingthreats.net/open/suricata-8.0.3/emerging.rules.tar.gz
tar xzf detection/etopen/et.tar.gz -C detection/etopen
cat detection/etopen/rules/*.rules > detection/etopen/all.rules

packetforge fp-benchmark --env office --rules detection/etopen/all.rules --duration 3600
```

That URL pins Suricata 8.0.3. Emerging Threats publishes one tree per Suricata version, so change
the path to match your own build (`suricata --build-info | head -1`) when 8.0.3 falls out of date.

## 2. Sigma over Zeek logs

`sigma/` holds behavioral Sigma rules evaluated against the Zeek logs a capture produces. Sigma is
a vendor-neutral rule format for log data. The evaluator here supports a small subset:
selections, `and`, `or`, `not`, and `| count() by <field> > N` aggregations.

```console
$ packetforge sigma capture.pcap --rules-dir detection/sigma
Sigma over Zeek: 1/3 rules fired  (capture.pcap)
  silent AS-REP Roasting - RC4 AS Responses [T1558.004]
  silent DNS Tunneling - Subdomain Query Burst [T1048.003]
  FIRED  Kerberoasting - RC4 Service Ticket Burst [T1558.003]  10.10.0.40:8
```

That is the kerberoasting capture. The rule fires when one source requests more than five RC4
service tickets, and here 10.10.0.40 requests eight. It stays silent on the AES Kerberos traffic in
the benign ambient. No indicator is involved.

## 3. Regression corpus

A versioned, labeled capture set with a manifest. Each capture carries its sha256, so
`corpus-verify` refuses to score a corpus that has been altered.

```bash
packetforge corpus-build --out corpus/
packetforge corpus-verify --corpus corpus/ --rules your.rules --save today.json
# after a rule change: non-zero exit if a technique regressed or a new false positive appeared
packetforge corpus-verify --corpus corpus/ --rules your.rules --baseline today.json
```

`corpus-build` writes 26 captures in about 30 seconds. `corpus-verify` prints a per-capture score:

```
corpus v1.0 vs detection/example.rules: 12/31 techniques caught, 6 false positives
  office-account-discovery         caught 0/1  fp=0
  office-admin-share-transfer      caught 0/1  fp=0
  office-asrep-roasting            caught 1/1  fp=0
  office-brute-force               caught 1/1  fp=0
  office-cloud-exfil               caught 0/1  fp=0
  ...
```

All six false positives land on `office-ipv6-c2`. They are the IPv6 address-string artifact
described above, not a rule misfiring on benign traffic.

The corpus scores 12 of 31 where the coverage matrix scores 11, because the two use different seeds
and flow counts. Compare a ruleset against a baseline of itself, not across the two tools.

## Inside your own CI

These commands grade a ruleset interactively. For the same idea as a pytest fixture that renders
its own capture and gates a merge, see [`../docs/detection-ci.md`](../docs/detection-ci.md).
