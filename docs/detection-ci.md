# Detection-CI

How to use PacketForge as a fixture source inside your own pipeline. A rule test renders its own
capture, so the test is deterministic and can gate a merge.

Detection-as-Code puts rules in version control and gates them in CI, which needs test data that
regenerates byte-for-byte. A fixture is that data: a capture, the Zeek logs those exact bytes
produce, and a ground-truth answer key.

## In your pytest suite

```python
from packetforge.detection_ci import packetforge_fixture

MY_RULES = "detection/example.rules"

def test_kerberoasting_fires_and_is_quiet_on_benign():
    fx = packetforge_fixture("kerberoasting", env="office", seed=7)
    assert fx.fires(MY_RULES)
    assert fx.quiet_on_benign(MY_RULES)
```

One call renders two captures from the same seed: the attack, and a benign twin composed from the
same environment with the attack left out. The two assertions are the two a detection has to pass,
because a rule that catches the technique but also fires on ordinary traffic is not shippable.

That test passes in about 3 seconds against the 11 rules in `detection/example.rules`. Run
`packetforge list-attacks` for the 26 fixture names and `packetforge list-envs` for the 9
environments.

The alert calls need `suricata` on PATH. If `zeek` and `tshark` are also present, the fixture
directory holds the Zeek logs those bytes produce, so log-based detections (Sigma, Splunk, Elastic)
can grade against `conn.log`, `dns.log`, `kerberos.log` and the rest.

## What a failure looks like

A bare `assert fx.fires(MY_RULES)` reports `assert False` and tells you nothing about why. Take the
alert histogram first, and pass `out_dir` so the capture outlives the test run.

```python
def test_dcsync_rule_fires():
    fx = packetforge_fixture("dcsync", env="office", seed=7, out_dir="/tmp/pf-dcsync")
    alerts = fx.suricata_alerts(MY_RULES)
    assert alerts, f"no signature fired on {fx.pcap}"
```

```
>       assert alerts, f"no signature fired on {fx.pcap}"
E       AssertionError: no signature fired on /tmp/pf-dcsync/dcsync/capture.pcap
E       assert {}
```

Open that capture in Wireshark, or read the `GROUND_TRUTH.json` written beside it for the flows and
ATT&CK techniques the rule was meant to hit. The same directory holds `dce_rpc.log`, which is where
a DCSync detection would look.

## What a fixture exposes

| Member | What it is |
|---|---|
| `pcap` | Path to the attack capture. |
| `ground_truth` | Path to `GROUND_TRUTH.json`, the answer key. |
| `zeek_dir` | Path to the bundle directory: Zeek logs, `manifest.json`, ground truth. |
| `expected_sids` | Frozen signature-id counts, populated when `rules=` was passed. |
| `suricata_alerts(rules)` | Signature id to count, on the attack capture. |
| `benign_alerts(rules)` | Signature id to count, on the benign twin. |
| `fires(rules, sid=None)` | True if anything fired, or if that one signature fired. |
| `quiet_on_benign(rules, sid=None)` | True if nothing fired on the benign twin. |

Pass a `sid` when you are testing one specific rule. Without it, `fires` accepts any alert at all,
which will mask a rule that stopped working while an unrelated one still fires.

## Pinning determinism

The same version and the same arguments produce the same bytes. `manifest.json` in the fixture
directory records the hash alongside the round-trip result for that capture. An excerpt:

```json
{
  "pcap": "capture.pcap",
  "sha256": "8b30a4a9ca60e5a8a62700e3a2cd902567f699ad95c62d4f178d617c8507bb1c",
  "flows": 131,
  "consistency": {
    "ok": true,
    "matched_flows": 131,
    "total_flows": 131,
    "zeek_weird": 0,
    "zeek_reporter": 0,
    "tshark_errors": 0,
    "tshark_warnings": 0,
    "mismatches": []
  }
}
```

That guarantee stops at the version boundary. A renderer change moves the bytes on purpose, so an
unpinned dependency bump can quietly change what your rules are being tested against. Two steps
close the gap.

Pin the install to a commit rather than a branch:

```bash
pip install "git+https://github.com/peterhanily/PacketForge@<commit-sha>"
```

Then assert the hash, so a changed fixture fails loudly instead of passing quietly:

```python
import json

def test_fixture_bytes_are_pinned():
    fx = packetforge_fixture("kerberoasting", env="office", seed=7)
    manifest = json.loads((fx.zeek_dir / "manifest.json").read_text())
    assert manifest["sha256"] == "8b30a4a9ca60e5a8a62700e3a2cd902567f699ad95c62d4f178d617c8507bb1c"
```

When that test fails, re-run the rule tests against the new capture, confirm they still pass, then
update the hash in the same commit as the version bump.

## Export to suricata-verify

To drop a capture into a Suricata rule-regression suite in the
[suricata-verify](https://github.com/OISF/suricata-verify) format:

```bash
packetforge suricata-verify --attack kerberoasting --rules detection/example.rules \
  --seed 7 -o tests/kerberoasting/
```

The same thing from Python, when you already hold a fixture:

```python
from packetforge.detection_ci import packetforge_fixture, write_suricata_verify

fx = packetforge_fixture("kerberoasting", env="office", seed=7, rules=MY_RULES)
write_suricata_verify(fx, "tests/kerberoasting/", MY_RULES)
```

Both write `test.pcap` and a `test.yaml` whose checks are the signature counts the rules produce
now. For the example ruleset that is 10 alerts across 2 signatures:

```yaml
checks:
- filter:
    count: 8
    match:
      alert.signature_id: 9000010
- filter:
    count: 2
    match:
      alert.signature_id: 9000011
```

The test then fails if a later rule edit silences a detection that used to work.

## In GitHub Actions

```yaml
name: detections
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - name: Install tshark, Suricata and Zeek
        run: |
          sudo apt-get update
          sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark suricata
          echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
            | sudo tee /etc/apt/sources.list.d/zeek.list
          curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
            | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg >/dev/null
          sudo apt-get update && sudo apt-get install -y zeek
          echo /opt/zeek/bin >> "$GITHUB_PATH"
      - run: pip install "git+https://github.com/peterhanily/PacketForge" pytest
      - run: pytest tests/detections/
```

PacketForge is not published on PyPI, so `pip install packetforge` will not work. Install from the
repository, and pin the commit as described above once the suite is real. Zeek, tshark and Suricata
are external programs, not Python dependencies, which is why they come from apt.

Python 3.9 is the declared floor and the project's own CI runs 3.9 and 3.11.

## Grading a ruleset by hand

Fixtures answer a yes-or-no question about one rule. To measure a whole ruleset, its ATT&CK
coverage and its false-positive rate over an hour of benign traffic, see
[`../detection/README.md`](../detection/README.md).
