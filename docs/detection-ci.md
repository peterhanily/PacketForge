# Detection-CI — PacketForge as a fixture source for Detection-as-Code

Detection engineering runs on **Detection-as-Code**: rules live in version control, are
reviewed in PRs, and are gated in CI. The dependency that model can't cleanly satisfy is
*trustworthy, regenerable test data* — live emulation isn't byte-reproducible (tests flake),
and static datasets can't be regenerated. PacketForge is the missing piece: a **unit-test
fixture source** that renders a byte-identical capture, the exact Zeek logs it produces, and a
ground-truth answer key — so a rule test is deterministic and can gate a merge.

## In your pytest suite

```python
from packetforge.detection_ci import packetforge_fixture

MY_RULES = "rules/lateral_movement.rules"

def test_psexec_rule_fires_and_is_quiet_on_benign():
    fx = packetforge_fixture("psexec-lateral", env="office", seed=7)
    # the rule must catch the attack ...
    assert fx.fires(MY_RULES)
    # ... and must NOT fire on the benign-only twin (same env/seed, no attack)
    assert fx.quiet_on_benign(MY_RULES)
```

Every fixture is deterministic (same inputs → byte-identical pcap), ships its `GROUND_TRUTH.json`
answer key, and carries a benign twin for the false-positive half of the test — the two
assertions every good detection needs (*catches the TTP*, *stays quiet on normal traffic*).

`packetforge list-attacks` enumerates the fixtures. The rendered bundle (`fx.zeek_dir`) also
holds the real Zeek logs, so log-based detections (Sigma over Zeek, Splunk, Elastic) can grade
against `conn.log` / `dns.log` / `dce_rpc.log` / … the same way.

## Export to suricata-verify

To drop a PacketForge capture straight into a Suricata rule-regression suite (the
[`suricata-verify`](https://github.com/OISF/suricata-verify) format):

```python
from packetforge.detection_ci import packetforge_fixture, write_suricata_verify

fx = packetforge_fixture("dcsync", rules="rules/ad.rules")     # freezes the golden alert set
write_suricata_verify(fx, "tests/dcsync/", "rules/ad.rules")   # -> test.pcap + test.yaml
```

The generated `test.yaml` asserts the signatures that fire now keep firing — a regression guard
that fails loudly if a rule change silences a known-true detection.

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
      - run: |
          sudo apt-get update && sudo apt-get install -y suricata tshark
          echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
            | sudo tee /etc/apt/sources.list.d/zeek.list
          curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
            | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg >/dev/null
          sudo apt-get update && sudo apt-get install -y zeek
          echo /opt/zeek/bin >> "$GITHUB_PATH"
      - run: pip install packetforge pytest
      - run: pytest tests/detections/          # your rule tests, gated on the fixtures above
```

A detection can no longer merge unless it fires on the known-true capture and stays quiet on the
benign one — the same contract a unit test gives application code.
