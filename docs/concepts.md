# Concepts

The vocabulary the rest of the documentation assumes. Read this once and the other pages stop
needing footnotes.

## The one idea

A synthetic capture is only worth having if two things are true about it: the packets behave like
packets, and the labels are right. Most synthetic traffic gets one or the other.

PacketForge gets both by describing an incident once and projecting it twice. The packets and the
log rows that incident should produce come from the same description, so they cannot drift apart
on a port, a hostname or a byte count. Then real Zeek reads the capture back and its logs are
compared against the expected rows, field by field. The generator does not grade its own work.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/consistency-dark.svg">
  <img alt="One incident is rendered twice: as packets, which real Zeek reads back into logs, and as the logs the same event should produce. The two sets of logs must match field for field." src="img/consistency.svg" width="880">
</picture>

## The four gates

Every claim PacketForge makes belongs to one of four questions. Each has a command, and each has a
published answer.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/gates-dark.svg">
  <img alt="Gates one to three ask whether a capture looks like real traffic: validity, realism and detection behaviour. Gate four asks whether it is faithful to the incident it claims to depict." src="img/gates.svg" width="880">
</picture>

Gates 1 to 3 are three versions of one question: is this like real traffic? What each one measures,
how to run it, and where the numbers currently stand are in [`validation.md`](validation.md).

Gate 4 asks something they cannot. A capture can be well formed, statistically plausible and
detection-equivalent while depicting an incident that never happened the way it says. That failure
has a worked example in this repository, scored in
[`exploitgym-postmortem-delta.md`](exploitgym-postmortem-delta.md), and the check that now catches
it is in [`correspondence.md`](correspondence.md).

## Two kinds of answer key

The distinction runs through the sample gallery and the manifests, so it is worth fixing early.

**Ground truth.** A scenario was executed against a plan the generator holds. The plan is the
answer key, and it is exact. Every attack in `packetforge list-attacks` works this way, and its
capture ships `GROUND_TRUTH.md` and `GROUND_TRUTH.json`.

**Reconstruction.** The subject is somebody else's incident, known only through what its
participants published. Nobody ran it, so no ground truth exists. What exists is a set of source
claims, and the artifact ships `RECONSTRUCTION.md` plus a generated `CLAIMS.md` saying which claim
licenses each flow and which fields were invented. Calling that file `GROUND_TRUTH` would be a
category error, which is why it is not called that.

## Inert by construction

Traffic that models an attack reproduces the detection signal and never the offensive capability.
Argument stubs are zero filler, NTLM responses are fixed bytes rather than crackable hashes,
transferred files are typed containers with no executable section, and no packet contains a
working command line. PacketForge opens no sockets and executes nothing. The property is enforced
by tests rather than asserted, and the details are in
[`inert-by-construction.md`](inert-by-construction.md).

## Determinism

The same inputs produce the same bytes, on any machine, on any run. This is what makes a capture
usable as a test fixture: a rule test that renders its own input cannot flake. It is also the
property most easily lost, because scapy fills several time and identifier fields from the wall
clock unless they are pinned. See [`DESIGN.md`](DESIGN.md) for how that is caught.

## Glossary

**Ambient.** The background traffic of a network going about its day. A scenario is mostly
ambient, with the storyline woven through it, so that finding the attack takes work.

**BZAR.** [MITRE's Bro/Zeek ATT&CK-based Analytics and Reporting](https://github.com/mitre-attack/bzar),
a set of Zeek scripts that raise notices on Windows lateral-movement behaviour. Several attacks
here are built to trip specific BZAR notices, and the tests check that against the real analytic.

**C2ST.** Classifier two-sample test. Train a classifier to tell two sets of flows apart and read
its cross-validated AUC. An AUC of 0.5 means it cannot; 1.0 means the two sets are trivially
separable. Used as Gate 2's adversary.

**conn_state.** Zeek's summary of how a connection ended: `SF` for a normal finish, `S0` for a SYN
with no reply, `REJ` for a refusal, `RSTO` for a reset by the originator, and so on. A capture
where everything is `SF` does not look like a real network.

**Ground truth.** See [two kinds of answer key](#two-kinds-of-answer-key) above.

**history.** Zeek's per-connection string recording the order of TCP events, one letter per event.
PacketForge reconstructs the expected string from the exact bytes it emitted, which is a strict
test of the TCP layer.

**IMDS.** A cloud instance metadata service, reachable at the link-local address 169.254.169.254
on every major provider. Stealing credentials from it through a server-side request forgery is the
shape of the 2019 Capital One breach.

**JA3 and JA4.** Fingerprints of a TLS client, computed from the shape of its ClientHello rather
than from any address or name. They identify the software, which puts them near the top of the
[Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html), the
observation that indicators an attacker can change cheaply are worth less than ones they cannot.

**MMD.** Maximum mean discrepancy, a kernel distance between two distributions. Reported alongside
the C2ST AUC because it moves when the distributions converge even if the classifier's headline
number does not.

**Opaque shell.** A flow with correct handshake, teardown, sequencing and volumetrics, whose
application bytes are sized filler. Used where there is no faithful renderer yet, in preference to
emitting a half-parsed guess that a dissector would flag.

**Real-vs-real floor.** The score the Gate 2 adversary gives two genuinely different real
captures. It is high, because two real captures are two different distributions. It is the target
a generator of new traffic can actually reach, and the reason 0.5 is the wrong bar.

**SPAN, TAP, mirror.** Three places a sensor can sit. A SPAN port copies traffic inside a switch,
a TAP sits inline on a link, and a cloud traffic mirror encapsulates copied packets to a collector.
Each sees a different version of the same incident.

**Texture.** How messy a capture is: `clean`, `realistic` (round-trip jitter, retransmits,
duplicate acknowledgements), or `conditioned` (marginals matched to a reference capture).

**Vantage.** Where the capture was taken. `packetforge scenario --vantages` renders one incident
from several at once, which answers whether a detection fires given where the sensors actually are.

**Linux SLL.** The cooked link type `tcpdump` records when it captures on a host rather than on a
wire, with no Ethernet header. Cloud environments use it, because that is what a capture agent on
an instance actually produces.
