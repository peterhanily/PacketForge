# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic TCP conversation builder.

Given a list of application messages (each tagged with a direction), this produces a
byte-accurate, reassembly-valid TCP packet series that real Zeek reads without
``weird``/``reporter`` events. It owns SEQ/ACK arithmetic, MSS segmentation, the
handshake, per-``conn_state`` shapes, and teardown — and reconstructs the Zeek
``history`` string from exactly the packets it emits.

The builder is pure: it is handed already-resolved endpoint fingerprint parameters
(TTL, window, TCP options) so it has no dependency on the fingerprint library or the
IR. L7 renderers call it; DNS/ICMP do not.
"""

from __future__ import annotations

import contextvars
import math
import random
from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

MSS = 1460


@dataclass(frozen=True)
class Texture:
    """Capture 'texture' — the imperfections that make a clean pass mean something.

    ``clean`` (all zero) reproduces the byte-exact ideal flow. ``realistic`` sprinkles
    RTT/timing jitter, TCP retransmissions, and duplicate ACKs — all things real Zeek
    handles without a ``weird``, and none of which change the reassembled application
    stream, the conn_state, or Zeek's sequence-based byte counts.
    """

    jitter_frac: float = 0.0       # inter-packet gap jitter, as a fraction of RTT
    retransmit_prob: float = 0.0   # per data segment, chance it is retransmitted once
    dup_ack_prob: float = 0.0      # per ACK, chance a duplicate ACK follows
    linger_scale: float = 0.0      # mean idle seconds before teardown (heavy-tailed);
    #                                real flows keep connections open, ours don't
    heavy_timing: bool = False     # draw data-phase gaps from a heavy-tailed (exponential)
    #                                distribution instead of tight uniform jitter, and space
    #                                consecutive segments, so within-flow inter-arrivals get
    #                                the spread/burstiness (ia_std, ia_burst) of real traffic.
    #                                Mean-preserving and adds no packets — validity is untouched.


_LOGN_SIGMA = 1.2   # heavy_timing: lognormal gap sigma (CV = sqrt(exp(s^2)-1) ~ 1.7, bursty)

TEXTURES = {
    "clean": Texture(),
    "realistic": Texture(jitter_frac=0.45, retransmit_prob=0.03, dup_ack_prob=0.05,
                         linger_scale=12.0),
    # Reference-matching timing without retransmits/dup-ACKs, so packet counts stay exact
    # (validity is byte-for-byte) while within-flow inter-arrivals get real bursty spread.
    "conditioned": Texture(jitter_frac=0.3, heavy_timing=True),
}

# Capture-wide texture, set by the compiler around a render so renderers need no new
# parameter. Defaults to clean, so a bare build_tcp_flow() is byte-exact as before.
_TEXTURE: contextvars.ContextVar = contextvars.ContextVar("pf_texture", default=TEXTURES["clean"])

# Per-flow effective segment size (bytes), set by the compiler around a render. None -> MSS.
# Lets a flow emit fewer, larger-than-MSS segments (as an offload/GRO capture does) so its
# packet count matches a conditioned reference. Capped to fit a single IP packet.
_SEG_BYTES: contextvars.ContextVar = contextvars.ContextVar("pf_seg_bytes", default=None)
_MAX_SEG = 64000


@dataclass
class Endpoint:
    ip: str
    port: int
    mac: str
    ttl: int = 64
    window: int = 64240
    # scapy TCP options list, e.g. [("MSS", 1460), ("SAckOK", b""), ("WScale", 7)].
    syn_options: list = field(default_factory=list)
    timestamps: bool = False  # emit the TCP Timestamps option (negotiated if both do)


@dataclass
class TcpMessage:
    """One application-layer message and its direction."""

    from_orig: bool
    payload: bytes


@dataclass
class TcpResult:
    packets: list  # list[scapy Packet], each with .time set
    summary: dict  # measured Zeek-style conn.log view


class _HistoryRecorder:
    """Reconstructs Zeek's connection ``history`` string.

    Zeek records the first occurrence, per direction, of each state letter. Uppercase
    = originator sent it, lowercase = responder sent it. S=SYN, H=SYN+ACK, A=pure ACK,
    D=data, F=FIN, R=RST.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._chars: list[str] = []

    def record(self, letter_upper: str, from_orig: bool) -> None:
        ch = letter_upper if from_orig else letter_upper.lower()
        if ch not in self._seen:
            self._seen.add(ch)
            self._chars.append(ch)

    def value(self) -> str:
        return "".join(self._chars)


def _segment(payload: bytes, mss: int, min_segments: int = 1) -> list[bytes]:
    """Split a payload into <= mss chunks, honoring a minimum segment count."""
    if not payload:
        return []
    chunks = [payload[i : i + mss] for i in range(0, len(payload), mss)]
    # If the caller wants more segments than MSS forces, split further, evenly.
    while len(chunks) < min_segments and any(len(c) > 1 for c in chunks):
        biggest = max(range(len(chunks)), key=lambda i: len(chunks[i]))
        c = chunks[biggest]
        half = max(1, len(c) // 2)
        chunks[biggest : biggest + 1] = [c[:half], c[half:]]
    return chunks


def build_tcp_flow(
    orig: Endpoint,
    resp: Endpoint,
    messages: list[TcpMessage],
    start_time: float,
    rtt: float,
    rng: random.Random,
    conn_state: str = "SF",
    min_segments: int = 1,
) -> TcpResult:
    """Render one TCP conversation. See module docstring."""
    c_isn = rng.randint(0, 0xFFFFFFFF)
    s_isn = rng.randint(0, 0xFFFFFFFF)
    hist = _HistoryRecorder()
    pkts: list[Packet] = []
    clock = {"t": start_time}
    texture = _TEXTURE.get()
    # Bytes counted per direction from ORIGINAL segments only (retransmits repeat
    # sequence space and must not double-count — matching Zeek's seq-based orig_bytes).
    data_bytes = {True: 0, False: 0}

    def jit(base: float) -> float:
        """Jitter a delay by +/- jitter_frac (never negative). No rng draw when clean."""
        if not texture.jitter_frac:
            return base
        return max(0.0, base * (1.0 + texture.jitter_frac * (rng.random() * 2.0 - 1.0)))

    def hgap(mean: float) -> float:
        """A data-phase inter-packet gap. Under heavy_timing it is lognormal with expectation
        `mean` and a heavy right tail (sigma sets the burstiness), reproducing real traffic's
        low-median / high-variance inter-arrivals (ia_std, ia_burst). Lognormal is used rather
        than an ON/OFF mix because each gap independently centres on `mean`, so even a short
        flow with a handful of gaps keeps ia_mean ~ `mean` instead of collapsing to a floor.
        Mean-preserving and adds no packets; falls back to uniform jitter when not heavy-tailed."""
        if not (texture.heavy_timing and mean > 0):
            return jit(mean)
        mu = math.log(mean) - _LOGN_SIGMA * _LOGN_SIGMA / 2.0   # E[exp(N(mu,s))] = mean
        return min(90.0, math.exp(rng.gauss(mu, _LOGN_SIGMA)))

    # TCP Timestamps: negotiated only when both endpoints advertise them; once active
    # they appear on every segment with a ~1 kHz clock and echo the peer's last tsval.
    ts_active = orig.timestamps and resp.timestamps
    ts_base = {True: rng.randint(1_000_000, 2_000_000_000),
               False: rng.randint(1_000_000, 2_000_000_000)}  # keyed by from_orig
    ts_last = {True: 0, False: 0}

    def _ipid() -> int:
        return rng.randint(0, 0xFFFF)

    def frame(from_orig: bool, flags: str, seq: int, ack: Optional[int],
              payload: bytes = b"", options: Optional[list] = None) -> Packet:
        s, d = (orig, resp) if from_orig else (resp, orig)
        tcp = TCP(sport=s.port, dport=d.port, flags=flags, seq=seq, window=s.window)
        if ack is not None:
            tcp.ack = ack
        opts = list(options) if options else []
        if ts_active:
            tsval = (ts_base[from_orig] + int((clock["t"] - start_time) * 1000)) & 0xFFFFFFFF
            opts.append(("Timestamp", (tsval, ts_last[not from_orig])))
            ts_last[from_orig] = tsval
        if opts:
            tcp.options = opts
        p = Ether(src=s.mac, dst=d.mac) / IP(src=s.ip, dst=d.ip, id=_ipid(), ttl=s.ttl) / tcp
        if payload:
            p = p / Raw(payload)
        p.time = clock["t"]
        return p

    def emit(p: Packet, letter: str, from_orig: bool, advance: float = 0.0) -> None:
        pkts.append(p)
        hist.record(letter, from_orig)
        clock["t"] += advance

    # Under heavy_timing the conditioned rtt is an *application* pacing scale (think-time),
    # so network-level gaps — the handshake, teardown ACKs — use a capped network RTT. The
    # mix of a fast handshake and slow think-time is what gives real flows their ia_std.
    net_rtt = min(rtt, 0.05) if texture.heavy_timing else rtt
    half = net_rtt / 2.0

    # ----- handshake (all states except a pure teardown-less variant start here) -----
    established = conn_state in {"SF", "RSTO", "RSTR"}
    if conn_state == "S0":
        # SYN sent, nothing comes back.
        emit(frame(True, "S", c_isn, None, options=orig.syn_options), "S", True)
        clock["t"] += rtt
    elif conn_state == "REJ":
        emit(frame(True, "S", c_isn, None, options=orig.syn_options), "S", True, half)
        emit(frame(False, "RA", 0, c_isn + 1), "R", False)
        clock["t"] += rtt
    elif established:
        emit(frame(True, "S", c_isn, None, options=orig.syn_options), "S", True, half)
        emit(frame(False, "SA", s_isn, c_isn + 1, options=resp.syn_options), "H", False, half)
        emit(frame(True, "A", c_isn + 1, s_isn + 1), "A", True)
    else:
        raise ValueError(f"unsupported conn_state: {conn_state!r}")

    c_seq = c_isn + 1
    s_seq = s_isn + 1

    if established:
        # ----- data exchange: each message sent, then acked by the peer -----
        for msg in messages:
            snd, rcv = (True, False) if msg.from_orig else (False, True)
            seq = c_seq if msg.from_orig else s_seq
            peer_ack = s_seq if msg.from_orig else c_seq
            clock["t"] += hgap(rtt) if texture.heavy_timing else jit(rng.uniform(0.001, 0.01))
            mss = min(_SEG_BYTES.get() or MSS, _MAX_SEG)
            segs = list(_segment(msg.payload, mss, min_segments))
            for i, chunk in enumerate(segs):
                emit(frame(snd, "PA", seq, peer_ack, payload=chunk), "D", snd)
                data_bytes[snd] += len(chunk)  # original bytes only
                # Retransmission: the same segment (same seq/payload) resent after a
                # short RTO. Zeek marks a retransmitted payload in history as 'T'/'t'
                # (distinct from the original 'D'/'d') and does not re-count its bytes.
                if texture.retransmit_prob and rng.random() < texture.retransmit_prob:
                    clock["t"] += jit(half * (1.0 + rng.random()))
                    emit(frame(snd, "PA", seq, peer_ack, payload=chunk), "T", snd)
                seq += len(chunk)
                if texture.heavy_timing and i < len(segs) - 1:
                    clock["t"] += hgap(rtt)  # space consecutive segments (bursty app pacing)
            if msg.from_orig:
                c_seq = seq
            else:
                s_seq = seq
            # peer acknowledges the whole message
            clock["t"] += hgap(rtt)
            ack_seq = s_seq if msg.from_orig else c_seq
            ack_num = c_seq if msg.from_orig else s_seq
            emit(frame(rcv, "A", ack_seq, ack_num), "A", rcv)
            if texture.dup_ack_prob and rng.random() < texture.dup_ack_prob:
                clock["t"] += jit(half * 0.3)
                emit(frame(rcv, "A", ack_seq, ack_num), "A", rcv)  # duplicate ACK

        # ----- teardown -----
        # Real connections often stay open idle before closing, giving a heavy-tailed
        # duration distribution; ours pack tightly. About half the flows linger for an
        # exponential idle time (capped), reproducing that long tail.
        if texture.linger_scale and rng.random() < 0.5:
            clock["t"] += min(250.0, rng.expovariate(1.0 / texture.linger_scale))
        clock["t"] += jit(rng.uniform(0.02, 0.2))
        if conn_state == "SF":
            emit(frame(True, "FA", c_seq, s_seq), "F", True, half)
            emit(frame(False, "FA", s_seq, c_seq + 1), "F", False, half)
            emit(frame(True, "A", c_seq + 1, s_seq + 1), "A", True)
        elif conn_state == "RSTO":
            emit(frame(True, "R", c_seq, s_seq), "R", True)
        elif conn_state == "RSTR":
            emit(frame(False, "R", s_seq, c_seq), "R", False)

    # ----- measured summary, reconstructed purely from emitted packets -----
    def _is_orig(p: Packet) -> bool:
        return p[IP].src == orig.ip

    orig_pkts = sum(1 for p in pkts if _is_orig(p))
    resp_pkts = len(pkts) - orig_pkts
    # Zeek counts payload bytes from sequence space, so retransmitted segments don't
    # add to orig_bytes/resp_bytes (they do add packets and IP bytes, which are raw).
    orig_bytes = data_bytes[True]
    resp_bytes = data_bytes[False]
    orig_ip_bytes = sum(len(p[IP]) for p in pkts if _is_orig(p))
    resp_ip_bytes = sum(len(p[IP]) for p in pkts if not _is_orig(p))
    duration = round((pkts[-1].time - pkts[0].time), 6) if pkts else 0.0

    summary = {
        "conn_state": conn_state,
        "history": hist.value(),
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_ip_bytes": orig_ip_bytes,
        "resp_ip_bytes": resp_ip_bytes,
        "duration": duration,
    }
    return TcpResult(packets=pkts, summary=summary)
