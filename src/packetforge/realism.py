# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Realism audit — Gate 2: is the synthetic traffic distinguishable from real traffic?

The consistency gate (Gate 1) proves a capture is *valid* (real Zeek reproduces it). This
proves it is *realistic*, adversarially: an independent classifier is trained to tell
PacketForge flows from real ones, and its cross-validated accuracy is the distinguishability
statistic (a Classifier Two-Sample Test; ~0.5 = indistinguishable, 1.0 = trivially told
apart). Alongside the number, per-feature distances and permutation importance name the
*tell* to fix — because the point is a deterministic fix -> re-measure loop, exactly like
the consistency gate.

The classifier only *measures and guides*; it never generates. Fixes stay hand-authored
and deterministic, preserving the engine's no-ML-at-generation contract.

Features are derived from Zeek's ``conn.log`` — precisely what a defender's NIDS-ML sees —
run through the *same* pipeline for both sides, so nothing separates on capture tooling.
Scoped honestly: the result is "indistinguishable to a flow-feature gradient-boosted
adversary on these features", never an unqualified claim.

Optional dependency: ``pip install packetforge[realism]`` (scikit-learn, scipy, numpy).
"""

from __future__ import annotations

import math
import statistics
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Rich, detection-relevant per-flow features derived from packet timing/size — the
# cadence and packet-shape signal behavioural detection keys on, which conn.log misses.
_PKT_FEATURES = ["ia_mean", "ia_std", "ia_burst", "pkt_size_mean", "pkt_size_std",
                 "first_pkt_size", "first_ttl", "first_window",
                 # L7 / fingerprint signal a JA3/JA4- or p0f-aware adversary keys on:
                 "has_tcp_ts", "tls13", "ch_n_ciphers", "ch_n_exts", "ch_has_alpn"]

# Below this many flows on either side, a cross-validated C2ST can't be trained: the folds
# are too small to fit an adversary, so the number would be an artifact, not a measurement.
_MIN_FLOWS = 20


def _flow_key(orig_h, orig_p, resp_h, resp_p):
    return frozenset({(orig_h, str(orig_p)), (resp_h, str(resp_p))})


def _packet_features(pcap) -> dict:
    """Per-flow (5-tuple) features from the pcap via tshark: inter-arrival + packet-size
    stats, plus the L7 / fingerprint signal a JA3/JA4- or p0f-aware adversary keys on —
    TCP-timestamp presence and TLS ClientHello shape (version, cipher/extension counts,
    ALPN) — which conn.log alone can't see."""
    if pcap is None:
        return {}
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-T", "fields",
         "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
         "-e", "tcp.srcport", "-e", "udp.srcport", "-e", "tcp.dstport", "-e", "udp.dstport",
         "-e", "frame.time_epoch", "-e", "frame.len", "-e", "ip.ttl",
         "-e", "tcp.window_size_value", "-e", "tcp.options.timestamp.tsval",
         "-e", "tls.handshake.type", "-e", "tls.handshake.ciphersuite",
         "-e", "tls.handshake.extension.type"],
        capture_output=True, text=True, check=False).stdout
    flows: dict = {}
    for line in out.splitlines():
        c = (line.split("\t") + [""] * 16)[:16]
        src, dst = c[0] or c[1], c[2] or c[3]
        sport, dport = c[4] or c[5], c[6] or c[7]
        if not src or not dst:
            continue
        try:
            t, ln = float(c[8]), float(c[9])
        except ValueError:
            continue
        f = flows.setdefault(_flow_key(src, sport, dst, dport),
                             {"ts": [], "sz": [], "ttl": _f(c[10]), "win": _f(c[11]),
                              "has_ts": 0.0, "ciph": 0.0, "ext": 0.0, "alpn": 0.0, "v13": 0.0})
        f["ts"].append(t)
        f["sz"].append(ln)
        if c[12]:                               # any segment carried a TCP timestamp
            f["has_ts"] = 1.0
        if "1" in c[13].split(","):             # a TLS ClientHello in this frame
            exts = [x for x in c[15].split(",") if x]
            f["ciph"] = float(len([x for x in c[14].split(",") if x]))
            f["ext"] = float(len(exts))
            f["alpn"] = 1.0 if "16" in exts else 0.0
            f["v13"] = 1.0 if "43" in exts else 0.0  # supported_versions -> a real 1.3 hello
    feats: dict = {}
    for key, d in flows.items():
        ts, sz = sorted(d["ts"]), d["sz"]
        ias = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        ia_mean = statistics.mean(ias) if ias else 0.0
        ia_std = statistics.pstdev(ias) if len(ias) > 1 else 0.0
        feats[key] = [math.log1p(ia_mean), math.log1p(ia_std),
                      ia_std / ia_mean if ia_mean else 0.0,
                      statistics.mean(sz) if sz else 0.0,
                      statistics.pstdev(sz) if len(sz) > 1 else 0.0,
                      float(sz[0]) if sz else 0.0, d["ttl"], d["win"],
                      d["has_ts"], d["v13"], d["ciph"], d["ext"], d["alpn"]]
    return feats

# Categorical conn_state values Zeek emits; one-hot so the classifier can use them.
_CONN_STATES = ["SF", "S0", "S1", "S2", "S3", "SH", "SHR", "RSTO", "RSTR", "RSTOS0",
                "RSTRH", "REJ", "OTH"]
_PROTOS = ["tcp", "udp", "icmp"]


def _f(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def flow_feature_rows(zeek_workdir: str | Path, pcap=None) -> tuple:
    """Per-flow feature vectors from Zeek conn.log (+ packet timing/size if ``pcap`` given).

    Returns (rows, names, services).
    """
    from packetforge.validation.roundtrip import _parse_zeek_log
    conn = _parse_zeek_log(Path(zeek_workdir) / "conn.log")
    pfeats = _packet_features(pcap)

    names = ["l_duration", "l_orig_bytes", "l_resp_bytes", "l_orig_pkts", "l_resp_pkts",
             "l_orig_ipb", "l_resp_ipb", "orig_bpp", "resp_bpp", "l_byte_ratio",
             "l_pkt_ratio", "history_len", "l_missed", "l_total_pkts"]
    names += [f"cs_{s}" for s in _CONN_STATES] + [f"proto_{p}" for p in _PROTOS] + _PKT_FEATURES

    rows, services = [], []
    for r in conn:
        dur = _f(r.get("duration"))
        ob, rb = _f(r.get("orig_bytes")), _f(r.get("resp_bytes"))
        op, rp = _f(r.get("orig_pkts")), _f(r.get("resp_pkts"))
        oib, rib = _f(r.get("orig_ip_bytes")), _f(r.get("resp_ip_bytes"))
        hist = r.get("history", "") or ""
        vec = [
            math.log1p(dur), math.log1p(ob), math.log1p(rb), math.log1p(op),
            math.log1p(rp), math.log1p(oib), math.log1p(rib),
            ob / op if op else 0.0, rb / rp if rp else 0.0,
            math.log1p(rb / ob) if ob else 0.0,
            math.log1p(rp / op) if op else 0.0,
            float(len(hist)), math.log1p(_f(r.get("missed_bytes"))),
            math.log1p(op + rp),
        ]
        cs = r.get("conn_state", "OTH")
        vec += [1.0 if cs == s else 0.0 for s in _CONN_STATES]
        proto = r.get("proto", "")
        vec += [1.0 if proto == p else 0.0 for p in _PROTOS]
        key = _flow_key(r.get("id.orig_h", ""), r.get("id.orig_p", ""),
                        r.get("id.resp_h", ""), r.get("id.resp_p", ""))
        vec += pfeats.get(key, [0.0] * len(_PKT_FEATURES))
        rows.append(vec)
        services.append(r.get("service", "-") or "-")
    return rows, names, services


@dataclass
class RealismReport:
    c2st_auc: float = 0.5           # headline: 0.5 = indistinguishable, 1.0 = separable
    held_out_auc: float = 0.5       # a different, held-out learner (Goodhart guard)
    mmd: float = 0.0                # kernel two-sample distance (0 = identical)
    n_real: int = 0
    n_synth: int = 0
    tells: list = field(default_factory=list)     # [(feature, ks, importance)] worst first
    per_service_auc: dict = field(default_factory=dict)
    service_mix: dict = field(default_factory=dict)  # service -> (real_frac, synth_frac)
    # Calibration: the same C2ST run between the reference and a *second real* capture. Two
    # distinct real captures are not the same distribution (different networks/times/mix), so
    # this is well above 0.5 — it is the floor a generator of *novel* traffic can reach. The
    # synth's AUC is only meaningful relative to it; an absolute 0.5 target is unachievable for
    # anything but a near-exact replay of this one reference. 0.0 => not measured.
    real_baseline_auc: float = 0.0            # mean AUC across the calibration captures
    real_baseline_range: tuple = ()           # (min, max) across the calibration captures
    temporal_baseline_auc: float = 0.0        # within-source floor (first vs second half)

    @property
    def underpowered(self) -> bool:
        """Too few flows on one side to actually train the adversary — the C2ST didn't run."""
        return min(self.n_real, self.n_synth) < _MIN_FLOWS

    @property
    def verdict(self) -> str:
        if self.underpowered:
            # The 0.5 here is a default, not a measurement — never report it as a pass.
            return f"inconclusive — too few flows to run the test (need >= {_MIN_FLOWS} per side)"
        a = self.c2st_auc
        if a < 0.6:
            return "indistinguishable (to this adversary)"
        if a < 0.75:
            return "weakly distinguishable"
        if a < 0.9:
            return "distinguishable"
        return "trivially distinguishable"

    def render(self) -> str:
        if self.underpowered:
            # No test was run — say so plainly instead of printing a 0.500 that reads as a pass.
            return "\n".join([
                "Realism audit (Gate 2) — flow-feature adversary",
                f"  INCONCLUSIVE: {self.verdict}",
                f"  real flows: {self.n_real}, synthetic: {self.n_synth}  "
                f"(the 0.5 / MMD 0 below are defaults, NOT a measurement)",
                "  Capture a larger real reference (a longer, broader tcpdump — not just a few "
                "web/DNS flows) and re-run; the synthetic side is already large enough.",
            ])
        lines = [
            "Realism audit (Gate 2) — flow-feature adversary",
            f"  C2ST AUC: {self.c2st_auc:.3f}  ->  {self.verdict}   "
            f"(0.5 = indistinguishable, 1.0 = trivially told apart)",
            f"  held-out adversary AUC (ExtraTrees): {self.held_out_auc:.3f}  "
            f"(Goodhart guard — both must be low to claim indistinguishable)",
            f"  kernel MMD: {self.mmd:.4f}   |   real flows: {self.n_real}, synthetic: {self.n_synth}",
        ]
        if self.per_service_auc:
            lines.append("  per-service AUC (mix-invariant):")
            for svc, auc in sorted(self.per_service_auc.items(), key=lambda kv: -kv[1]):
                lines.append(f"    {svc:8} {auc:.3f}")
        lines.append("  top tells (fix these deterministically, worst first):")
        for name, ks, imp in self.tells[:8]:
            lines.append(f"    {name:14} KS={ks:.3f}  importance={imp:.3f}")
        return "\n".join(lines)


def _mmd_rbf(x, y, gamma=None) -> float:
    """RBF-kernel MMD^2 between standardized samples x and y (0 = identical)."""
    import numpy as np
    from sklearn.metrics.pairwise import rbf_kernel
    x, y = np.clip(x, -8, 8), np.clip(y, -8, 8)  # tame outliers so the Gram matrix is stable
    if gamma is None:
        gamma = 1.0 / max(1, x.shape[1])
    with np.errstate(over="ignore", invalid="ignore"):
        kxx, kyy, kxy = rbf_kernel(x, x, gamma), rbf_kernel(y, y, gamma), rbf_kernel(x, y, gamma)
    return float(max(0.0, kxx.mean() + kyy.mean() - 2 * kxy.mean()))


def c2st_auc_between(rows_a: list, rows_b: list) -> float:
    """Cross-validated C2ST AUC between two feature-row sets (same learner as the audit).

    0.5 = the two sets are one distribution; 1.0 = trivially separable. Used to calibrate the
    synth-vs-real number against a real-vs-real baseline (two distinct real captures).
    """
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import cross_val_predict
    A, B = np.array(rows_a, dtype=float), np.array(rows_b, dtype=float)
    if len(A) < 20 or len(B) < 20:
        return 0.5
    Xy = np.vstack([A, B])
    yy = np.array([1] * len(A) + [0] * len(B))
    clf = HistGradientBoostingClassifier(max_depth=4, random_state=0)
    p = cross_val_predict(clf, Xy, yy, cv=5, method="predict_proba")[:, 1]
    return float(roc_auc_score(yy, p))


def temporal_split_auc(rows: list) -> float:
    """C2ST AUC between the first and second half of one capture's flows (conn.log is ~time
    ordered). A *within-source* baseline: how separable two time-windows of the same network
    are. It sits between the random-split null (~0.5) and the cross-capture floor (~0.95), and
    needs no second capture — so it is always reportable as context for the synth's number.
    """
    n = len(rows) // 2
    if n < 20:
        return 0.5
    return c2st_auc_between(rows[:n], rows[n:])


def hurst_aggvar(times: list, base_bins: int = 512) -> float:
    """Hurst exponent of an event-arrival series by the aggregated-variance method — a measure
    of self-similarity / long-range dependence (burstiness that persists across timescales).
    H ~ 0.5 = no LRD (Poisson/uniform arrivals — the classic synthetic tell); 0.5 < H < 1 =
    self-similar, as real aggregate traffic is (Leland-Willinger). Returns NaN if too few events.

    Bin the arrival times into a fine count series, aggregate at geometric block sizes m, and fit
    Var(X^(m)) ~ m^(2H-2); the slope gives H. Used as a first-class realism signal so within-capture
    heterogeneity is measured, not assumed.
    """
    import numpy as np
    t = np.sort(np.asarray(list(times), dtype=float))
    if len(t) < 128 or t[-1] <= t[0]:
        return float("nan")
    counts = np.histogram(t, bins=base_bins, range=(t[0], t[-1]))[0].astype(float)
    ms, vs = [], []
    m = 1
    while base_bins // m >= 8:
        trimmed = counts[: (len(counts) // m) * m].reshape(-1, m).mean(axis=1)
        v = float(trimmed.var())
        if v > 0:
            ms.append(m)
            vs.append(v)
        m *= 2
    if len(ms) < 3:
        return float("nan")
    slope = float(np.polyfit(np.log(ms), np.log(vs), 1)[0])
    return 1.0 + slope / 2.0


def audit(real_workdir: str | Path, synth_workdir: str | Path,
          real_pcap=None, synth_pcap=None) -> RealismReport:
    """Score how distinguishable the synthetic capture is from the real one.

    Pass the pcaps to add packet timing/size/fingerprint features (recommended).
    """
    import numpy as np
    from scipy.stats import ks_2samp
    from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
    from sklearn.inspection import permutation_importance
    from sklearn.model_selection import cross_val_predict
    from sklearn.preprocessing import StandardScaler

    import warnings

    from sklearn.metrics import roc_auc_score

    real_rows, names, real_svc = flow_feature_rows(real_workdir, real_pcap)
    synth_rows, _, synth_svc = flow_feature_rows(synth_workdir, synth_pcap)
    R, S = np.array(real_rows, dtype=float), np.array(synth_rows, dtype=float)
    rep = RealismReport(n_real=len(R), n_synth=len(S))
    if len(R) == 0 or len(S) == 0:
        # Empty in, "0.500 indistinguishable" out would be a lie — two empty captures
        # aren't realistically alike, there's simply nothing there. Refuse it.
        raise ValueError(f"no flows to compare (real={len(R)}, synth={len(S)}) — "
                         f"are both captures valid, non-empty pcaps?")
    if len(R) < _MIN_FLOWS or len(S) < _MIN_FLOWS:
        return rep  # too few to train an adversary — rep.underpowered flags this honestly

    def c2st_auc(a, b, cv, clf=None):
        Xy = np.vstack([a, b])
        yy = np.array([1] * len(a) + [0] * len(b))
        if clf is None:
            clf = HistGradientBoostingClassifier(max_depth=4, random_state=0)
        p = cross_val_predict(clf, Xy, yy, cv=cv, method="predict_proba")[:, 1]
        return float(roc_auc_score(yy, p))

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)  # numpy/BLAS numeric noise
        X = np.vstack([R, S])
        y = np.array([1] * len(R) + [0] * len(S))
        rep.c2st_auc = c2st_auc(R, S, cv=5)  # the headline distinguishability statistic
        # a different, held-out learner: if we drove the GBM to 0.5 by overfitting its
        # inductive bias, this one would still separate. A claim needs both low.
        rep.held_out_auc = c2st_auc(
            R, S, cv=5, clf=ExtraTreesClassifier(n_estimators=200, random_state=1))

        # standardized MMD — drop zero-variance columns so the scaler can't emit inf/nan
        keep = X.std(axis=0) > 0
        Xs = np.nan_to_num(StandardScaler().fit_transform(X[:, keep]))
        rep.mmd = _mmd_rbf(Xs[y == 1], Xs[y == 0])

        # per-feature KS + permutation importance -> the actionable tell ranking
        clf = HistGradientBoostingClassifier(max_depth=4, random_state=0).fit(X, y)
        imp = permutation_importance(clf, X, y, n_repeats=5, random_state=0).importances_mean
        tells = [(name, float(ks_2samp(R[:, j], S[:, j]).statistic), float(imp[j]))
                 for j, name in enumerate(names)]
        rep.tells = sorted(tells, key=lambda t: (-t[2], -t[1]))

        # per-service AUC (mix-invariant): only where both sides have enough of that service
        for svc in set(real_svc) & set(synth_svc):
            ri = [i for i, s in enumerate(real_svc) if s == svc]
            si = [i for i, s in enumerate(synth_svc) if s == svc]
            if len(ri) >= 15 and len(si) >= 15:
                try:
                    rep.per_service_auc[svc] = c2st_auc(R[ri], S[si], cv=3)
                except ValueError:
                    pass

    nr, ns = max(1, len(real_svc)), max(1, len(synth_svc))
    for svc in set(real_svc) | set(synth_svc):
        rep.service_mix[svc] = (real_svc.count(svc) / nr, synth_svc.count(svc) / ns)
    return rep
