#!/usr/bin/env python3
"""Render the PacketForge documentation figures.

One source, two files per figure (light + dark), so a README can use
<picture> and follow the reader's GitHub theme. Presentation is inline on
every element: GitHub's SVG sanitiser is not guaranteed to keep <style>.
"""
from __future__ import annotations

import pathlib
import sys

MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace"

THEMES = {
    "light": {
        "ink": "#1F2328",      # primary text, box strokes
        "muted": "#6E7781",    # captions, secondary labels
        "rule": "#D1D9E0",     # hairlines
        "fill": "#FFFFFF",     # box interiors (opaque so lines never show through)
        "wash": "#F6F8FA",     # grouping bands
        "ok": "#1A7F37",
        "bad": "#CF222E",
        "accent": "#9A6700",
    },
    "dark": {
        "ink": "#E6EDF3",
        "muted": "#9198A1",
        "rule": "#3D444D",
        "fill": "#0D1117",
        "wash": "#161B22",
        "ok": "#3FB950",
        "bad": "#F85149",
        "accent": "#D29922",
    },
}


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Fig:
    """A tiny SVG builder. Coordinates are absolute; the grid is 4px."""

    def __init__(self, w: int, h: int, t: dict, title: str, desc: str):
        self.w, self.h, self.t = w, h, t
        self.parts: list[str] = []
        self.title, self.desc = title, desc

    def text(self, x, y, s, size=13, fill="ink", anchor="start", weight="400",
             family=MONO, spacing=None, opacity=None):
        extra = ""
        if spacing:
            extra += f' letter-spacing="{spacing}"'
        if opacity:
            extra += f' opacity="{opacity}"'
        self.parts.append(
            f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
            f'font-weight="{weight}" fill="{self.t[fill]}" text-anchor="{anchor}"'
            f'{extra}>{esc(s)}</text>'
        )

    def box(self, x, y, w, h, r=3, stroke="ink", fill="fill", width=1.25, dash=None):
        extra = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" '
            f'fill="{self.t[fill]}" stroke="{self.t[stroke]}" stroke-width="{width}"{extra}/>'
        )

    def band(self, x, y, w, h, r=4, fill="wash"):
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{self.t[fill]}"/>'
        )

    def line(self, x1, y1, x2, y2, stroke="rule", width=1.25, dash=None):
        extra = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{self.t[stroke]}" '
            f'stroke-width="{width}" stroke-linecap="round"{extra}/>'
        )

    def path(self, d, stroke="rule", width=1.25, fill="none", marker=False, dash=None):
        f = "none" if fill == "none" else self.t[fill]
        m = ' marker-end="url(#arrow)"' if marker else ""
        extra = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<path d="{d}" fill="{f}" stroke="{self.t[stroke]}" stroke-width="{width}" '
            f'stroke-linecap="round" stroke-linejoin="round"{m}{extra}/>'
        )

    def arrow(self, x1, x2, y, stroke="rule"):
        """Horizontal arrow, left to right."""
        self.path(f"M {x1} {y} H {x2 - 7}", stroke=stroke, marker=True)

    def render(self) -> str:
        t = self.t
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
            f'width="{self.w}" height="{self.h}" role="img" '
            f'aria-labelledby="figtitle figdesc">\n'
            f'  <title id="figtitle">{esc(self.title)}</title>\n'
            f'  <desc id="figdesc">{esc(self.desc)}</desc>\n'
            f'  <defs>\n'
            f'    <marker id="arrow" viewBox="0 0 8 8" refX="6" refY="4" markerWidth="6" '
            f'markerHeight="6" orient="auto">\n'
            f'      <path d="M 0 1 L 7 4 L 0 7 z" fill="{t["rule"]}"/>\n'
            f'    </marker>\n'
            f'  </defs>\n  '
            + "\n  ".join(self.parts)
            + "\n</svg>\n"
        )


# --------------------------------------------------------------------------
# Figure 1: one incident, two renderings, one comparison
# --------------------------------------------------------------------------
def fig_consistency(t: dict) -> str:
    f = Fig(880, 248, t, "How the consistency check works",
            "One incident is rendered twice: as packets and as logs. Real Zeek reads the "
            "packets back into logs, and the two sets of logs are compared field by field.")

    top, bot = 74, 178          # centre lines of the two paths
    bh = 48                     # box height

    # source
    f.box(8, top - bh // 2, 130, bot - top + bh)
    f.text(73, 118, "one", 14, anchor="middle", weight="600")
    f.text(73, 136, "incident", 14, anchor="middle", weight="600")
    f.text(73, 158, "flows.yaml", 10.5, fill="muted", anchor="middle")

    def cell(x, w, y, label, sub=None):
        f.box(x, y - bh // 2, w, bh)
        if sub:
            f.text(x + w / 2, y - 1, label, 12.5, anchor="middle")
            f.text(x + w / 2, y + 16, sub, 10.5, fill="muted", anchor="middle")
        else:
            f.text(x + w / 2, y + 5, label, 12.5, anchor="middle")

    # branch stubs
    f.arrow(138, 178, top)
    f.arrow(138, 178, bot)

    # top path: packets, read back by a tool we did not write
    cell(178, 148, top, "render", "packetforge")
    f.arrow(326, 458, top)
    f.text(392, top - 11, "capture.pcap", 11, fill="muted", anchor="middle")
    cell(458, 138, top, "real Zeek", "zeek -r")
    f.arrow(596, 640, top)
    cell(640, 196, top, "conn.log  dns.log", "http.log  ssl.log")

    # bottom path: the logs the same event produces
    cell(178, 148, bot, "emit", "EvidenceForge")
    f.arrow(326, 640, bot)
    f.text(483, bot - 11, "no packets involved", 11, fill="muted", anchor="middle")
    cell(640, 196, bot, "conn.log  dns.log", "http.log  ssl.log")

    # the comparison, in the gap between the two sets of logs
    y1, y2 = top + bh // 2, bot - bh // 2
    f.path(f"M 672 {y1 + 6} V {y2 - 6}", stroke="accent", width=1.5)
    f.path(f"M 667 {y1 + 12} L 672 {y1 + 4} L 677 {y1 + 12}", stroke="accent", width=1.5)
    f.path(f"M 667 {y2 - 12} L 672 {y2 - 4} L 677 {y2 - 12}", stroke="accent", width=1.5)
    f.text(692, 118, "identical,", 12, fill="accent")
    f.text(692, 134, "field for field", 12, fill="accent")
    f.text(692, 150, "or the build fails", 10.5, fill="muted")

    # path captions
    f.text(178, top - bh // 2 - 13, "WHAT WAS ON THE WIRE", 10.5, fill="muted", spacing="0.06em")
    f.text(178, bot + bh // 2 + 23, "WHAT THE SENSORS LOGGED", 10.5, fill="muted", spacing="0.06em")
    return f.render()


# --------------------------------------------------------------------------
# Figure 2: the four gates
# --------------------------------------------------------------------------
GATES = [
    ("1", "validity", "Does real Zeek reproduce what we rendered?", "packetforge validate", "PASS", "ok"),
    ("2", "realism", "Can an adversary separate it from real traffic?", "packetforge realism-audit", "AT THE FLOOR", "ink"),
    ("3", "detection", "Do the same rules behave the same way on both?", "packetforge coverage", "PASS", "ok"),
    ("4", "correspondence", "Is it faithful to the incident it claims to depict?", "packetforge warrant", "1 OF 2 FAILS", "bad"),
]


def fig_gates(t: dict) -> str:
    f = Fig(880, 316, t, "The four gates",
            "Gates one to three ask whether a capture looks like real traffic. Gate four asks "
            "whether it is faithful to the incident it claims to depict.")

    left, right = 40, 856

    def row(y, gate):
        num, name, question, cmd, verdict, colour = gate
        f.text(left, y, f"Gate {num}", 12, fill="muted")
        f.text(left + 66, y, name, 13.5, weight="600")
        f.text(left + 66, y + 19, question, 12, fill="muted")
        f.text(right, y, verdict, 12, fill=colour, anchor="end", weight="600")
        f.text(right, y + 19, cmd, 10.5, fill="muted", anchor="end")

    # group one: three gates, all asking the same kind of question
    f.text(24, 26, "IS THIS LIKE REAL TRAFFIC?", 11, fill="muted", spacing="0.09em")
    f.path("M 24 40 V 176", stroke="rule", width=1.5)
    for i, gate in enumerate(GATES[:3]):
        y = 60 + i * 50
        row(y, gate)
        if i < 2:
            f.line(left, y + 33, right, y + 33, width=1)

    # group two: the question the first three cannot ask
    f.text(24, 228, "IS THIS LIKE THE INCIDENT IT CLAIMS TO DEPICT?", 11, fill="accent",
           spacing="0.09em")
    f.path("M 24 242 V 288", stroke="accent", width=1.5)
    row(262, GATES[3])

    f.text(40, 308, "Gate 4 fails on sample 18 in CI, on purpose. It is kept as the artifact "
                    "that was wrong.", 11, fill="muted")
    return f.render()


# --------------------------------------------------------------------------
# Figure 3: one incident, four places to stand
# --------------------------------------------------------------------------
VANTAGES = [
    ("edge TAP", "source NAT and one router hop", "external addresses, TTL one lower"),
    ("core SPAN", "802.1Q VLAN tag", "the tag Zeek records on every frame"),
    ("host tcpdump", "only this host's flows", "cooked Linux SLL, no Ethernet header"),
    ("cloud mirror", "VXLAN to a collector VTEP", "link-local 169.254/16 never appears"),
]


def fig_vantage(t: dict) -> str:
    f = Fig(880, 246, t, "One incident, four places to stand",
            "The same rendered incident projected to an edge TAP, a core SPAN, a host tcpdump "
            "and a cloud traffic mirror. Each vantage changes what a sensor can see.")

    rows = [56, 100, 144, 188]
    mid = (rows[0] + rows[-1]) / 2

    f.box(8, mid - 30, 132, 60)
    f.text(74, mid - 4, "one", 14, anchor="middle", weight="600")
    f.text(74, mid + 14, "incident", 14, anchor="middle", weight="600")

    # the spine, and one arrow per vantage
    f.line(160, rows[0], 160, rows[-1], stroke="rule")
    f.path(f"M 140 {mid} H 160", stroke="rule")
    for y in rows:
        f.arrow(160, 196, y)

    for y, (name, changes, effect) in zip(rows, VANTAGES):
        f.text(204, y + 4, name, 12.5, weight="600")
        f.text(324, y + 4, changes, 12, fill="muted")
        f.text(560, y + 4, effect, 12, fill="muted")

    f.text(204, 26, "VANTAGE", 10.5, fill="muted", spacing="0.08em")
    f.text(324, 26, "WHAT CHANGES", 10.5, fill="muted", spacing="0.08em")
    f.text(560, 26, "WHAT A SENSOR THEN SEES", 10.5, fill="muted", spacing="0.08em")
    f.line(204, 34, 872, 34, width=1)

    f.text(8, 236, "scenario --vantages renders all of them from one storyline; --mirror renders "
                   "the cloud one.", 11, fill="muted")
    return f.render()


FIGURES = {
    "consistency": fig_consistency,
    "gates": fig_gates,
    "vantage": fig_vantage,
}


def main(outdir: str) -> None:
    out = pathlib.Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in FIGURES.items():
        for theme, palette in THEMES.items():
            suffix = "" if theme == "light" else "-dark"
            path = out / f"{name}{suffix}.svg"
            path.write_text(fn(palette))
            print(f"wrote {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs/img")
