#!/usr/bin/env python3
"""Draws the README images in docs/ (dark + light). Stdlib only: python3 docs/make_docs.py"""
import html
import os

OUT = os.path.dirname(os.path.abspath(__file__))
E = html.escape
THEMES = {
    "dark": dict(bg="#060a0f", bg2="#0b1118", panel="#0f161d", line="#1f2c37", line2="#2b3c4a", fg="#e8eff3",
                 muted="#8d9ca8", accent="#f5b83f", ai="#4fd1ff", live="#45e08f", bad="#ff6b6b", glow=".2"),
    "light": dict(bg="#ebe2cc", bg2="#e2d6ba", panel="#f8f1e1", line="#cdbd98", line2="#b4a07a", fg="#231a11",
                  muted="#6a5842", accent="#d24f1b", ai="#16766f", live="#3d7a1f", bad="#b3261e", glow=".14"),
}
DISPLAY = "'Chakra Petch','Segoe UI',Helvetica,Arial,sans-serif"
BODY = "'IBM Plex Sans','Segoe UI',Helvetica,Arial,sans-serif"
MONO = "'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"


def banner(t):
    w, h = 1280, 260
    # a heartbeat line that flat-lines (DOWN), then recovers after the diagnosis
    pts = []
    x = 760
    for seg in ["f", "b", "f", "b", "f", "d", "d", "d", "f", "b", "f", "b"]:
        if seg == "f":
            pts += [(x, 130), (x + 30, 130)]
            x += 30
        elif seg == "b":
            pts += [(x, 130), (x + 8, 100), (x + 16, 165), (x + 24, 118), (x + 32, 130)]
            x += 32
        else:
            pts += [(x, 130), (x + 40, 130)]
            x += 40
    d = "M" + " L".join(f"{a},{b}" for a, b in pts)
    length = int((x - 760) * 1.7)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="diag-agent: a home server that diagnoses its own outages">
<defs><clipPath id="c"><rect width="{w}" height="{h}" rx="20"/></clipPath>
<radialGradient id="g" cx="80%" cy="45%" r="55%"><stop offset="0" stop-color="{t["accent"]}" stop-opacity="{t["glow"]}"/><stop offset="1" stop-color="{t["accent"]}" stop-opacity="0"/></radialGradient>
<pattern id="dots" width="20" height="20" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="{t["line"]}"/></pattern></defs>
<g clip-path="url(#c)">
<rect width="{w}" height="{h}" fill="{t["bg"]}"/><rect width="{w}" height="{h}" fill="url(#dots)"/><rect width="{w}" height="{h}" fill="url(#g)"/>
<text x="60" y="74" font-family="{MONO}" font-size="13" letter-spacing="3" fill="{t["accent"]}">// SELF-DIAGNOSING HOME SERVER</text>
<text x="58" y="138" font-family="{DISPLAY}" font-size="64" font-weight="700" fill="{t["fg"]}">diag-agent</text>
<text x="60" y="180" font-family="{BODY}" font-size="21" fill="{t["fg"]}">Alert → read-only evidence → redaction → LLM with no tools</text>
<text x="60" y="210" font-family="{BODY}" font-size="21" fill="{t["accent"]}">→ one message with the cause and the fix. Never runs anything.</text>
<path d="{d}" fill="none" stroke="{t["live"]}" stroke-width="3" stroke-linejoin="round" stroke-dasharray="{length}" stroke-dashoffset="{length}">
<animate attributeName="stroke-dashoffset" values="{length};0;0" keyTimes="0;.6;1" dur="6s" repeatCount="indefinite"/></path>
<rect x="{760 + 30 * 3 + 32 * 2}" y="92" width="120" height="76" rx="8" fill="{t["bad"]}" opacity=".10"/>
<text x="{760 + 30 * 3 + 32 * 2 + 60}" y="86" text-anchor="middle" font-family="{MONO}" font-size="12" letter-spacing="2" fill="{t["bad"]}">DOWN</text>
<g font-family="{MONO}" font-size="12" letter-spacing="1.5" fill="{t["muted"]}">
<text x="{760 + 30 * 3 + 32 * 2 + 60}" y="196" text-anchor="middle">DIAGNOSED</text>
<text x="{x - 30}" y="196" text-anchor="middle" fill="{t["live"]}">UP</text></g>
<rect x=".75" y=".75" width="{w - 1.5}" height="{h - 1.5}" rx="19.5" fill="none" stroke="{t["line2"]}" stroke-width="1.5"/>
</g></svg>'''


STAGES = [
    ("Uptime Kuma", "monitor DOWN", "muted"),
    ("Re-check", "120 s · rate limits", "muted"),
    ("Collector", "root · fixed whitelist", "accent"),
    ("Redaction", "keys · mails · blobs", "accent"),
    ("LLM analyst", "no tools · JSON schema", "ai"),
    ("Validation", "command blocklist", "ai"),
    ("Report", "page + 1 notification", "live"),
]


def pipeline(t):
    w, h = 1280, 250
    n = len(STAGES)
    bw, gap, y = 158, 22, 70
    x0 = (w - (n * bw + (n - 1) * gap)) / 2
    parts, path = [], []
    for i, (title, sub, col) in enumerate(STAGES):
        x = x0 + i * (bw + gap)
        parts.append(f'<rect x="{x:.0f}" y="{y}" width="{bw}" height="92" rx="14" fill="{t["panel"]}" stroke="{t[col] if col != "muted" else t["line2"]}" stroke-width="1.6"/>'
                     f'<text x="{x + 16:.0f}" y="{y + 26}" font-family="{MONO}" font-size="11" letter-spacing="1.5" fill="{t[col]}">{i + 1:02d}</text>'
                     f'<text x="{x + 16:.0f}" y="{y + 54}" font-family="{DISPLAY}" font-size="18" font-weight="700" fill="{t["fg"]}">{E(title)}</text>'
                     f'<text x="{x + 16:.0f}" y="{y + 76}" font-family="{BODY}" font-size="12.5" fill="{t["muted"]}">{E(sub)}</text>')
        if i < n - 1:
            ax = x + bw
            parts.append(f'<path d="M{ax + 3:.0f},{y + 46} L{ax + gap - 5:.0f},{y + 46}" stroke="{t["line2"]}" stroke-width="2"/>'
                         f'<path d="M{ax + gap - 9:.0f},{y + 41} L{ax + gap - 3:.0f},{y + 46} L{ax + gap - 9:.0f},{y + 51}" fill="none" stroke="{t["line2"]}" stroke-width="2"/>')
    path = f"M{x0 + 10:.0f},{y + 101} L{x0 + n * bw + (n - 1) * gap - 10:.0f},{y + 101}"
    # zones underneath
    def zone(i0, i1, label, col):
        a = x0 + i0 * (bw + gap)
        b = x0 + i1 * (bw + gap) + bw
        return (f'<path d="M{a:.0f},{y + 112} L{a:.0f},{y + 120} L{b:.0f},{y + 120} L{b:.0f},{y + 112}" fill="none" stroke="{t[col]}" stroke-width="1.5"/>'
                f'<text x="{(a + b) / 2:.0f}" y="{y + 142}" text-anchor="middle" font-family="{MONO}" font-size="11.5" letter-spacing="1.5" fill="{t[col]}">{E(label)}</text>')
    parts.append(zone(0, 1, "TRIGGER · FLAPS IGNORED", "muted"))
    parts.append(zone(2, 3, "ROOT, READ-ONLY · NOTHING LEAVES UNREDACTED", "accent"))
    parts.append(zone(4, 5, "UNPRIVILEGED · UNTRUSTED OUTPUT", "ai"))
    parts.append(zone(6, 6, "HUMAN DECIDES", "live"))
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="Pipeline: Uptime Kuma DOWN, re-check, root collector with a fixed whitelist, redaction, LLM analyst with no tools, validation with a command blocklist, report page and one notification">
<rect x=".75" y=".75" width="{w - 1.5}" height="{h - 1.5}" rx="18" fill="{t["bg"]}" stroke="{t["line2"]}" stroke-width="1.5"/>
<text x="{x0:.0f}" y="44" font-family="{MONO}" font-size="12.5" letter-spacing="3" fill="{t["accent"]}">// HOW IT WORKS</text>
{"".join(parts)}
<circle r="6" fill="{t["accent"]}"><animateMotion dur="5s" repeatCount="indefinite" path="{path}"/>
<animate attributeName="fill" values="{t["muted"]};{t["accent"]};{t["accent"]};{t["ai"]};{t["live"]}" keyTimes="0;.25;.5;.7;1" dur="5s" repeatCount="indefinite"/></circle>
</svg>'''


def main():
    for m, t in THEMES.items():
        for name, fn in (("banner", banner), ("pipeline", pipeline)):
            with open(os.path.join(OUT, f"{name}-{m}.svg"), "w") as f:
                f.write(fn(t))
    print("ok")


if __name__ == "__main__":
    main()
