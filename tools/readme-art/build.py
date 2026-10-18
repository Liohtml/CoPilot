"""Build the README's animated SVGs (hero, how-it-works, quick start) in a dark and a light variant.

    python3 tools/readme-art/build.py

Writes docs/assets/readme/{hero,how-it-works,quickstart}-{dark,light}.svg. The animations are plain
CSS (no SMIL, no script, no web fonts), so they play wherever GitHub shows an SVG through an <img>,
and stop for viewers who ask for reduced motion.
"""

from __future__ import annotations

import html
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "assets" / "readme"
LOGO = ROOT / "frontend" / "src" / "assets" / "images" / "socfortress_logo_small_dark.svg"

FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"

# The frontend's own tokens (frontend/src/design-tokens.json).
THEMES = {
    "dark": {
        "bg": "#14161A",
        "surface": "#1D1F25",
        "surface2": "#26282D",
        "border": "#43444C",
        "text": "#FFFFFF",
        "text2": "#ACB5BE",
        "text3": "#747E88",
        "primary": "#FFB600",
        "info": "#6267FF",
        "success": "#00E19B",
        "pink": "#FF61C9",
        "error": "#FF0156",
        "grid": "#FFFFFF",
        "glow": 0.22,
    },
    "light": {
        "bg": "#FFFFFF",
        "surface": "#FFFFFF",
        "surface2": "#F0F2F4",
        "border": "#E2E6E9",
        "text": "#0B0D10",
        "text2": "#495465",
        "text3": "#727373",
        "primary": "#DB9D00",
        "info": "#6267FF",
        "success": "#00B27B",
        "pink": "#E0479E",
        "error": "#E00049",
        "grid": "#0B0D10",
        "glow": 0.16,
    },
}

REDUCED = "@media (prefers-reduced-motion: reduce) { * { animation: none !important; } .rm-hide { display: none; } }"


def esc(text: str) -> str:
    return html.escape(text, quote=True)


def logo_mark(x: float, y: float, height: float) -> str:
    """The SOCFortress castle mark (five filled paths), placed with its top-left at (x, y)."""
    src = LOGO.read_text()
    paths = "".join(re.findall(r"<path[^>]*/>", src))
    width = height * 400 / 497.1875
    return f'<svg x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height:.1f}" viewBox="0 0 400 497.1875">{paths}</svg>'


def svg_open(width: int, height: int, title: str, desc: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'role="img" aria-labelledby="t d" font-family="{FONT}">'
        f'<title id="t">{esc(title)}</title><desc id="d">{esc(desc)}</desc>'
    )


# --------------------------------------------------------------------------------------------- hero


SATELLITES = [
    ("Wazuh", "info"),
    ("Graylog", "pink"),
    ("Velociraptor", "success"),
    ("Grafana", "primary"),
    ("Shuffle", "info"),
    ("+ 30 more", "text3"),
]


def hero(theme: str) -> str:
    t = THEMES[theme]
    w, h = 1280, 400
    cx, cy = 960, 200
    rx, ry = 220, 136
    import math

    out = [
        svg_open(
            w,
            h,
            "SOCFortress CoPilot",
            "One console for your open-source SOC: alerts, cases, SLAs and a customer portal across Wazuh, Graylog, Velociraptor and 30+ integrations.",
        ),
    ]
    out.append(
        "<style>"
        ".flow{stroke-dasharray:3 9;animation:flow 1.6s linear infinite}"
        "@keyframes flow{to{stroke-dashoffset:-24}}"
        ".packet{stroke-dasharray:10 600;stroke-dashoffset:10;animation:packet 3.2s cubic-bezier(.45,0,.55,1) infinite}"
        "@keyframes packet{0%{stroke-dashoffset:10;opacity:0}8%{opacity:1}85%{opacity:1}100%{stroke-dashoffset:-260;opacity:0}}"
        ".float{animation:float 6s ease-in-out infinite}"
        "@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}"
        ".ring{transform-box:fill-box;transform-origin:center;animation:ring 3.2s ease-out infinite}"
        "@keyframes ring{0%{transform:scale(.85);opacity:.55}100%{transform:scale(1.55);opacity:0}}"
        ".blink{animation:blink 2.4s ease-in-out infinite}"
        "@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}"
        f"{REDUCED}"
        "</style>",
    )
    out.append(
        "<defs>"
        f'<radialGradient id="ga" cx="22%" cy="30%" r="45%"><stop offset="0" stop-color="{t["primary"]}" stop-opacity="{t["glow"]}"/><stop offset="1" stop-color="{t["primary"]}" stop-opacity="0"/></radialGradient>'
        f'<radialGradient id="gb" cx="76%" cy="50%" r="40%"><stop offset="0" stop-color="{t["info"]}" stop-opacity="{t["glow"] * 0.9:.2f}"/><stop offset="1" stop-color="{t["info"]}" stop-opacity="0"/></radialGradient>'
        f'<pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1" fill="{t["grid"]}" opacity="0.10"/></pattern>'
        '<linearGradient id="fade" x1="0" x2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset=".45" stop-color="#fff" stop-opacity=".9"/><stop offset="1" stop-color="#fff" stop-opacity="1"/></linearGradient>'
        '<mask id="m"><rect width="100%" height="100%" fill="url(#fade)"/></mask>'
        f'<linearGradient id="title" x1="0" x2="1"><stop offset="0" stop-color="{t["primary"]}"/><stop offset="1" stop-color="#FF7A1A"/></linearGradient>'
        '<filter id="soft" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3"/></filter>'
        f'<clipPath id="card"><rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="24"/></clipPath>'
        "</defs>",
    )
    out.append(f'<rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="24" fill="{t["bg"]}" stroke="{t["border"]}"/>')
    out.append('<g clip-path="url(#card)">')
    out.append(f'<rect width="{w}" height="{h}" fill="url(#ga)"/><rect width="{w}" height="{h}" fill="url(#gb)"/>')
    out.append(f'<rect width="{w}" height="{h}" fill="url(#dots)" mask="url(#m)"/>')

    # Left: the words.
    x0 = 72
    out.append(
        f'<g transform="translate({x0} 92)">'
        f'<rect width="236" height="30" rx="15" fill="{t["surface2"]}" stroke="{t["border"]}"/>'
        f'<circle class="blink" cx="17" cy="15" r="4.5" fill="{t["success"]}"/>'
        f'<text x="31" y="20" font-size="13" font-weight="600" fill="{t["text2"]}" letter-spacing=".3">Open source · Self-hosted</text>'
        "</g>",
    )
    out.append(f'<text x="{x0}" y="176" font-size="15" font-weight="700" letter-spacing="4" fill="{t["primary"]}">SOCFORTRESS</text>')
    out.append(
        f'<text x="{x0 - 3}" y="244" font-size="76" font-weight="800" letter-spacing="-2" fill="{t["text"]}">Co<tspan fill="url(#title)">Pilot</tspan></text>',
    )
    out.append(f'<text x="{x0}" y="290" font-size="24" font-weight="500" fill="{t["text2"]}">One console for your open-source SOC.</text>')
    chips = ["Alerts & cases", "SLAs", "Customer portal", "Response"]
    cx0 = x0
    for chip in chips:
        cw = 16 + len(chip) * 7.6
        out.append(
            f'<g transform="translate({cx0:.0f} 314)"><rect width="{cw:.0f}" height="28" rx="8" fill="{t["surface2"]}" stroke="{t["border"]}"/>'
            f'<text x="{cw / 2:.0f}" y="19" text-anchor="middle" font-size="13" font-weight="600" fill="{t["text2"]}">{esc(chip)}</text></g>',
        )
        cx0 += cw + 8

    # Right: the hub.
    angles = [-90, -30, 30, 90, 150, 210]
    centre_half = 66
    for i, ((label, colour), ang) in enumerate(zip(SATELLITES, angles)):
        a = math.radians(ang)
        sx, sy = cx + rx * math.cos(a), cy + ry * math.sin(a)
        # the line from the satellite to the edge of the centre card
        dx, dy = cx - sx, cy - sy
        dist = math.hypot(dx, dy)
        ex, ey = sx + dx * (1 - (centre_half + 6) / dist), sy + dy * (1 - (centre_half + 6) / dist)
        bx, by = sx + dx * (24 / dist), sy + dy * (24 / dist)
        c = t[colour]
        out.append(
            f'<path class="flow" d="M{bx:.1f} {by:.1f} L{ex:.1f} {ey:.1f}" stroke="{c}" stroke-opacity=".55" stroke-width="1.6" fill="none"/>',
        )
        delay = i * 0.53
        out.append(
            f'<path class="packet rm-hide" style="animation-delay:{delay:.2f}s" d="M{bx:.1f} {by:.1f} L{ex:.1f} {ey:.1f}" '
            f'stroke="{c}" stroke-width="4" stroke-linecap="round" fill="none"/>',
        )
    # centre card
    out.append(f'<circle class="ring" cx="{cx}" cy="{cy}" r="74" fill="none" stroke="{t["primary"]}" stroke-width="2"/>')
    out.append(
        f'<circle class="ring" style="animation-delay:1.6s" cx="{cx}" cy="{cy}" r="74" fill="none" stroke="{t["primary"]}" stroke-width="2"/>',
    )
    out.append(
        f'<rect x="{cx - centre_half}" y="{cy - centre_half}" width="{2 * centre_half}" height="{2 * centre_half}" rx="30" fill="{t["primary"]}" opacity=".35" filter="url(#soft)"/>',
    )
    out.append(
        f'<rect x="{cx - centre_half}" y="{cy - centre_half}" width="{2 * centre_half}" height="{2 * centre_half}" rx="30" fill="{t["surface"]}" stroke="{t["primary"]}" stroke-opacity=".8" stroke-width="1.5"/>',
    )
    out.append(logo_mark(cx - 30, cy - 46, 74))
    out.append(
        f'<text x="{cx}" y="{cy + 50}" text-anchor="middle" font-size="12" font-weight="700" letter-spacing="1.5" fill="{t["text2"]}">COPILOT</text>',
    )
    # satellites on top of the lines
    for i, ((label, colour), ang) in enumerate(zip(SATELLITES, angles)):
        a = math.radians(ang)
        sx, sy = cx + rx * math.cos(a), cy + ry * math.sin(a)
        pw = 30 + len(label) * 8.2
        c = t[colour]
        out.append(
            f'<g class="float" style="animation-delay:{-i * 0.9:.1f}s"><g transform="translate({sx - pw / 2:.1f} {sy - 19:.1f})">'
            f'<rect width="{pw:.0f}" height="38" rx="12" fill="{t["surface"]}" stroke="{t["border"]}"/>'
            f'<circle cx="17" cy="19" r="5" fill="{c}"/>'
            f'<text x="29" y="24" font-size="14" font-weight="600" fill="{t["text"]}">{esc(label)}</text></g></g>',
        )
    out.append("</g></svg>")
    return "".join(out)


# ------------------------------------------------------------------------------------ how it works


SOURCES = [
    ("Wazuh", "SIEM + XDR", "info"),
    ("Graylog", "log pipeline", "pink"),
    ("Velociraptor", "forensics + response", "success"),
    ("Grafana · InfluxDB", "dashboards + health", "primary"),
    ("Shuffle", "SOAR automation", "info"),
    ("EDR · cloud · email", "CrowdStrike, M365, AWS …", "pink"),
]

PEOPLE = [
    ("SOC analysts", "triage, investigate, respond", "Analyst console"),
    ("SOC leads", "SLAs, workload, quality", "SOC Management"),
    ("Your customers", "their alerts, cases, reports", "Customer portal"),
]

CAPABILITIES = [
    ("1", "Collect", "alerts from every tool, one format"),
    ("2", "Investigate", "cases, IoCs, AI analyst reports"),
    ("3", "Respond", "isolate hosts, run playbooks"),
    ("4", "Report", "SLAs, PDFs, customer views"),
]


def how_it_works(theme: str) -> str:
    t = THEMES[theme]
    w, h = 1280, 560
    out = [
        svg_open(
            w,
            h,
            "How CoPilot works",
            "Your security tools feed CoPilot; CoPilot gives analysts, SOC leads and your customers one place to work.",
        ),
    ]
    out.append(
        "<style>"
        ".flow{stroke-dasharray:4 8;animation:flow 1.4s linear infinite}"
        "@keyframes flow{to{stroke-dashoffset:-24}}"
        ".packet{stroke-dasharray:8 900;stroke-dashoffset:8;animation:packet 4s cubic-bezier(.45,0,.55,1) infinite}"
        "@keyframes packet{0%{stroke-dashoffset:8;opacity:0}6%{opacity:1}88%{opacity:1}100%{stroke-dashoffset:-330;opacity:0}}"
        ".hl{opacity:0;animation:hl 8s ease-in-out infinite}"
        "@keyframes hl{0%,25%,100%{opacity:0}5%,20%{opacity:1}}"
        f"{REDUCED}"
        "</style>",
    )
    out.append(
        "<defs>"
        f'<radialGradient id="g" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="{t["primary"]}" stop-opacity="{t["glow"]}"/><stop offset="1" stop-color="{t["primary"]}" stop-opacity="0"/></radialGradient>'
        '<filter id="soft" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="8"/></filter>'
        "</defs>",
    )
    out.append(f'<rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="24" fill="{t["bg"]}" stroke="{t["border"]}"/>')

    # column headers
    def header(x: float, text: str, anchor: str = "start") -> None:
        out.append(
            f'<text x="{x}" y="58" text-anchor="{anchor}" font-size="13" font-weight="700" letter-spacing="2.5" fill="{t["text3"]}">{esc(text)}</text>',
        )

    header(56, "YOUR SECURITY STACK")
    header(640, "COPILOT", "middle")
    header(w - 56, "YOUR PEOPLE", "end")

    # left: sources
    lx, lw, lh = 56, 300, 56
    ly0, lgap = 86, 74
    card_x, card_y, card_w, card_h = 450, 86, 380, 416
    for i, (name, sub, colour) in enumerate(SOURCES):
        y = ly0 + i * lgap
        c = t[colour]
        out.append(
            f'<g transform="translate({lx} {y})"><rect width="{lw}" height="{lh}" rx="14" fill="{t["surface"]}" stroke="{t["border"]}"/>'
            f'<rect x="14" y="14" width="28" height="28" rx="8" fill="{c}" opacity=".16"/><circle cx="28" cy="28" r="5" fill="{c}"/>'
            f'<text x="56" y="25" font-size="15" font-weight="700" fill="{t["text"]}">{esc(name)}</text>'
            f'<text x="56" y="43" font-size="12.5" fill="{t["text2"]}">{esc(sub)}</text></g>',
        )
        sx, sy = lx + lw, y + lh / 2
        tx, ty = card_x, card_y + 70 + i * (card_h - 140) / (len(SOURCES) - 1)
        d = f"M{sx} {sy:.1f} C{sx + 60} {sy:.1f} {tx - 60} {ty:.1f} {tx} {ty:.1f}"
        out.append(f'<path class="flow" d="{d}" fill="none" stroke="{c}" stroke-opacity=".45" stroke-width="1.6"/>')
        out.append(
            f'<path class="packet rm-hide" style="animation-delay:{i * 0.6:.1f}s" d="{d}" fill="none" stroke="{c}" stroke-width="4" stroke-linecap="round"/>',
        )

    # middle: the CoPilot card
    out.append(f'<rect x="{card_x - 40}" y="{card_y - 30}" width="{card_w + 80}" height="{card_h + 60}" fill="url(#g)"/>')
    out.append(
        f'<rect x="{card_x}" y="{card_y}" width="{card_w}" height="{card_h}" rx="22" fill="{t["primary"]}" opacity=".25" filter="url(#soft)"/>',
    )
    out.append(
        f'<rect x="{card_x}" y="{card_y}" width="{card_w}" height="{card_h}" rx="22" fill="{t["surface"]}" stroke="{t["primary"]}" stroke-opacity=".7" stroke-width="1.5"/>',
    )
    out.append(logo_mark(card_x + 28, card_y + 24, 44))
    out.append(f'<text x="{card_x + 72}" y="{card_y + 46}" font-size="22" font-weight="800" fill="{t["text"]}">CoPilot</text>')
    out.append(
        f'<text x="{card_x + 72}" y="{card_y + 66}" font-size="12.5" fill="{t["text2"]}">one console · one data model · multi-tenant</text>',
    )
    for i, (num, title, sub) in enumerate(CAPABILITIES):
        y = card_y + 96 + i * 70
        # one step lit at a time, in order; negative delays so every step is already on its cycle
        out.append(
            f'<g transform="translate({card_x + 24} {y})">'
            f'<rect width="{card_w - 48}" height="58" rx="14" fill="{t["surface2"]}" stroke="{t["border"]}"/>'
            f'<rect class="hl" style="animation-delay:-{(8 - 2 * i) % 8}s" width="{card_w - 48}" height="58" rx="14" '
            f'fill="{t["primary"]}" fill-opacity=".10" stroke="{t["primary"]}" stroke-opacity=".9" stroke-width="1.5"/>'
            f'<circle cx="29" cy="29" r="15" fill="{t["primary"]}"/>'
            f'<text x="29" y="34" text-anchor="middle" font-size="14" font-weight="800" fill="#14161A">{num}</text>'
            f'<text x="58" y="25" font-size="15.5" font-weight="700" fill="{t["text"]}">{esc(title)}</text>'
            f'<text x="58" y="44" font-size="12.5" fill="{t["text2"]}">{esc(sub)}</text></g>',
        )
    out.append(
        f'<text x="{card_x + card_w / 2}" y="{card_y + card_h - 20}" text-anchor="middle" font-size="12" font-weight="600" '
        f'letter-spacing=".5" fill="{t["text3"]}">Rust backend · MySQL · MinIO · Vue 3</text>',
    )

    # right: people
    rw, rh = 300, 108
    rx0 = w - 56 - rw
    ry0, rgap = 110, 134
    for i, (who, what, where) in enumerate(PEOPLE):
        y = ry0 + i * rgap
        out.append(
            f'<g transform="translate({rx0} {y})"><rect width="{rw}" height="{rh}" rx="16" fill="{t["surface"]}" stroke="{t["border"]}"/>'
            f'<text x="20" y="34" font-size="16" font-weight="700" fill="{t["text"]}">{esc(who)}</text>'
            f'<text x="20" y="55" font-size="12.5" fill="{t["text2"]}">{esc(what)}</text>'
            f'<rect x="20" y="70" width="{30 + len(where) * 7.6:.0f}" height="24" rx="7" fill="{t["primary"]}" opacity=".16"/>'
            f'<text x="30" y="87" font-size="12.5" font-weight="700" fill="{t["primary"]}">{esc(where)} →</text></g>',
        )
        sx, sy = card_x + card_w, card_y + 120 + i * (card_h - 240) / (len(PEOPLE) - 1)
        tx, ty = rx0, y + rh / 2
        d = f"M{sx} {sy:.1f} C{sx + 70} {sy:.1f} {tx - 70} {ty:.1f} {tx} {ty:.1f}"
        out.append(f'<path class="flow" d="{d}" fill="none" stroke="{t["primary"]}" stroke-opacity=".5" stroke-width="1.6"/>')
        out.append(
            f'<path class="packet rm-hide" style="animation-delay:{1.5 + i * 0.9:.1f}s" d="{d}" fill="none" stroke="{t["primary"]}" stroke-width="4" stroke-linecap="round"/>',
        )
    out.append("</svg>")
    return "".join(out)


# ---------------------------------------------------------------------------------- quick start


# (kind, text, start second, end second); "cmd" lines are typed, "out" lines appear.
TERMINAL = [
    ("cmd", "git clone https://github.com/socfortress/CoPilot.git && cd CoPilot", 0.4, 2.2),
    ("cmd", "cp .env.example .env          # set JWT_SECRET and the passwords", 2.7, 4.3),
    ("cmd", "docker compose up -d", 4.8, 5.6),
    ("ok", " ✔ Container copilot-mysql          Healthy", 6.3, 0),
    ("ok", " ✔ Container copilot-backend-init   Exited", 6.7, 0),
    ("ok", " ✔ Container copilot-backend        Healthy", 7.1, 0),
    ("ok", " ✔ Container copilot-frontend       Started", 7.5, 0),
    ("cmd", 'docker compose logs copilot-backend | grep "Admin user password"', 8.3, 10.0),
    ("out", " Admin user password: ●●●●●●●●●●●●●●●●", 10.5, 0),
    ("done", "→ open https://<your-host> and sign in as admin", 11.3, 0),
]
CYCLE = 16.0


def quickstart(theme: str) -> str:
    t = THEMES[theme]
    w, h = 960, 412
    term_bg = "#0F1115" if theme == "dark" else "#14161A"
    out = [
        svg_open(
            w,
            h,
            "CoPilot quick start",
            "git clone, cp .env.example .env, docker compose up -d, then read the admin password from the logs and open CoPilot in the browser.",
        ),
    ]
    styles = [
        ".cur{animation:cur 1s steps(1) infinite}@keyframes cur{50%{opacity:0}}",
    ]
    lh = 28
    top = 86
    left = 50
    char_w = 8.6  # 14.3 px monospace, approximately
    body = []
    for i, (kind, text, start, end) in enumerate(TERMINAL):
        y = top + i * lh
        appear = start / CYCLE * 100
        fade_out = (CYCLE - 0.7) / CYCLE * 100
        styles.append(
            f"@keyframes l{i}{{0%,{max(appear - 0.01, 0):.2f}%{{opacity:0}}{appear:.2f}%,{fade_out:.2f}%{{opacity:1}}100%{{opacity:0}}}}"
            f".l{i}{{animation:l{i} {CYCLE}s linear infinite}}",
        )
        if kind == "cmd":
            prompt = f'<tspan fill="{t["success"] if theme == "dark" else "#00E19B"}">❯ </tspan>'
            line = f'<text class="l{i}" x="{left}" y="{y}" font-family="{MONO}" font-size="14.3" fill="#E6E9EE" xml:space="preserve">{prompt}{esc(text)}</text>'
            body.append(line)
            # the cover slides right to "type" the command
            width = (len(text) + 2) * char_w + 12
            a = start / CYCLE * 100
            b = end / CYCLE * 100
            # steps() applies per keyframe segment, so the typing segment ticks once a character
            styles.append(
                f"@keyframes c{i}{{0%,{a:.2f}%{{transform:translateX(0)}}{b:.2f}%,100%{{transform:translateX({width:.0f}px)}}}}"
                f".c{i}{{animation:c{i} {CYCLE}s steps({len(text)}) infinite}}",
            )
            body.append(
                f'<rect class="c{i} rm-hide" x="{left + 2 * char_w:.0f}" y="{y - 18}" width="{width + 40:.0f}" height="{lh}" fill="{term_bg}"/>',
            )
        else:
            colour = {"ok": "#00E19B", "out": "#ACB5BE", "done": "#FFB600"}[kind]
            weight = "700" if kind == "done" else "400"
            body.append(
                f'<text class="l{i}" x="{left}" y="{y}" font-family="{MONO}" font-size="14.3" font-weight="{weight}" fill="{colour}" xml:space="preserve">{esc(text)}</text>',
            )
    styles.append(REDUCED)
    out.append("<style>" + "".join(styles) + "</style>")
    out.append(
        '<defs><filter id="sh" x="-10%" y="-10%" width="120%" height="140%"><feDropShadow dx="0" dy="14" stdDeviation="16" flood-opacity=".28"/></filter></defs>',
    )
    # the shadow on its own rect: a filtered fill drifts in colour, and the typing covers must match the fill exactly
    out.append(f'<rect x="24" y="16" width="{w - 48}" height="{h - 40}" rx="16" fill="{term_bg}" filter="url(#sh)"/>')
    out.append(f'<rect x="24" y="16" width="{w - 48}" height="{h - 40}" rx="16" fill="{term_bg}" stroke="{THEMES["dark"]["border"]}"/>')
    out.append(f'<path d="M24 32 a16 16 0 0 1 16 -16 H{w - 40} a16 16 0 0 1 16 16 V52 H24 Z" fill="#1D1F25"/>')
    for j, colour in enumerate(["#FF5F57", "#FEBC2E", "#28C840"]):
        out.append(f'<circle cx="{48 + j * 20}" cy="34" r="6" fill="{colour}"/>')
    out.append(
        f'<text x="{w / 2}" y="39" text-anchor="middle" font-family="{MONO}" font-size="12.5" fill="#747E88">~/CoPilot — bash</text>',
    )
    # the final prompt, its cursor blinking
    y = top + len(TERMINAL) * lh
    appear = 12.1 / CYCLE * 100
    fade_out = (CYCLE - 0.7) / CYCLE * 100
    styles_tail = (
        f"@keyframes lp{{0%,{appear - 0.01:.2f}%{{opacity:0}}{appear:.2f}%,{fade_out:.2f}%{{opacity:1}}100%{{opacity:0}}}}"
        f".lp{{animation:lp {CYCLE}s linear infinite}}"
    )
    out.append(f"<style>{styles_tail}{REDUCED}</style>")
    body.append(
        f'<g class="lp"><text x="{left}" y="{y}" font-family="{MONO}" font-size="14.3" fill="#00E19B">❯</text>'
        f'<rect class="cur" x="{left + 2 * char_w:.0f}" y="{y - 14}" width="9" height="18" fill="#E6E9EE"/></g>',
    )
    out.append('<defs><clipPath id="screen"><rect x="25" y="52" width="{}" height="{}" rx="0"/></clipPath></defs>'.format(w - 50, h - 77))
    out.append('<g clip-path="url(#screen)">' + "".join(body) + "</g>")
    out.append("</svg>")
    return "".join(out)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for theme in THEMES:
        (OUT / f"hero-{theme}.svg").write_text(hero(theme) + "\n")
        (OUT / f"how-it-works-{theme}.svg").write_text(how_it_works(theme) + "\n")
        (OUT / f"quickstart-{theme}.svg").write_text(quickstart(theme) + "\n")
    for p in sorted(OUT.glob("*.svg")):
        print(f"{p.relative_to(ROOT)}  {p.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
