#!/usr/bin/env python3
"""Send a Watchtower scan debrief email via Resend.

Reads `RESEND_API_KEY` from the real environment or `~/.claude/.env`.
Reads `to` / `from` / `subjectPrefix` from `config.emailDebrief` in
`watchtower.config.json`.

Body is markdown, supplied via `--body-file` or stdin. Converted to minimal
HTML (headings, bold, inline code, lists, paragraphs) — good enough for a
debrief, not a full markdown engine.

Exit codes:
  0 — email sent
  1 — error (network, auth, malformed payload)
  2 — skipped intentionally (no config, no API key)
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Force UTF-8 for stdin/stdout/stderr. On Windows, Python defaults to cp1252
# which mangles em-dashes, emoji, and other non-ASCII bytes piped from Bash —
# the user sees mojibake like "â€"" instead of "—" in the rendered email.
for stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8")
    except (AttributeError, Exception):
        pass

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "watchtower.config.json"
ENV_PATH = Path.home() / ".claude" / ".env"


def load_resend_key():
    """Prefer the real environment; fall back to ~/.claude/.env. Never log the value."""
    key = os.environ.get("RESEND_API_KEY")
    if key:
        return key
    if ENV_PATH.exists():
        for raw in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("RESEND_API_KEY="):
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                if v:
                    return v
    return None


def html_escape(t):
    return (
        t.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


PALETTE = {
    "bg": "#f6f8fa",
    "card": "#ffffff",
    "text": "#1a1f2b",
    "muted": "#6b7280",
    "border": "#e5e9f0",
    "brand": "#5b9bd5",
    "brand_dark": "#1e3a5f",
    # Severity colors — soft pastel backgrounds for inline badges, darker for tiles.
    "p1_bg": "#fee2e2", "p1_text": "#991b1b", "p1_tile": "#dc2626",
    "p2_bg": "#fed7aa", "p2_text": "#9a3412", "p2_tile": "#ea580c",
    "p3_bg": "#fef3c7", "p3_text": "#92400e", "p3_tile": "#ca8a04",
    "p4_bg": "#e5e7eb", "p4_text": "#374151", "p4_tile": "#6b7280",
    # Section colors and matching emojis.
    "section_changed": "#5b9bd5",
    "section_stands":  "#8b5cf6",
    "section_address": "#dc2626",
    "section_good":    "#16a34a",
    "section_bad":     "#ea580c",
    "section_default": "#1a1f2b",
}


SECTION_META = [
    # (title-substring, color-key, emoji)
    ("what changed",              "section_changed", "🔄"),
    ("stands out",                "section_stands",  "✨"),
    ("needs to be addressed",     "section_address", "⚠️"),
    ("needs addressing",          "section_address", "⚠️"),
    ("what's good",               "section_good",    "✅"),
    ("whats good",                "section_good",    "✅"),
    ("what's bad",                "section_bad",     "🔴"),
    ("whats bad",                 "section_bad",     "🔴"),
]


def section_meta_for(title):
    """Return (color, emoji) for a section heading. Falls back to default + no emoji."""
    t = title.lower()
    for needle, color_key, emoji in SECTION_META:
        if needle in t:
            return PALETTE[color_key], emoji
    return PALETTE["section_default"], ""


def render_scoreboard(p1, p2, p3, p4):
    """Render a 4-tile severity scoreboard row. Counts are strings or ints."""
    def tile(label, count, bg):
        return (
            f'<td align="center" valign="middle" width="25%" '
            f'style="background: {bg}; color: #ffffff; padding: 16px 8px; '
            f'border-radius: 8px;">'
            f'<div style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace; '
            f'font-size: 28px; font-weight: 700; line-height: 1;">{count}</div>'
            f'<div style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace; '
            f'font-size: 10px; font-weight: 600; letter-spacing: 0.12em; '
            f'text-transform: uppercase; margin-top: 4px; opacity: 0.9;">{label}</div>'
            f'</td>'
        )
    return (
        '<table role="presentation" cellspacing="8" cellpadding="0" border="0" width="100%" '
        'style="margin: 20px 0 8px; border-collapse: separate;">'
        '<tr>'
        + tile("P1 Critical", p1, PALETTE["p1_tile"])
        + tile("P2 High",     p2, PALETTE["p2_tile"])
        + tile("P3 Medium",   p3, PALETTE["p3_tile"])
        + tile("P4 Low",      p4, PALETTE["p4_tile"])
        + '</tr></table>'
    )


def render_cta_button(url, label="View Dashboard →"):
    return (
        '<table role="presentation" cellspacing="0" cellpadding="0" border="0" '
        'style="margin: 20px 0;"><tr><td>'
        f'<a href="{html_escape(url)}" '
        f'style="display: inline-block; background: {PALETTE["brand_dark"]}; '
        f'color: #ffffff; padding: 12px 24px; border-radius: 8px; '
        f'text-decoration: none; font-weight: 600; font-size: 14px; '
        f'font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', sans-serif;">'
        f'{html_escape(label)}</a>'
        '</td></tr></table>'
    )


def badgeify_severity(html_fragment):
    """Replace bare P1/P2/P3/P4 tokens with styled severity pills.
    Matches whole-word P# only — won't touch P1234 or similar."""
    def repl(m):
        sev = m.group(0)
        sev_lower = sev.lower()
        bg = PALETTE[f"{sev_lower}_bg"]
        fg = PALETTE[f"{sev_lower}_text"]
        return (
            f'<span style="display: inline-block; padding: 2px 8px; '
            f'background: {bg}; color: {fg}; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; '
            f'font-size: 11px; font-weight: 600; border-radius: 4px; '
            f'letter-spacing: 0.04em;">{sev}</span>'
        )
    return re.sub(r"\bP[1-4]\b", repl, html_fragment)


def inline_fmt(t):
    """Apply markdown links, **bold**, `code`, and severity badges to a fragment.
    Escapes HTML, then re-injects styled markup. Markdown links and a small set of
    common HTML entities pass through so writers can use either form."""
    t = html_escape(t)
    # Markdown links: [text](url)  →  <a href="url">text</a>
    t = re.sub(
        r"\[([^\]]+)\]\(([^)\s]+)\)",
        lambda m: f'<a href="{m.group(2)}" style="color: {PALETTE["brand"]}; text-decoration: underline;">{m.group(1)}</a>',
        t,
    )
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(
        r"`([^`]+)`",
        r'<code style="background: #f1f5f9; color: #0f172a; padding: 1px 6px; '
        r'border-radius: 3px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; '
        r'font-size: 0.9em;">\1</code>',
        t,
    )
    # Allow a handful of safe HTML entities to pass through after html_escape.
    # html_escape turned `&` into `&amp;`, so e.g. `&middot;` became `&amp;middot;`.
    # Un-escape just the known-safe set so writers can use either Unicode or entities.
    for entity in ("middot", "mdash", "ndash", "hellip", "rarr", "larr", "uarr", "darr", "check", "times"):
        t = t.replace(f"&amp;{entity};", f"&{entity};")
    return badgeify_severity(t)


SCORE_RE = re.compile(
    r"^SCORE:\s*P1\s*=\s*(\d+)\s+P2\s*=\s*(\d+)\s+P3\s*=\s*(\d+)\s+P4\s*=\s*(\d+)\s*$",
    re.IGNORECASE,
)
DASHBOARD_RE = re.compile(r"^DASHBOARD:\s*(\S+)\s*$", re.IGNORECASE)


def md_to_html(md):
    """Convert markdown to richly-styled HTML.

    Recognized special lines:
      `SCORE: P1=N P2=N P3=N P4=N`  → colored severity scoreboard tiles
      `DASHBOARD: <url>`            → CTA button linking to the dashboard
      `## <Section title>`          → colored heading with auto-emoji
    """
    out = []
    in_list = False
    for raw in md.splitlines():
        line = raw.rstrip()
        if not line:
            if in_list:
                out.append("</ul>")
                in_list = False
            continue
        # Scoreboard tile bar (must appear before other line-pattern checks).
        m = SCORE_RE.match(line)
        if m:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(render_scoreboard(*m.groups()))
            continue
        # Dashboard CTA button.
        m = DASHBOARD_RE.match(line)
        if m:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(render_cta_button(m.group(1)))
            continue
        # Horizontal rule.
        if line.strip() == "---":
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(
                f'<hr style="border: 0; border-top: 1px solid {PALETTE["border"]}; '
                f'margin: 24px 0 16px;">'
            )
            continue
        if line.startswith("# "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(
                f'<h1 style="font-size: 24px; font-weight: 700; color: {PALETTE["text"]}; '
                f'margin: 0 0 6px; line-height: 1.25;">{inline_fmt(line[2:])}</h1>'
            )
            continue
        if line.startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            title = line[3:]
            color, emoji = section_meta_for(title)
            prefix = f"{emoji} " if emoji else ""
            out.append(
                f'<h2 style="font-size: 13px; font-weight: 700; color: {color}; '
                f'text-transform: uppercase; letter-spacing: 0.1em; margin: 28px 0 12px; '
                f'padding-bottom: 8px; border-bottom: 2px solid {color};">'
                f'<span style="font-size: 16px; vertical-align: -1px; margin-right: 4px;">{prefix.strip()}</span>'
                f'{inline_fmt(title)}</h2>'
            )
            continue
        if line.startswith("### "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(
                f'<h3 style="font-size: 13px; font-weight: 600; color: {PALETTE["text"]}; '
                f'margin: 18px 0 8px;">{inline_fmt(line[4:])}</h3>'
            )
            continue
        if line.startswith("- "):
            if not in_list:
                out.append(
                    '<ul style="margin: 8px 0; padding-left: 22px; '
                    'color: ' + PALETTE["text"] + '; line-height: 1.65;">'
                )
                in_list = True
            out.append(
                f'<li style="margin-bottom: 6px;">{inline_fmt(line[2:])}</li>'
            )
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        out.append(
            f'<p style="margin: 10px 0; color: {PALETTE["text"]}; line-height: 1.65;">'
            f'{inline_fmt(line)}</p>'
        )
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Send a Watchtower scan debrief via Resend.")
    parser.add_argument("--subject", required=True, help="Subject line. config.emailDebrief.subjectPrefix is prepended if set.")
    parser.add_argument("--body-file", help="Markdown body. Defaults to stdin.")
    parser.add_argument("--dry-run", action="store_true", help="Validate inputs and print payload; do not send.")
    args = parser.parse_args()

    if not CONFIG_PATH.exists():
        print(f"ERROR: {CONFIG_PATH} not found", file=sys.stderr)
        sys.exit(1)
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    cfg = config.get("emailDebrief")
    if not cfg:
        print("emailDebrief not configured in watchtower.config.json; skipping.")
        sys.exit(2)

    # Validate required fields up front. A misconfigured emailDebrief block should
    # produce a clear error, not an uncaught KeyError further down. Codex review
    # of the first version of this script flagged this as a P2 — fixed.
    missing = [k for k in ("to", "from") if not cfg.get(k)]
    if missing:
        print(
            f"ERROR: emailDebrief is missing required field(s): {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    api_key = load_resend_key()
    if not api_key and not args.dry_run:
        print("RESEND_API_KEY not in environment or ~/.claude/.env; skipping.")
        sys.exit(2)

    if args.body_file:
        md = Path(args.body_file).read_text(encoding="utf-8")
    else:
        md = sys.stdin.read()
    if not md.strip():
        print("ERROR: empty body", file=sys.stderr)
        sys.exit(1)

    subject = args.subject
    prefix = cfg.get("subjectPrefix")
    if prefix:
        subject = f"{prefix} {subject}"

    inner = md_to_html(md)
    html = f'''<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{html_escape(subject)}</title>
</head>
<body style="margin: 0; padding: 0; background: {PALETTE["bg"]}; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; color: {PALETTE["text"]}; -webkit-font-smoothing: antialiased;">
<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background: {PALETTE["bg"]}; padding: 32px 16px;">
  <tr>
    <td align="center">
      <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="640" style="max-width: 640px; width: 100%;">
        <!-- Brand stripe -->
        <tr>
          <td style="background: linear-gradient(90deg, {PALETTE["brand_dark"]} 0%, {PALETTE["brand"]} 100%); padding: 14px 28px; border-radius: 10px 10px 0 0;">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
              <tr>
                <td style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; font-weight: 700; letter-spacing: 0.16em; color: #ffffff; text-transform: uppercase;">
                  🛡️ Watchtower &middot; Portfolio Security Debrief
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <!-- Main card -->
        <tr>
          <td style="background: {PALETTE["card"]}; border: 1px solid {PALETTE["border"]}; border-top: 0; border-radius: 0 0 10px 10px; padding: 28px 32px 32px;">
            {inner}
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="padding: 18px 8px 0; font-size: 11px; color: {PALETTE["muted"]}; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; line-height: 1.6;">
            🤖 Sent by the Watchtower scheduled scan. To stop, remove the <code style="background: transparent; color: {PALETTE["muted"]};">emailDebrief</code> block from <code style="background: transparent; color: {PALETTE["muted"]};">watchtower.config.json</code>.
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>'''

    to_field = cfg["to"]
    if isinstance(to_field, str):
        to_field = [to_field]

    payload = {
        "from": cfg["from"],
        "to": to_field,
        "subject": subject,
        "html": html,
    }

    if args.dry_run:
        print("--- DRY RUN - would POST to https://api.resend.com/emails ---")
        # Print payload but redact 'html' length to keep stdout short
        preview = dict(payload)
        preview["html"] = f"<{len(html)} chars>"
        print(json.dumps(preview, indent=2))
        sys.exit(0)

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            # Resend's edge (Cloudflare) blocks the default Python-urllib UA
            # with error code 1010. Identify the client explicitly.
            "User-Agent": "Watchtower-PhaseE/1.0 (+https://github.com/galengrimm-code/watchtower)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            print(f"Sent. HTTP {resp.status} {body[:200]}")
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8")[:500] if hasattr(e, "read") else ""
        print(f"ERROR: Resend returned {e.code}: {msg}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
