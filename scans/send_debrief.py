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


def inline_fmt(t):
    """Apply **bold** and `code` to an already-escaped text fragment."""
    t = html_escape(t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    return t


def md_to_html(md):
    """Convert a small subset of markdown to HTML: H1/H2/H3, lists, paragraphs, **bold**, `code`."""
    out = []
    in_list = False
    for raw in md.splitlines():
        line = raw.rstrip()
        if not line:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("")
            continue
        if line.startswith("# "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h1>{inline_fmt(line[2:])}</h1>")
            continue
        if line.startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h2>{inline_fmt(line[3:])}</h2>")
            continue
        if line.startswith("### "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h3>{inline_fmt(line[4:])}</h3>")
            continue
        if line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline_fmt(line[2:])}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        out.append(f"<p>{inline_fmt(line)}</p>")
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
    html = (
        '<!doctype html>\n'
        '<html><body style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', sans-serif; max-width: 720px; margin: 0 auto; padding: 20px; color: #222; line-height: 1.5">\n'
        + inner
        + '\n<hr style="margin-top: 32px; border: 0; border-top: 1px solid #ddd">\n'
        '<p style="font-size: 11px; color: #888">Sent by the Watchtower scheduled scan. To stop receiving these, remove the <code>emailDebrief</code> block from <code>watchtower.config.json</code>.</p>\n'
        '</body></html>'
    )

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
