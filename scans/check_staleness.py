#!/usr/bin/env python3
"""check_staleness.py -- is the scan cycle still running?

Runs OUTSIDE the scan, on its own schedule. A liveness signal that lives inside
the thing it monitors stops when that thing stops (LESSONS N35): on 2026-11-09 the
scheduled scan was found disabled with no next run, and nothing said so. The
dashboard's "Updated" date could not say so either -- it takes the newest date
across all apps, so one fresh one-off scan makes the whole portfolio look current.

A "full cycle" is a date on which at least half the active (non-Archived)
projects have a scans/<slug>-<date>.json. One-off rescans join an existing
cycle's date (write_scan_jsons.py --slug enforces that), so they never count as
a new cycle here.

Stale = the newest full cycle is older than scanCadenceDays (watchtower.config.json)
plus a grace period.

Usage:
  python scans/check_staleness.py            # print status; exit 1 when stale
  python scans/check_staleness.py --email    # also email the owner when stale
  python scans/check_staleness.py --email --dry-run   # show the email, send nothing

Exit codes: 0 fresh, 1 stale, 2 no full cycle found / config error.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

WATCHTOWER_ROOT = Path(__file__).resolve().parent.parent
SCANS_DIR = WATCHTOWER_ROOT / "scans"
CONFIG_PATH = WATCHTOWER_ROOT / "watchtower.config.json"
GRACE_DAYS = 3
SCAN_FILE = re.compile(r"^(?P<slug>.+)-(?P<date>\d{4}-\d{2}-\d{2})\.json$")


def main():
    ap = argparse.ArgumentParser(description="Report whether the scan cycle has gone stale.")
    ap.add_argument("--email", action="store_true", help="Email the owner when stale (via send_debrief.py).")
    ap.add_argument("--dry-run", action="store_true", help="With --email: print the email instead of sending.")
    ap.add_argument("--today", default=None, help="Override today's date (YYYY-MM-DD), for testing.")
    args = ap.parse_args()

    if not CONFIG_PATH.exists():
        print(f"ERROR: {CONFIG_PATH} not found", file=sys.stderr)
        return 2
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    cadence = config.get("scanCadenceDays")
    if not isinstance(cadence, int) or cadence <= 0:
        print("ERROR: watchtower.config.json has no positive integer scanCadenceDays; "
              "it is the one place the cadence is declared.", file=sys.stderr)
        return 2
    today = date.fromisoformat(args.today) if args.today else date.today()

    active = {p["slug"]: p["displayName"] for p in config.get("projects", [])
              if p.get("category") != "Archived"}
    by_date = {}
    newest_per_slug = {}
    for f in SCANS_DIR.glob("*.json"):
        m = SCAN_FILE.match(f.name)
        if not m or m.group("slug") not in active:
            continue  # integrity-*, docs-freshness, semantic-candidates, archived apps
        d = m.group("date")
        by_date.setdefault(d, set()).add(m.group("slug"))
        if d > newest_per_slug.get(m.group("slug"), ""):
            newest_per_slug[m.group("slug")] = d

    threshold = max(1, (len(active) + 1) // 2)
    full = sorted(d for d, slugs in by_date.items() if len(slugs) >= threshold)
    if not full:
        print(f"STALE-UNKNOWN  no full scan cycle found (needs {threshold} of {len(active)} "
              f"active projects on one date)")
        return 2

    last = full[-1]
    age = (today - date.fromisoformat(last)).days
    limit = cadence + GRACE_DAYS
    never = sorted(active[s] for s in active if s not in newest_per_slug)
    oldest_slug = min(newest_per_slug, key=newest_per_slug.get) if newest_per_slug else None
    oldest_line = (f"oldest project scan: {active[oldest_slug]} on {newest_per_slug[oldest_slug]} "
                   f"({(today - date.fromisoformat(newest_per_slug[oldest_slug])).days} days)"
                   if oldest_slug else "")

    stale = age > limit
    status = "STALE" if stale else "FRESH"
    print(f"{status}  last full cycle {last} ({age} days ago; cadence {cadence} + {GRACE_DAYS} "
          f"grace = {limit}). {oldest_line}"
          + (f". Never scanned: {', '.join(never)}" if never else ""))

    if stale and args.email:
        body = (
            f"# The Watchtower scan cycle is overdue\n\n"
            f"- **Last full cycle:** {last}, {age} days ago.\n"
            f"- **Cadence:** every {cadence} days (`scanCadenceDays` in watchtower.config.json), "
            f"plus {GRACE_DAYS} days' grace.\n"
            + (f"- **{oldest_line[0].upper() + oldest_line[1:]}.**\n" if oldest_line else "")
            + (f"- **Never scanned:** {', '.join(never)}.\n" if never else "")
            + "\nCheck that the `weekly-security-scan` scheduled task is enabled, or run it now. "
              "Findings on the dashboard are no newer than the date above.\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
            tf.write(body)
            body_path = tf.name
        cmd = [sys.executable, str(SCANS_DIR / "send_debrief.py"),
               "--subject", f"Scan cycle overdue: last full cycle {last} ({age} days)",
               "--body-file", body_path]
        if args.dry_run:
            cmd.append("--dry-run")
        try:
            sent = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        finally:
            Path(body_path).unlink(missing_ok=True)
        print(sent.stdout.strip())
        if sent.returncode != 0:
            # A staleness alert that fails to send is itself a silent failure. Say so loudly.
            print(f"ERROR: staleness email was NOT sent (send_debrief exit {sent.returncode}): "
                  f"{sent.stderr.strip()[:300]}", file=sys.stderr)
            return 2

    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
