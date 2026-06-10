#!/usr/bin/env python3
"""Extract active flags from each project's CLAUDE.md and write scans/SLUG-DATE.json.

Reads watchtower.config.json for portfolioRoot + projects list. Scan date defaults
to today (UTC) unless overridden by --date YYYY-MM-DD.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

WATCHTOWER_ROOT = Path(__file__).resolve().parent.parent
SCANS_DIR = WATCHTOWER_ROOT / "scans"
CONFIG_PATH = WATCHTOWER_ROOT / "watchtower.config.json"

TABLE_ROW = re.compile(
    r'\|\s*(P[1-4])\s*\|\s*([\w-]+)\s*\|\s*([\d.]+%?)\s*\|\s*(.+?)\s*\|'
)

# CLAUDE.md "## Tech Stack" table Layer labels -> apps.js tech object keys
# (the keys phase_c_update.py's js_tech() consumes).
TECH_LAYER_MAP = {
    "frontend": "frontend",
    "backend": "backend",
    "data": "dataStorage",
    "datastorage": "dataStorage",
    "integrations": "integrations",
    "auth": "auth",
    "testing": "testing",
    "hosting": "hosting",
}


def load_config():
    if not CONFIG_PATH.exists():
        sys.exit(f"ERROR: {CONFIG_PATH} not found. Copy watchtower.config.example.json and edit.")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_confidence(raw):
    raw = raw.strip()
    if raw.endswith('%'):
        return round(float(raw[:-1]) / 100, 2)
    return float(raw)


def read_scan_section(claude_md_path):
    """Return the SCAN:AUTO block's inner text, or "" if the markers are absent."""
    with open(claude_md_path, 'r', encoding='utf-8') as f:
        content = f.read()
    m = re.search(r'<!-- SCAN:AUTO:START\b[^>]*-->(.*?)<!-- SCAN:AUTO:END\b', content, re.DOTALL)
    if not m:
        m = re.search(r'<!-- SCAN:AUTO:START[^>]*-->(.*?)<!-- SCAN:AUTO:END(?!\w)', content, re.DOTALL)
        if not m:
            return ""
    return m.group(1)


def parse_tech(scan_section):
    """Parse the "## Tech Stack" Layer/Tech table into apps.js tech keys."""
    m = re.search(r'## Tech Stack\s*\n+\|[^\n]+\n\|[-| :]+\n((?:\|.*\n)*)', scan_section)
    if not m:
        return {}
    tech = {}
    for row in m.group(1).splitlines():
        cells = [c.strip() for c in re.split(r'(?<!\\)\|', row.strip().strip('|'))]
        if len(cells) < 2:
            continue
        key = TECH_LAYER_MAP.get(re.sub(r'[^a-z]', '', cells[0].lower()))
        value = re.sub(r'\*\*([^*]+)\*\*', r'\1', cells[1]).replace('\\|', '|').strip()
        # _None_ / *None* emphasis -> None. Explicit "None" is kept — it's data
        # (e.g. Auth | None drives the dashboard's no-auth classification), not
        # an empty cell. Only truly empty/dash cells are dropped.
        value = value.strip('_*').strip()
        if key and value.strip('-— '):
            tech[key] = value
    return tech


def parse_prod_url(scan_section):
    """Extract the Production URL line. Returns None when absent or not deployed."""
    for m in re.finditer(r'Production URL[:*\s]+(\S+)', scan_section):
        url = m.group(1).strip('`').rstrip('.,;)')
        if url.startswith('http'):
            return url
    return None


def parse_metrics(scan_section):
    """Parse the "## Metrics" bullet list into an apps.js metrics dict.

    Returns {} when the section or its Total lines bullet is absent (pre-template
    SCAN:AUTO blocks), so the merge step leaves any existing metrics untouched.
    filesOver500 keeps its legacy key name but counts files over the v6.8
    1,500-line threshold — listed files at or under 1,500 (e.g. the "Largest:"
    examples in a "_None over the threshold_" line) are excluded, which also
    converts pre-v6.8 500-threshold lists to the current semantics.
    """
    m = re.search(r'## Metrics\s*\n(.*?)(?=\n## |\Z)', scan_section, re.DOTALL)
    if not m:
        return {}
    section = m.group(1)
    tl = re.search(r'\*\*Total lines:\*\*\s*~?([\d,]+)', section)
    if not tl:
        return {}
    metrics = {"totalLines": int(tl.group(1).replace(',', ''))}
    for label, key in (("Components", "components"), ("Pages", "pages"), ("API routes", "apiRoutes")):
        cm = re.search(r'\*\*%s:\*\*\s*~?([\d,]+)' % re.escape(label), section)
        if cm:
            metrics[key] = int(cm.group(1).replace(',', ''))
    fo = re.search(r'\*\*Files over [\d,]+ lines:\*\*\s*(.+)', section)
    if fo:
        # Filenames may or may not be backticked (older blocks use plain text),
        # so count every "(N)" line-count on the line, not just backticked ones.
        counts = [int(n.replace(',', '')) for n in re.findall(r'\((\d[\d,]*)\)', fo.group(1))]
        metrics["filesOver500"] = sum(1 for n in counts if n > 1500)
    return metrics


def parse_flags(scan_section):
    af_m = re.search(r'### Active Flags\s*\|[^\n]+\n\|[-| ]+\n((?:\|.*\n)*)', scan_section)
    if not af_m:
        return []
    flags = []
    for row in af_m.group(1).splitlines():
        rm = TABLE_ROW.match(row)
        if rm:
            severity, category, confidence_raw, description = rm.groups()
            text = re.sub(r'\*\*([^*]+)\*\*', r'\1', description).strip()
            text = re.split(r'\s+—\s+(?:Fix|Run|Replace|Add|Change|Rotate|Do NOT)', text)[0]
            text = re.split(r'\.\s+Fix:', text)[0]
            if len(text) > 150:
                text = text[:147] + "..."
            flags.append({
                "text": text,
                "severity": severity,
                "category": category,
                "confidence": parse_confidence(confidence_raw),
            })
    return flags


def main():
    parser = argparse.ArgumentParser(description="Write per-project scan JSONs.")
    parser.add_argument("--date", default=None, help="Scan date (YYYY-MM-DD). Defaults to today (UTC).")
    args = parser.parse_args()

    scan_date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    config = load_config()
    portfolio_root = Path(config["portfolioRoot"])
    projects = config["projects"]

    written = []
    errors = []

    for proj in projects:
        folder = proj["folder"]
        slug = proj["slug"]
        display_name = proj["displayName"]
        claude_path = portfolio_root / folder / "CLAUDE.md"
        if not claude_path.exists():
            errors.append(f"NOT FOUND: {claude_path}")
            continue
        scan_section = read_scan_section(claude_path)
        flags = parse_flags(scan_section)
        out = {
            "app": display_name,
            "directory": folder,
            "scanDate": scan_date,
            "flagCount": {"P1": 0, "P2": 0, "P3": 0, "P4": 0},
            "flags": flags,
        }
        out.update(parse_tech(scan_section))
        url = parse_prod_url(scan_section)
        if url:
            out["url"] = url
        metrics = parse_metrics(scan_section)
        if metrics:
            out["metrics"] = metrics
        for f in flags:
            out["flagCount"][f["severity"]] += 1
        filename = f"{slug}-{scan_date}.json"
        filepath = SCANS_DIR / filename
        with open(filepath, "w", encoding="utf-8") as fp:
            json.dump(out, fp, indent=2)
        written.append(filename)
        print(f"  {filename}  ({len(flags)} flags: P1={out['flagCount']['P1']} P2={out['flagCount']['P2']} P3={out['flagCount']['P3']} P4={out['flagCount']['P4']})")

    print(f"\nWrote {len(written)} scan files.")
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
