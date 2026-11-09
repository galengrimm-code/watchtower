#!/usr/bin/env python3
"""Extract Active Flags and the Watch List from each project's scan blocks and write
scans/SLUG-DATE.json.

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

# v7.9 refutation marker written by the orchestrator's Phase B.65 at the start of a
# disputed Active Flags description: "DISPUTED: DOWNGRADE P3; owner review pending. ..."
DISPUTED_RE = re.compile(
    r'^DISPUTED:\s*(STANDS|DOWNGRADE|UNRESOLVED|REJECT)(?:\s+(P[1-4]))?\s*;\s*owner review pending\.?\s*'
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


def detect_scan_version():
    """First vN.N in the methodology prompt header, or None.

    Stamped into every result JSON so the artifact says which prompt produced it.
    Without it an integrity check cannot tell a current file from a stale one.
    """
    cfg = load_config()
    roots = []
    if cfg.get("promptsRoot"):
        roots.append(Path(cfg["promptsRoot"]) / "security-scan-prompt.md")
    roots.append(WATCHTOWER_ROOT / "prompts" / "security-scan-prompt.md")
    for path in roots:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            continue
        m = re.search(r"v\d+\.\d+", head)
        if m:
            return m.group(0)
    return None


_TAXONOMY = None


def taxonomy_keys():
    """Category keys from the prompt's CATEGORY TAXONOMY table (the single source of
    truth). Empty set if the prompt cannot be read -- legacy Watch List items then
    carry no category rather than a guessed one."""
    global _TAXONOMY
    if _TAXONOMY is None:
        _TAXONOMY = set()
        cfg = load_config()
        roots = []
        if cfg.get("promptsRoot"):
            roots.append(Path(cfg["promptsRoot"]) / "security-scan-prompt.md")
        roots.append(WATCHTOWER_ROOT / "prompts" / "security-scan-prompt.md")
        for path in roots:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            m = re.search(r'## CATEGORY TAXONOMY(.*?)(?=\n## )', text, re.DOTALL)
            if m:
                _TAXONOMY = set(re.findall(r'^\|\s*`?([a-z0-9]+(?:-[a-z0-9]+)+)`?\s*\|', m.group(1), re.MULTILINE))
                break
        if not _TAXONOMY:
            print("WARN: could not read the CATEGORY TAXONOMY from the scan prompt; "
                  "legacy Watch List items will carry no category.", file=sys.stderr)
    return _TAXONOMY


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


def _read_block(path):
    """Return one file's SCAN:AUTO block inner text, or "" if the file or markers are absent."""
    path = Path(path)
    if not path.exists():
        return ""
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    m = re.search(r'<!-- SCAN:AUTO:START\b[^>]*-->(.*?)<!-- SCAN:AUTO:END\b', content, re.DOTALL)
    if not m:
        m = re.search(r'<!-- SCAN:AUTO:START[^>]*-->(.*?)<!-- SCAN:AUTO:END(?!\w)', content, re.DOTALL)
        if not m:
            return ""
    return m.group(1)


def read_scan_section(claude_md_path):
    """Return the project's scan output: CLAUDE.md's SCAN:AUTO block plus, from v7.8,
    the block in docs/security-scan.md (Security Notes, Deployed Surface, Strengths,
    Metrics moved there so they are not auto-loaded every session). A pre-v7.8 project
    has no companion file and everything is still in CLAUDE.md, so both layouts parse."""
    claude_md_path = Path(claude_md_path)
    companion = claude_md_path.parent / "docs" / "security-scan.md"
    return _read_block(claude_md_path) + "\n" + _read_block(companion)


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
    # Pre-template blocks store the same bold-labeled bullets inline (no
    # "## Metrics" heading) — fall back to the whole SCAN:AUTO block so those
    # projects still participate in the metrics-refresh path.
    section = m.group(1) if m else scan_section
    tl = re.search(r'\*\*Total lines:\*\*\s*~?([\d,]+)', section)
    if not tl:
        return {}
    metrics = {"totalLines": int(tl.group(1).replace(',', ''))}
    for label, key in (("Components", "components"), ("Pages", "pages"), ("API routes", "apiRoutes")):
        cm = re.search(r'\*\*%s:\*\*([^|\n]*)' % re.escape(label), section)
        if cm:
            # Mixed-format counts ("2 Vercel serverless (...) + 10 Cloud Function
            # exports") sum every number OUTSIDE parentheses — parentheticals are
            # clarifications ("0 (client-side SDK; 9 Cloud Functions)" is 0).
            seg = re.sub(r'\([^)]*\)', ' ', cm.group(1))
            nums = [int(n.replace(',', '')) for n in re.findall(r'\d[\d,]*', seg)]
            if nums:
                metrics[key] = sum(nums)
    # Heading varies by scan era: "Files over 500 lines:" / "Files over 1500 lines (v6.8):".
    fo = re.search(r'\*\*Files over [\d,]+ lines[^:\n]*:\*\*\s*(.+)', section)
    if fo:
        val = fo.group(1).strip()
        # Filenames may or may not be backticked (older blocks use plain text),
        # and the size paren may carry an annotation ("(2,294 lines)",
        # "(867 — dead)") — count every number-leading paren on the line.
        counts = [int(n.replace(',', '')) for n in re.findall(r'\((\d[\d,]*)\b[^)]*\)', val)]
        if counts:
            metrics["filesOver500"] = sum(1 for n in counts if n > 1500)
        else:
            bare = re.match(r'~?(\d[\d,]*)\b', val)
            if bare and int(bare.group(1).replace(',', '')) == 0:
                # Bare 0 is threshold-independent: none over 500 implies none
                # over 1,500.
                metrics["filesOver500"] = 0
            elif re.search(r'none', val, re.I):
                metrics["filesOver500"] = 0
            # Nonzero count-only legacy lines ("Files over 500 lines: 26") are
            # 500-threshold counts that can't be converted without per-file line
            # counts — omit so phase_c_update preserves the existing value until
            # the block regenerates in the current format on its next scan.
    # v7.9 I21: "Coverage: methods 31/33 · server actions 4/4 · ..." -- kept as the
    # agent wrote it; the dashboard shows it verbatim next to the flag counts.
    cov = re.search(r'\*\*Coverage:\*\*\s*(.+)', section)
    if cov:
        val = cov.group(1).strip()
        if val and not val.startswith('{'):
            metrics["coverage"] = val[:600]
    return metrics


def parse_strengths(scan_section):
    """Extract the one-sentence "## Strengths" line (v7.0). Returns None when the
    section is absent (pre-v7.0 blocks) or holds only a placeholder."""
    m = re.search(r'## Strengths\s*\n+(?!#)(.+)', scan_section)
    if not m:
        return None
    line = re.sub(r'^[-*]\s+', '', m.group(1).strip())
    line = re.sub(r'\*\*([^*]+)\*\*', r'\1', line).strip('_ ')
    # An empty section would otherwise capture the next heading as "data".
    if not line or line.startswith(('{', '#')) or line.lower() in ('none', 'n/a'):
        return None
    return line


def parse_flags(scan_section):
    # Isolate the Active Flags section first, then find the table inside it. An agent may
    # legitimately place a provenance note between the heading and the table; requiring the
    # table to follow the heading immediately silently drops every flag in that project.
    sect_m = re.search(r'### Active Flags\b(.*?)(?=\n### |\n## |\Z)', scan_section, re.DOTALL)
    if not sect_m:
        return []
    af_m = re.search(r'\|[^\n]+\n\|[-| ]+\n((?:\|.*\n)*)', sect_m.group(1))
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
            # Store the description WHOLE. A 150-char cap silently truncated half
            # of every cycle's flags (median description is 151 chars) and cut them
            # exactly where the evidence lives -- one P2 read "proven live ..." with
            # the proof gone. The dashboard clamps for display; the data must not.
            # The 1000 is a runaway guard, not a display budget.
            if len(text) > 1000:
                text = text[:997] + "..."
            flag = {
                "text": text,
                "severity": severity,
                "category": category,
                "confidence": parse_confidence(confidence_raw),
            }
            # v7.9 Phase B.65: the orchestrator annotates a disputed row by prefixing
            # its description. The markdown stays the single source of truth; the
            # marker is lifted into a structured field so the dashboard can badge it.
            dm = DISPUTED_RE.match(text)
            if dm:
                flag["text"] = text[dm.end():].strip() or text
                flag["refutation"] = {"verdict": dm.group(1)}
                if dm.group(2):
                    flag["refutation"]["tier"] = dm.group(2)
            flags.append(flag)
    return flags


def _cell_text(cell):
    return re.sub(r'\*\*([^*]+)\*\*', r'\1', cell).replace('\\|', '|').strip()


def parse_watch_list(scan_section):
    """Parse '### Watch List' into a list of dicts (v7.9).

    Two formats. The v7.9 template is a table with a header row
    (Severity | Category | Confidence | Verdict | Description); columns are matched
    by header name, so order changes do not shift fields. Earlier scans wrote free-
    form bullets; each top-level bullet becomes one item marked format "legacy",
    with severity / category / confidence lifted only when the bullet states them.
    Nothing is dropped: an item the parser cannot structure still keeps its text.
    """
    sect_m = re.search(r'### Watch List[^\n]*\n(.*?)(?=\n### |\n## |\Z)', scan_section, re.DOTALL)
    if not sect_m:
        return []
    body = sect_m.group(1)
    items = []
    tm = re.search(r'^(\|[^\n]+)\n\|[-| :]+\n((?:\|.*\n?)*)', body, re.MULTILINE)
    if tm:
        header = [h.strip().lower() for h in re.split(r'(?<!\\)\|', tm.group(1).strip().strip('|'))]
        for row in tm.group(2).splitlines():
            cells = [c.strip() for c in re.split(r'(?<!\\)\|', row.strip().strip('|'))]
            if len(cells) < len(header):
                continue
            rec = dict(zip(header, cells))
            sev = rec.get("severity", "").strip()
            if not re.fullmatch(r'P[1-4]', sev):
                continue
            text = _cell_text(rec.get("description", ""))
            if len(text) > 1000:
                text = text[:997] + "..."
            item = {"text": text, "severity": sev,
                    "category": rec.get("category", "").strip('` ')}
            try:
                item["confidence"] = parse_confidence(rec.get("confidence", ""))
            except ValueError:
                pass
            verdict = rec.get("verdict", "").strip().upper()
            if verdict in ("CONFIRMED", "UNRESOLVED"):
                item["verdict"] = verdict
            bm = re.search(r'\bBlocker:\s*(.+)$', text)
            if bm:
                item["blocker"] = bm.group(1).strip()
            items.append(item)
        return items
    # Legacy bullets: one item per top-level bullet, continuation lines folded in.
    current = None
    for line in body.splitlines():
        if re.match(r'^[-*]\s+', line):
            if current is not None:
                items.append(current)
            current = line
        elif current is not None and line.strip() and not line.startswith('#'):
            current += " " + line.strip()
    if current is not None:
        items.append(current)
    out = []
    for raw in items:
        text = _cell_text(re.sub(r'^[-*]\s+', '', raw))
        if len(text) > 1000:
            text = text[:997] + "..."
        head = text[:160]
        item = {"text": text, "format": "legacy"}
        sm = re.search(r'\bP([1-4])\b', head)
        if sm:
            item["severity"] = "P" + sm.group(1)
        # Only a real taxonomy key counts. Prose is full of hyphenated words
        # ("re-verified", "owner-only", dates) that are not categories.
        for tok in re.findall(r'\b([a-z0-9]+(?:-[a-z0-9]+)+)\b', head):
            if tok in taxonomy_keys():
                item["category"] = tok
                break
        fm = re.search(r'\b(0\.\d+|1\.0)\b', head)
        if fm:
            item["confidence"] = float(fm.group(1))
        out.append(item)
    return out


def main():
    parser = argparse.ArgumentParser(description="Write per-project scan JSONs.")
    parser.add_argument("--date", default=None, help="Scan date (YYYY-MM-DD). Defaults to today (UTC).")
    parser.add_argument("--slug", default=None,
                        help="Only write the JSON for this project slug. Omit to write all "
                             "config.projects (the default for a full scheduled scan). Use for "
                             "on-demand single-project rescans so you don't restamp every other "
                             "project's JSON with today's date from possibly-stale CLAUDE.md blocks. "
                             "Requires an explicit --date (see below).")
    parser.add_argument("--include-archived", action="store_true",
                        help="Also write JSONs for projects whose category is 'Archived'. OFF by "
                             "default: Phase B does not re-scan Archived projects, so their "
                             "CLAUDE.md blocks are from a PRIOR cycle. Writing them stamps stale "
                             "findings with today's date and the dashboard then presents last "
                             "cycle's posture as current — a silent false-freshness bug that a "
                             "2026-08-29 run had to clean up by hand.")
    args = parser.parse_args()

    # A single-slug rescan must land inside an EXISTING scan cycle, not mint a new
    # one. The stats pipeline groups scans/*-<date>.json by date: generate-portfolio-
    # stats.js counts each date as a cycle (projects++ per file) and compute-cycle-
    # stats.js picks the newest prior date as the baseline. A lone --slug write
    # stamped with today's date would read as a 1-project cycle — skewing burndown
    # and shifting the next debrief's baseline. Force the caller to name the cycle.
    if args.slug and not args.date:
        sys.exit(
            "ERROR: --slug requires an explicit --date so the single-project JSON joins the "
            "current scan cycle instead of creating a fake 1-project one. Pass the date of the "
            "cycle you're refreshing, e.g. --date <last-full-scan-date>."
        )

    scan_date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    config = load_config()
    portfolio_root = Path(config["portfolioRoot"])
    projects = config["projects"]
    if args.slug:
        # Enforce "join an EXISTING cycle", not just "a date was supplied": there
        # must already be at least one OTHER project's scan JSON dated <scan_date>.
        # A full scan writes every project's JSON for the cycle date first; a
        # single-slug rescan then joins that date. If no sibling file exists, the
        # lone --slug write would be the only file dated <scan_date> and the stats
        # pipeline (generate-portfolio-stats.js / compute-cycle-stats.js) would read
        # it as a fake 1-project cycle — the exact thing this guard prevents.
        siblings = [p for p in SCANS_DIR.glob(f"*-{scan_date}.json")
                    if p.name != f"{args.slug}-{scan_date}.json"]
        if not siblings:
            sys.exit(
                f"ERROR: --slug rescan must join an existing cycle, but no other "
                f"scans/*-{scan_date}.json exists for {scan_date}. Pass the date of a "
                f"completed full scan so the single-project file lands inside that cycle "
                f"instead of minting a fake 1-project one."
            )
        projects = [p for p in projects if p["slug"] == args.slug]
        if not projects:
            sys.exit(f"ERROR: --slug '{args.slug}' matched no project in watchtower.config.json")

    if not args.include_archived:
        archived = [p for p in projects if p.get("category") == "Archived"]
        if args.slug and archived:
            sys.exit(
                f"ERROR: --slug '{args.slug}' is an Archived project. Archived projects are not "
                f"re-scanned, so its CLAUDE.md block is from a prior cycle and writing it would "
                f"stamp stale findings with {scan_date}. Pass --include-archived if that is "
                f"genuinely what you want."
            )
        if archived:
            print(f"SKIP {len(archived)} Archived project(s): "
                  f"{', '.join(p['slug'] for p in archived)}")
        projects = [p for p in projects if p.get("category") != "Archived"]

    scan_version = detect_scan_version()
    if scan_version is None:
        print("WARN: could not read a version from the scan prompt; scanVersion will be null.")

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
            "slug": slug,
            "category": proj.get("category"),
            "directory": folder,
            "scanDate": scan_date,
            "scanVersion": scan_version,
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
        strengths = parse_strengths(scan_section)
        if strengths:
            out["strengths"] = strengths
        for f in flags:
            out["flagCount"][f["severity"]] += 1
        # v7.9: the Watch List is its own lane. It never feeds flagCount, grades or
        # stats -- those describe confirmed, Active findings only.
        out["watchList"] = parse_watch_list(scan_section)
        filename = f"{slug}-{scan_date}.json"
        filepath = SCANS_DIR / filename
        with open(filepath, "w", encoding="utf-8") as fp:
            json.dump(out, fp, indent=2)
        written.append(filename)
        print(f"  {filename}  ({len(flags)} flags: P1={out['flagCount']['P1']} P2={out['flagCount']['P2']} P3={out['flagCount']['P3']} P4={out['flagCount']['P4']}; watch list {len(out['watchList'])})")

    print(f"\nWrote {len(written)} scan files.")
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
