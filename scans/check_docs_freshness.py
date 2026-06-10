#!/usr/bin/env python3
"""Deterministic docs-freshness auditor (v7.0 stale-docs check).

Code, not LLM judgment: validates hand-written doc CLAIMS against reality for
every project in watchtower.config.json. Four checks per project:

  1. Dev commands — backticked `npm run X` / `pnpm X` / `yarn X` in README.md
     and CLAUDE.md's hand-written half must exist in package.json scripts.
  2. Referenced paths — backticked repo-relative file paths in CLAUDE.md's
     hand-written half and TECH-DEBT.md's active section must exist on disk.
     (Prose, URLs, absolute paths, globs, and cross-repo refs are ignored.)
  3. Handoff freshness — SESSION-HANDOFF.md describes "current state"; it is
     stale by definition when commits exist after it AND it is 7+ days behind.
  4. Last reviewed — `Last reviewed: YYYY-MM-DD` lines older than 90 days.
     (Absence of the convention is NOT flagged.)

Output: report to stdout + scans/docs-freshness.json. With --merge, each
project with findings gets exactly ONE consolidated P4 `stale-docs` flag in
data/apps.js (replacing any prior active stale-docs flag; accepted/resolved
ones are left alone); projects with no findings get their active stale-docs
flag removed. apps.js is backed up and node --check validated, same contract
as phase_c_update.py. Every per-project failure fails open (skip + note).

Usage:
  python scans/check_docs_freshness.py            # report only
  python scans/check_docs_freshness.py --merge    # also update data/apps.js
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

WATCHTOWER_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = WATCHTOWER_ROOT / "watchtower.config.json"
APPS_JS = WATCHTOWER_ROOT / "data" / "apps.js"
OUT_JSON = WATCHTOWER_ROOT / "scans" / "docs-freshness.json"

HANDOFF_GRACE_DAYS = 7
LAST_REVIEWED_MAX_DAYS = 90

RUN_CMD = re.compile(r"`(?:npm run|pnpm(?: run)?|yarn(?: run)?)\s+([\w:-]+)`")
# Backticked repo-relative path: must contain a slash and end in a short
# extension. Excludes URLs, absolute/home/drive paths, globs, node_modules.
REL_PATH = re.compile(r"`([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.[A-Za-z]{1,5})`")
LAST_REVIEWED = re.compile(r"Last reviewed:\s*(\d{4}-\d{2}-\d{2})", re.I)
SCAN_AUTO_BLOCK = re.compile(r"<!-- SCAN:AUTO:START.*?SCAN:AUTO:END[^>]*-->", re.S)


def hand_written_half(claude_md_text):
    """CLAUDE.md content OUTSIDE the SCAN:AUTO markers (the half humans write)."""
    return SCAN_AUTO_BLOCK.sub("", claude_md_text)


def active_tech_debt(text):
    """TECH-DEBT.md content before any Resolved heading."""
    return re.split(r"^#+\s*Resolved\b", text, flags=re.M)[0]


def read(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "out", ".vercel", "coverage"}


def build_file_index(root):
    """Set of all repo-relative file paths (forward slashes), pruned."""
    index = set()
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            for entry in d.iterdir():
                if entry.is_dir():
                    if entry.name not in SKIP_DIRS:
                        stack.append(entry)
                else:
                    index.add(entry.relative_to(root).as_posix())
        except OSError:
            continue
    return index


def path_resolves(rel, root, file_index, extra_roots):
    """True if a doc-referenced path points at something real.

    Docs abbreviate ('settings/page.tsx' for 'app/settings/page.tsx'), point at
    sibling repos (Watch Tower's promptsRoot architecture), or mean ~/Downloads.
    A reference only counts as stale when NONE of these resolve it.
    """
    clean = re.sub(r"^\./", "", rel)  # strip a literal leading "./" only — .claude/ etc. keep their dot
    if (root / clean).exists():
        return True
    # Suffix match against the repo's real files (handles abbreviated paths)
    suffix = "/" + clean
    for f in file_index:
        if f == clean or f.endswith(suffix):
            return True
    # Cross-root: portfolio sibling repos, promptsRoot, home (Downloads refs)
    for er in extra_roots:
        if er and (er / clean).exists():
            return True
    return False


def check_project(root, today, extra_roots):
    findings = []

    claude_hand = hand_written_half(read(root / "CLAUDE.md"))
    readme = read(root / "README.md")
    tech_debt = active_tech_debt(read(root / "TECH-DEBT.md"))

    # 1) Dev commands vs package.json scripts
    pkg_path = root / "package.json"
    if pkg_path.exists():
        try:
            scripts = set((json.loads(read(pkg_path)).get("scripts") or {}).keys())
            claimed = set(RUN_CMD.findall(readme)) | set(RUN_CMD.findall(claude_hand))
            for cmd in sorted(claimed - scripts):
                findings.append(f"doc references `npm run {cmd}` but package.json has no such script")
        except (json.JSONDecodeError, OSError):
            pass

    # 2) Backticked repo-relative paths exist on disk.
    #    Skipped: lines that intentionally reference nonexistent files
    #    ("create X", "X is missing", "X was removed"), compound adjectives
    #    (`pages/index.jsx`-style), and machine-local gitignored dirs.
    INTENTIONAL = re.compile(
        r"\b(create|missing|deleted|removed|renamed|future|formerly|no longer|to be|will live)\b", re.I
    )
    file_index = None
    seen = set()
    for source_name, text in (("CLAUDE.md", claude_hand), ("TECH-DEBT.md", tech_debt)):
        for line in text.splitlines():
            if INTENTIONAL.search(line):
                continue
            for m in REL_PATH.finditer(line):
                rel = m.group(1)
                after = line[m.end():m.end() + 1]
                if after == "-":  # `path.tsx`-style adjective, not a reference
                    continue
                if rel in seen or rel.startswith(("http", "node_modules", ".vercel/", ".next/")) or "*" in rel:
                    continue
                seen.add(rel)
                if file_index is None:
                    file_index = build_file_index(root)
                if not path_resolves(rel, root, file_index, extra_roots):
                    findings.append(f"{source_name} references `{rel}` which no longer exists")

    # 3) SESSION-HANDOFF freshness vs commits. Deterministic across clones:
    #    use the file's last-COMMIT time, not filesystem mtime (a fresh clone
    #    gives every file today's mtime). Exception: when the handoff has
    #    uncommitted local modifications, mtime IS the truth — a just-updated,
    #    not-yet-committed handoff is fresh, not stale.
    handoff = root / "SESSION-HANDOFF.md"
    if handoff.exists():
        try:
            r = subprocess.run(
                ["git", "log", "-1", "--format=%ct"],
                cwd=root, capture_output=True, text=True, timeout=10,
            )
            newest = int(r.stdout.strip() or 0)
            rf = subprocess.run(
                ["git", "log", "-1", "--format=%ct", "--", "SESSION-HANDOFF.md"],
                cwd=root, capture_output=True, text=True, timeout=10,
            )
            handoff_ts = int(rf.stdout.strip() or 0)
            dirty = subprocess.run(
                ["git", "status", "--porcelain", "--", "SESSION-HANDOFF.md"],
                cwd=root, capture_output=True, text=True, timeout=10,
            )
            if dirty.stdout.strip():
                handoff_ts = max(handoff_ts, int(handoff.stat().st_mtime))
            behind_days = (newest - handoff_ts) / 86400
            if newest and handoff_ts and behind_days > HANDOFF_GRACE_DAYS:
                findings.append(
                    f"SESSION-HANDOFF.md is {behind_days:.0f} days behind the latest commit — it claims to describe current state"
                )
        except (OSError, ValueError, subprocess.SubprocessError):
            pass

    # 4) Last reviewed: dates older than the window
    for source_name, text in (("README.md", readme), ("CLAUDE.md", claude_hand), ("TECH-DEBT.md", tech_debt)):
        for d in LAST_REVIEWED.findall(text):
            try:
                age = (today - datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)).days
            except ValueError:
                continue
            if age > LAST_REVIEWED_MAX_DAYS:
                findings.append(f"{source_name} 'Last reviewed: {d}' is {age} days old")

    return findings


def merge_into_apps(results):
    """One consolidated active P4 stale-docs flag per project (or none)."""
    sys.path.insert(0, str(WATCHTOWER_ROOT / "scans"))
    import phase_c_update as pc

    content = APPS_JS.read_text(encoding="utf-8")
    backup = APPS_JS.with_suffix(".js.docsfresh.bak")
    backup.write_text(content, encoding="utf-8")

    changed = []
    for display_name, findings in results.items():
        block = pc.find_app_block(content, display_name)
        if block is None:
            continue
        start, end = block
        obj = content[start:end]

        # Drop any existing ACTIVE stale-docs flag line (accepted/resolved kept).
        new_obj = re.sub(
            r'\n\s*\{ text: "[^"]*", severity: "P\d", category: "stale-docs", confidence: [\d.]+ \},',
            "", obj,
        )
        if findings:
            text = "Stale docs: " + "; ".join(findings)
            text = text.replace('"', "'")
            if len(text) > 400:
                text = text[:397] + "..."
            flag_line = f'      {{ text: "{text}", severity: "P4", category: "stale-docs", confidence: 1.00 }},'
            idx = new_obj.find("flags: [")
            if idx != -1:
                insert_at = new_obj.index("\n", idx) + 1
                new_obj = new_obj[:insert_at] + flag_line + "\n" + new_obj[insert_at:]
        if new_obj != obj:
            content = content[:start] + new_obj + content[end:]
            changed.append(display_name)

    APPS_JS.write_text(content, encoding="utf-8")
    check = subprocess.run(["node", "--check", str(APPS_JS)], capture_output=True, text=True, shell=False)
    if check.returncode != 0:
        APPS_JS.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
        sys.exit(f"ERROR: merge produced invalid JS — backup restored.\n{check.stderr}")
    return changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--merge", action="store_true", help="Update data/apps.js stale-docs flags")
    args = parser.parse_args()

    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    portfolio_root = Path(config["portfolioRoot"])
    today = datetime.now(timezone.utc)
    extra_roots = []
    for p in (config.get("promptsRoot"), config.get("portfolioRoot")):
        if p:
            extra_roots.append(Path(p))
            extra_roots.append(Path(p).parent)  # "prompts/x.md" refs resolve against promptsRoot's repo
    extra_roots.append(Path.home())

    results = {}
    for proj in config["projects"]:
        root = portfolio_root / proj["folder"]
        if not root.exists():
            continue
        try:
            findings = check_project(root, today, extra_roots)
        except Exception as e:  # noqa: BLE001 — fail open per project
            print(f"  SKIP {proj['slug']}: {e}", file=sys.stderr)
            continue
        results[proj["displayName"]] = findings
        if findings:
            print(f"  {proj['displayName']}:")
            for f in findings:
                print(f"    - {f}")

    clean = sum(1 for f in results.values() if not f)
    flagged = len(results) - clean
    print(f"\n{flagged} project(s) with stale docs, {clean} clean.")

    # firstFlagged carries forward across runs so generate-portfolio-stats.js can
    # feed the "days open" badge (flagAges). Deliberately NOT emitted into the
    # dated scans/*-DATE.json stream: the burndown chart tracks security-scan
    # posture per scan date, and a different-cadence docs check would double-
    # count projects per date and distort that trend.
    first_flagged = {}
    if OUT_JSON.exists():
        try:
            first_flagged = json.loads(OUT_JSON.read_text(encoding="utf-8")).get("firstFlagged", {})
        except (json.JSONDecodeError, OSError):
            pass
    today_str = today.strftime("%Y-%m-%d")
    for name, f in results.items():
        if f and name not in first_flagged:
            first_flagged[name] = today_str
        elif not f:
            first_flagged.pop(name, None)  # cleared — age resets if it ever returns

    OUT_JSON.write_text(json.dumps(
        {"checkedAt": today_str, "results": results, "firstFlagged": first_flagged}, indent=2,
    ), encoding="utf-8")

    if args.merge:
        changed = merge_into_apps(results)
        print(f"apps.js updated for: {', '.join(changed) if changed else 'no changes'}")


if __name__ == "__main__":
    main()
