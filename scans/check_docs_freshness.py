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

Plus two Watchtower-self checks that run ONCE (not per project) and route their
findings onto the Watch Tower app's own stale-docs flag:

  5. Scan-prompt version drift — the README + CLAUDE.md runbook must cite the
     version in the scan-prompt header (the machine-readable source of truth).
  6. Repo mirror drift — code scripts shared between the private runtime and the
     public methodology repo must stay identical (newline-normalized, so a pure
     CRLF/LF checkout difference isn't cried as drift); index.html may differ only
     by its known title/header lines. The mirror set is DISCOVERED (code files
     present in both scans/ dirs), never hardcoded.

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

# The scan-prompt version is machine-derivable from the prompt's own header —
# the single source of truth (phase_c_update.py reads the same line). Watchtower's
# own docs hand-cite this version and have silently drifted from it before
# (README said v7.0, runbook said v7.1, while the prompt was v7.2). Check 5 makes
# that drift self-catching every cycle instead of relying on someone noticing.
SCAN_PROMPT_VERSION = re.compile(r"^#\s*Security Scan Prompt\s+(v\d+\.\d+)", re.M)
# An ALLOWLIST of "claims the CURRENT version" phrasings, NOT every vN.N mention.
# Case-insensitive and tolerant of smart apostrophes (docs get auto-curly-quoted —
# an ASCII-only "It's" would silently go blind, defeating the whole gate). Paired
# with HISTORICAL_REF so a changelog line ("Scan Prompt v7.0 added…") is exempted
# rather than flagged. (Codex-reviewed 2026-07-13: closed the case/apostrophe
# false-negatives and the historical-ref false-positives.)
CURRENT_VERSION_CLAIM = re.compile(
    r"(?:currently at|current(?: version)? is|latest is|"
    r"scan prompt(?: version)? is|it[‘’']s|scan prompt)\s+(v\d+\.\d+)",
    re.I,
)
# A line carrying one of these is talking about a PAST version on purpose — never
# a current-version claim. Mirrors the INTENTIONAL exemption used in Check 2.
HISTORICAL_REF = re.compile(
    r"\b(added|since|introduced|was|prior|formerly|previously|before)\b", re.I
)
# The lines index.html is ALLOWED to differ on between the two repos: the runtime
# brands "Watch Tower" / "Galen Grimm", the public shell says "Watchtower" / has an
# empty subtitle slot. Anchored to the SPECIFIC title/h1/subtitle elements (not a
# bare `class="sub"` substring) so Check 6 still catches any OTHER dashboard drift.
MIRROR_INDEX_DELTA = re.compile(
    r'<title>.*</title>|<h1>\s*Watch\s?[Tt]ower\s*</h1>|<span class="sub"[^>]*>.*?</span>'
)

# Multi-line blocks the private runtime marks as instance-only (e.g. the idea/to-do
# board): <!-- RUNTIME-ONLY:START … --> … <!-- RUNTIME-ONLY:END -->. Stripped from
# BOTH sides before the mirror comparison, so a private runtime feature never reads
# as drift and never has to be hand-copied to (or stripped from) the public shell.
RUNTIME_ONLY_BLOCK = re.compile(
    r'<!--\s*RUNTIME-ONLY:START.*?RUNTIME-ONLY:END\s*-->', re.DOTALL
)


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


def scan_version_drift(config):
    """Watchtower's OWN docs must agree with the scan prompt's header version.

    Returns (canonical_version, findings). Fails open (empty findings) if the
    canonical version can't be read, so a prompt refactor never breaks the run.
    """
    prompts_root = config.get("promptsRoot")
    if not prompts_root:
        return None, []
    canonical_m = SCAN_PROMPT_VERSION.search(read(Path(prompts_root) / "security-scan-prompt.md"))
    if not canonical_m:
        return None, []
    canonical = canonical_m.group(1)

    docs = [
        ("public README", Path(prompts_root).parent / "README.md"),
        ("CLAUDE.md runbook", WATCHTOWER_ROOT / "CLAUDE.md"),
    ]
    findings = []
    for label, path in docs:
        text = read(path)
        if path.name == "CLAUDE.md":
            text = hand_written_half(text)  # the SCAN:AUTO block is generated, not a hand-cited claim
        claimed = set()
        for line in text.splitlines():
            if HISTORICAL_REF.search(line):
                continue  # a deliberate past-version reference, not a current-version claim
            claimed.update(CURRENT_VERSION_CLAIM.findall(line))
        for c in sorted(claimed):
            if c != canonical:
                findings.append(
                    f"{label} claims scan prompt {c} but the prompt header is {canonical}"
                )
    return canonical, findings


def watchtower_self_name(config, portfolio_root):
    """displayName of the project that IS this Watchtower runtime (for flag routing)."""
    for proj in config.get("projects", []):
        if (portfolio_root / proj["folder"]).resolve() == WATCHTOWER_ROOT:
            return proj["displayName"]
    return "Watch Tower"


def mirror_drift(config):
    """Code scripts shared between the runtime and the public methodology repo must
    stay identical; index.html may differ only by its known title/header lines.
    Returns drift findings. Fails open ([]) when the public repo isn't present
    alongside the runtime (e.g. a stranger's clone of just one repo).

    Self-maintaining: the mirror set is DISCOVERED (every code file present in both
    scans/ dirs), never hardcoded — a new shared script is covered automatically,
    a runtime-only script is ignored automatically.
    """
    prompts_root = config.get("promptsRoot")
    if not prompts_root:
        return []
    public_root = Path(prompts_root).parent.resolve()  # resolve so the == guard is symlink/case/rel-safe
    rt_scans = WATCHTOWER_ROOT / "scans"
    pub_scans = public_root / "scans"
    if public_root == WATCHTOWER_ROOT or not pub_scans.is_dir():
        return []  # no distinct public repo to compare against

    # Compare CONTENT, newline-normalized — a CRLF/LF checkout difference between
    # the two repos is not a real hand-sync miss, and byte-comparing would cry
    # wolf on every script the moment git normalized line endings differently.
    def norm(path):
        return read(path).splitlines()

    findings = []
    CODE_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh")  # code, not data (.json/.md would false-positive)
    for rt_file in sorted(rt_scans.iterdir()):
        if not rt_file.is_file() or rt_file.suffix not in CODE_EXT:
            continue
        pub_file = pub_scans / rt_file.name
        if not pub_file.exists():
            continue  # runtime-only script — not part of the mirror set
        if norm(rt_file) != norm(pub_file):
            findings.append(
                f"scans/{rt_file.name} has drifted between the runtime and the public repo"
            )

    # index.html: must exist in BOTH (absence on one side is itself drift), and
    # match once the known branding lines are masked out.
    rt_index, pub_index = WATCHTOWER_ROOT / "index.html", public_root / "index.html"
    if rt_index.exists() != pub_index.exists():
        findings.append("index.html is present in one repo but missing from the other")
    elif rt_index.exists():
        # RUNTIME-ONLY blocks are private to this instance and must NEVER reach the
        # public repo. Stripping them from BOTH sides (below) hides the legit case
        # (runtime has them, public doesn't) — but it would ALSO hide a LEAK: a
        # private block accidentally copied into the public index.html would be
        # stripped and the compare would read clean. So assert public has none
        # FIRST — a leak is a finding, not something to silently mask.
        if RUNTIME_ONLY_BLOCK.search(read(pub_index)):
            findings.append(
                "public index.html contains a RUNTIME-ONLY block — a private "
                "runtime-only feature leaked into the public repo; remove it "
                "before it ships (the public dashboard is served publicly)"
            )

        def index_body(path):
            # Strip RUNTIME-ONLY blocks (private runtime features) from the raw text
            # first, then mask the known branding lines. Both sides get the same
            # treatment, so instance-only blocks are invisible to the drift check.
            text = RUNTIME_ONLY_BLOCK.sub("", read(path))
            # Drop blank/whitespace-only lines: stripping a RUNTIME-ONLY block leaves
            # the newlines that surrounded it, and blank-line count is never semantic
            # HTML drift anyway. A real added line is non-blank and still caught.
            return [ln for ln in text.splitlines() if ln.strip() and not MIRROR_INDEX_DELTA.search(ln)]
        rt_body = index_body(rt_index)
        pub_body = index_body(pub_index)
        if rt_body != pub_body:
            findings.append(
                "index.html has drifted between the runtime and the public repo "
                "beyond its intended title/header deltas"
            )
    return findings


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

    # Checks 5 & 6 (Watchtower-self): run once, route any drift onto the Watch
    # Tower app's own stale-docs flag so it rides the same merge/burndown machinery.
    # Each fails open — a self-check must never break the whole freshness run.
    self_name = watchtower_self_name(config, portfolio_root)
    try:
        _canonical, vdrift = scan_version_drift(config)  # 5: docs vs prompt-header version
    except Exception as e:  # noqa: BLE001 — fail open
        print(f"  SKIP version-drift check: {e}", file=sys.stderr)
        vdrift = []
    try:
        mdrift = mirror_drift(config)  # 6: runtime <-> public repo byte-identity
    except Exception as e:  # noqa: BLE001 — fail open
        print(f"  SKIP mirror-drift check: {e}", file=sys.stderr)
        mdrift = []
    if vdrift or mdrift:
        results.setdefault(self_name, []).extend(vdrift + mdrift)
        if vdrift:
            print(f"  {self_name} (scan-prompt version drift):")
            for f in vdrift:
                print(f"    - {f}")
        if mdrift:
            print(f"  {self_name} (repo mirror drift):")
            for f in mdrift:
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
