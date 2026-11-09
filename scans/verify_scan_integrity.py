#!/usr/bin/env python3
"""Refuse to let a scan claim things that aren't true.

Runs AFTER the per-project scan phase and BEFORE phase_c_update.py touches
data/apps.js. Every assertion here exists because a real defect shipped past the
2026-08-29 v7.6 run, and every one of those defects failed SILENTLY -- it produced
a confident wrong answer rather than an error. That is the failure mode this file
is built to catch, including the next instance of it that isn't listed below.

  A1  contamination      Parallel agents shared one scratchpad path; three of them
                         spliced another project's findings into the wrong repo.
  A2  stale restamping   The writer produced dated result files for Archived
                         projects from prior-cycle markdown.
  A3  parse loss         The flag parser returned zero for a project whose markdown
                         held seven flags, including the run's worst finding. The
                         app reported CLEAN.
  A3w watch-list loss    (v7.9) The Watch List became its own lane in the scan JSON.
                         A3 counts Active rows only, so a parser that dropped the
                         whole lane would pass unnoticed.
  A4  metric drift       A line-count metric counted committed .json data as source
                         (821,400 reported vs 76,802 real).  WARN ONLY -- see below.
  A5  version drift      Result files carried no scanVersion at all, so nothing
                         could tell a current artifact from a stale one.
  A6  dead verifier      The NVD lookup sent its API key as a query param instead of
                         a header. NVD answered 200 with an empty body, so every CVE
                         check reported "zero results" -- indistinguishable from clean.
  A7  flag table missing The v7.8 split moved Active Flags to docs/security-scan.md.
                         A reader looking only at CLAUDE.md finds no table, parses 0,
                         and A3 passes 0 == 0: an all-clear for every project.
  A8  block freshness    (2026-11-09) A project whose agent silently failed kept last
                         cycle's block and was published dated today. A5 compared the
                         prompt header with a value stamped from that same header and
                         could not fail. A5 now reads the block's own version and A8
                         its own date, both from the SCAN:AUTO START marker.

On exit 0 the gate writes scans/integrity-pass-<date>.stamp; phase_c_update.py
refuses a full-portfolio merge without it.

A4 is WARN, not FAIL, on purpose. Line counts move for boring reasons (a new
lockfile, a vendored catalog, an .gitignore change). A gate that cries wolf gets
disabled by a tired operator, and a disabled gate protects nothing.

A6 is the one that isn't about artifacts. A1-A5 all verify that the scan wrote
coherent files; none of them prove the scan actually PERFORMED its checks. A6 asks
an external verifier a question whose answer is known, and fails if it lies.

Because the scan can run unattended, a hard failure must still be discoverable:
this writes scans/integrity-failure-<date>.json on any FAIL so a stopped run leaves
evidence instead of silence.

Exit codes:
  0  all hard assertions passed (warnings may still be present)
  1  at least one hard assertion FAILED -- do not publish this cycle
  2  could not run (missing config, no scan files for the date)
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

WATCHTOWER_ROOT = Path(__file__).resolve().parent.parent
SCANS_DIR = WATCHTOWER_ROOT / "scans"
CONFIG_PATH = WATCHTOWER_ROOT / "watchtower.config.json"

# An independent, deliberately dumb table-row detector. It must NOT share code with
# the production parser -- a checker that reuses the parser it is checking agrees
# with every bug the parser has.
FLAG_ROW = re.compile(r"^\|\s*(P[1-4])\s*\|", re.MULTILINE)

# A canary with a known answer. Log4Shell is not going to be un-published.
CANARY_CVE = "CVE-2021-44228"


class Result:
    def __init__(self):
        self.failures = []   # hard -- block the cycle
        self.warnings = []   # soft -- report and continue
        self.passes = []

    def fail(self, check, detail):
        self.failures.append({"check": check, "detail": detail})

    def warn(self, check, detail):
        self.warnings.append({"check": check, "detail": detail})

    def ok(self, check, detail):
        self.passes.append({"check": check, "detail": detail})


def load_config():
    if not CONFIG_PATH.exists():
        sys.exit(f"ERROR: {CONFIG_PATH} not found.")
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _read_block(path):
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r"<!-- SCAN:AUTO:START\b[^>]*-->(.*?)<!-- SCAN:AUTO:END", content, re.DOTALL)
    return m.group(1) if m else ""


def companion_path(claude_path):
    """v7.8 moved Security Notes / Deployed Surface / Strengths / Metrics out of the
    auto-loaded CLAUDE.md into docs/security-scan.md."""
    return claude_path.parent / "docs" / "security-scan.md"


def read_scan_section(claude_path):
    """CLAUDE.md's block joined with the docs/security-scan.md block (v7.8+).
    A pre-v7.8 project has no companion, so this is just the CLAUDE.md block."""
    return _read_block(claude_path) + "\n" + _read_block(companion_path(claude_path))


def active_flags_section(scan_section):
    """Text of '### Active Flags' up to the next heading. Empty string if absent."""
    m = re.search(r"### Active Flags\b(.*?)(?=\n### |\n## |\Z)", scan_section, re.DOTALL)
    return m.group(1) if m else ""


def detect_prompt_version(config):
    roots = []
    if config.get("promptsRoot"):
        roots.append(Path(config["promptsRoot"]) / "security-scan-prompt.md")
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


# ---------------------------------------------------------------- A1
def git_origin(folder_path):
    """origin URL for a repo, host+path lowercased, or None."""
    try:
        out = subprocess.run(["git", "-C", str(folder_path), "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    url = out.stdout.strip().lower()
    if not url:
        return None
    url = re.sub(r"^git@([^:]+):", r"/", url)
    url = re.sub(r"^https?://", "", url)
    return url.removesuffix(".git").rstrip("/")


def check_contamination(res, config, portfolio_root, active):
    """Does a project's generated block declare SOMEONE ELSE'S identity?

    Two earlier cuts of this check were wrong, and both are worth remembering.

    The first asked "does block X mention project Y" and produced 8 false positives
    on 25 real projects, because legitimate cross-references are common and
    load-bearing here: Farm Budget names farm-fin and Landowner-Portal because all
    three share one Supabase project, which was the most important finding of the
    2026-08-29 cycle. 'baseline' is also an ordinary English word. A gate that flags
    that is noise, and noisy gates get switched off. So: a block may MENTION any
    sibling it likes; it may not claim to BE one.

    The second compared the block's Repo line against a `repoUrl` key in
    watchtower.config.json -- a key that does not exist. Every comparison
    short-circuited on an empty string and the check reported "25 blocks declare
    their own repository" while verifying nothing. A deliberate splice test walked
    straight through it. That is the same silent-pass failure this whole file exists
    to catch, so the ground truth is now `git remote get-url origin` (authoritative,
    always present, cannot drift from config) and an identity that cannot be
    determined WARNS rather than passing quietly.
    """
    repo_line = re.compile(r"^\s*[-*]\s*\*\*Repo:?\*\*:?\s*(.+?)\s*$", re.MULTILINE)

    origins = {}
    for proj in active:
        o = git_origin(portfolio_root / proj["folder"])
        if o:
            origins[proj["slug"]] = o

    checked = no_line = no_origin = 0
    for proj in active:
        section = read_scan_section(portfolio_root / proj["folder"] / "CLAUDE.md")
        if not section:
            continue
        mine = origins.get(proj["slug"])
        if not mine:
            no_origin += 1
            continue
        m = repo_line.search(section)
        declared = m.group(1).strip() if m else ""
        declared = re.sub(r"\s*\(.*$", "", declared).strip().strip("`*").rstrip("/").lower()
        declared = re.sub(r"^https?://", "", declared).removesuffix(".git")
        if not declared:
            no_line += 1
            continue
        checked += 1

        if declared == mine or declared.startswith(mine) or mine.startswith(declared):
            continue
        foreign = [s2 for s2, u in origins.items() if s2 != proj["slug"] and declared == u]
        if foreign:
            res.fail("A1 contamination",
                     f"{proj['displayName']}'s block declares Repo={declared!r}, which is "
                     f"{foreign[0]}'s actual origin. A block claiming another project's identity "
                     f"was spliced in -- check that repo's CLAUDE.md before publishing.")
        else:
            res.warn("A1 contamination",
                     f"{proj['displayName']}'s block declares Repo={declared!r} but git origin is "
                     f"{mine!r}. Not a known sibling -- one of the two is stale.")

    if no_origin:
        res.warn("A1 contamination",
                 f"{no_origin} project(s) have no resolvable git origin, so their block identity "
                 f"could NOT be verified. This is unchecked, not clean.")
    if no_line:
        res.warn("A1 contamination",
                 f"{no_line} block(s) carry no Repo line; identity unverifiable. The canonical "
                 f"Metrics section requires one.")
    if checked and not any(f["check"].startswith("A1") for f in res.failures):
        res.ok("A1 contamination", f"{checked} block(s) verified against their git origin")
    elif not checked:
        res.warn("A1 contamination", "no block could be verified -- the check did not run")


# ---------------------------------------------------------------- A2
def check_archived(res, config, scan_date):
    archived = [p["slug"] for p in config["projects"] if p.get("category") == "Archived"]
    leaked = [s for s in archived if (SCANS_DIR / f"{s}-{scan_date}.json").exists()]
    if leaked:
        res.fail("A2 stale restamping",
                 f"Archived projects have files dated {scan_date}: {leaked}. Their CLAUDE.md "
                 f"blocks are from a prior cycle, so these present old findings as current.")
    else:
        res.ok("A2 stale restamping", f"none of {len(archived)} Archived projects wrote a file")


# ---------------------------------------------------------------- A3
def check_parse_loss(res, portfolio_root, active, scan_date):
    """Markdown row count must equal JSON flag count, per severity.

    'JSON is non-zero' is too weak -- it passes when 12 rows become 1 flag. This
    compares totals AND the per-severity split, using the independent detector above.
    """
    checked = mismatched = 0
    for proj in active:
        path = SCANS_DIR / f"{proj['slug']}-{scan_date}.json"
        if not path.exists():
            continue
        section = active_flags_section(read_scan_section(portfolio_root / proj["folder"] / "CLAUDE.md"))
        md = {}
        for sev in FLAG_ROW.findall(section):
            md[sev] = md.get(sev, 0) + 1
        data = json.loads(path.read_text(encoding="utf-8"))
        js = {}
        for f in data.get("flags") or []:
            sev = f.get("severity")
            if sev:
                js[sev] = js.get(sev, 0) + 1
        checked += 1
        if md != js:
            mismatched += 1
            res.fail("A3 parse loss",
                     f"{proj['displayName']}: markdown has {md or '{}'} but JSON has {js or '{}'} "
                     f"-- the parser lost rows between the document and the artifact.")
    if not mismatched:
        res.ok("A3 parse loss", f"{checked} projects: markdown rows == JSON flags, per severity")


def watch_list_items(scan_section):
    """Independent count of Watch List entries: table rows starting with a severity
    cell (v7.9 template), else top-level bullets (legacy free-form lists)."""
    m = re.search(r"### Watch List[^\n]*\n(.*?)(?=\n### |\n## |\Z)", scan_section, re.DOTALL)
    if not m:
        return 0
    body = m.group(1)
    rows = FLAG_ROW.findall(body)
    if rows:
        return len(rows)
    return len(re.findall(r"^[-*]\s+", body, re.MULTILINE))


def check_watch_list_parse_loss(res, portfolio_root, active, scan_date):
    """A3w (v7.9): Watch List entries in markdown must equal the JSON watchList.

    A3 counts only Active Flags, so a parser that dropped the whole Watch List lane
    would pass it 0 == 0 -- the exact silent all-clear A7 was added to stop. A JSON
    with no watchList key at all was written by a pre-v7.9 parser: also a failure.
    """
    checked = mismatched = 0
    for proj in active:
        path = SCANS_DIR / f"{proj['slug']}-{scan_date}.json"
        if not path.exists():
            continue
        md = watch_list_items(read_scan_section(portfolio_root / proj["folder"] / "CLAUDE.md"))
        data = json.loads(path.read_text(encoding="utf-8"))
        checked += 1
        if "watchList" not in data:
            mismatched += 1
            res.fail("A3w watch-list loss",
                     f"{proj['displayName']}: JSON has no watchList key -- written by a pre-v7.9 "
                     f"write_scan_jsons.py; re-run it.")
            continue
        js = len(data["watchList"])
        if md != js:
            mismatched += 1
            res.fail("A3w watch-list loss",
                     f"{proj['displayName']}: markdown Watch List has {md} entries but JSON has {js}.")
    if not mismatched:
        res.ok("A3w watch-list loss", f"{checked} projects: Watch List entries == JSON watchList")


# ---------------------------------------------------------------- A7
def check_flag_table_present(res, portfolio_root, active, scan_date):
    """A3 compares markdown rows to JSON flags, so it passes 0 == 0 when the flag table
    is simply not where the readers look -- the v7.8 split moved it to
    docs/security-scan.md, and a runtime still reading only CLAUDE.md would report an
    all-clear for every project. A clean project writes "_None_" UNDER an Active Flags
    heading; a missing heading is never clean.
    """
    ver_re = re.compile(r"SCAN:AUTO:START[^>]*?v(\d+)\.(\d+)")
    checked = 0
    for proj in active:
        if not (SCANS_DIR / f"{proj['slug']}-{scan_date}.json").exists():
            continue
        claude_path = portfolio_root / proj["folder"] / "CLAUDE.md"
        checked += 1
        name = proj["displayName"]
        if "### Active Flags" not in read_scan_section(claude_path):
            res.fail("A7 flag table missing",
                     f"{name}: no '### Active Flags' section in CLAUDE.md or "
                     f"docs/security-scan.md -- a zero-flag result here is unverified, not clean.")
            continue
        try:
            head = claude_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            head = ""
        m = ver_re.search(head)
        if m and (int(m.group(1)), int(m.group(2))) >= (7, 8):
            if not _read_block(companion_path(claude_path)):
                res.fail("A7 flag table missing",
                         f"{name}: CLAUDE.md block is stamped v{m.group(1)}.{m.group(2)} but "
                         f"docs/security-scan.md has no SCAN:AUTO block.")
            elif "## Security Notes" in _read_block(claude_path):
                res.fail("A7 flag table missing",
                         f"{name}: v7.8+ CLAUDE.md block still carries '## Security Notes' -- "
                         f"the split did not happen, and flags may be double-counted.")
    if not any(f["check"].startswith("A7") for f in res.failures):
        res.ok("A7 flag table missing", f"{checked} projects carry an Active Flags section")


# ---------------------------------------------------------------- A4 (WARN)
def check_metric_drift(res, active, scan_date, factor=3.0):
    """Line-count movement beyond `factor` is suspicious, not proof. WARN only."""
    moved = 0
    for proj in active:
        cur = SCANS_DIR / f"{proj['slug']}-{scan_date}.json"
        if not cur.exists():
            continue
        prior = sorted(SCANS_DIR.glob(f"{proj['slug']}-*.json"))
        prior = [p for p in prior if p.name < cur.name]
        if not prior:
            continue
        try:
            now = (json.loads(cur.read_text(encoding="utf-8")).get("metrics") or {}).get("totalLines")
            was = (json.loads(prior[-1].read_text(encoding="utf-8")).get("metrics") or {}).get("totalLines")
        except (json.JSONDecodeError, OSError):
            continue
        if not now or not was:
            continue
        ratio = max(now, was) / max(1, min(now, was))
        if ratio >= factor:
            moved += 1
            res.warn("A4 metric drift",
                     f"{proj['displayName']}: totalLines {was:,} -> {now:,} ({ratio:.1f}x vs "
                     f"{prior[-1].name}). Usually a measurement-definition change (committed data, "
                     f"a vendored catalog), not scan corruption -- confirm what is being counted.")
    if not moved:
        res.ok("A4 metric drift", "no project moved more than 3x")


# ---------------------------------------------------------------- A5
def check_scan_version(res, active, scan_date, expected):
    if not expected:
        res.warn("A5 version drift", "could not read a version from the prompt; check skipped")
        return
    # Compares the version each BLOCK says it was written with (blockVersion, parsed
    # from its START marker), not scanVersion. scanVersion is stamped from this same
    # prompt header, so comparing it here was a check that could not fail (N6).
    bad = []
    for proj in active:
        path = SCANS_DIR / f"{proj['slug']}-{scan_date}.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if "blockVersion" not in data:
            bad.append(f"{proj['slug']}=<no blockVersion: pre-2026-11-09 writer, re-run write_scan_jsons.py>")
            continue
        got = data["blockVersion"]
        if got != expected:
            bad.append(f"{proj['slug']}={got!r}")
    if bad:
        res.fail("A5 version drift",
                 f"prompt is {expected} but blocks were written by: {bad[:6]}"
                 + (f" (+{len(bad)-6} more)" if len(bad) > 6 else ""))
    else:
        res.ok("A5 version drift", f"every block written by {expected}")


# ---------------------------------------------------------------- A9
def check_prompt_lint(res, config):
    """A9 (WARN): the methodology prompt's structure (scans/lint_prompt.py).

    WARN, not FAIL: a drifted prompt does not make this cycle's findings wrong,
    and blocking publication over it would hide real findings. It is here so the
    lint runs every cycle instead of only when someone remembers it.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import lint_prompt
        root = Path(config["promptsRoot"]) if config.get("promptsRoot") else WATCHTOWER_ROOT / "prompts"
        problems = lint_prompt.lint(root)
    except (ImportError, OSError) as e:
        res.warn("A9 prompt lint", f"could not run: {e}")
        return
    if problems:
        res.warn("A9 prompt lint", f"{len(problems)} problem(s): " + "; ".join(problems[:3]))
    else:
        res.ok("A9 prompt lint", "prompt structure clean")


# ---------------------------------------------------------------- A8
def check_block_freshness(res, active, scan_date):
    """A8: every active project's block was written THIS cycle.

    write_scan_jsons.py writes a JSON for every active project, dated with the cycle,
    whether or not its agent ran. A project whose agent failed silently keeps last
    cycle's block and would publish as freshly scanned ("0d" on Scan Status). The
    block's own START marker date is the only evidence the agent wrote it. A block
    dated before the cycle, or with no date, fails. A date after the cycle is
    allowed: a long run crosses midnight.
    """
    stale, undated = [], []
    for proj in active:
        path = SCANS_DIR / f"{proj['slug']}-{scan_date}.json"
        if not path.exists():
            continue
        got = json.loads(path.read_text(encoding="utf-8")).get("blockDate")
        if not got:
            undated.append(proj["slug"])
        elif got < scan_date:
            stale.append(f"{proj['slug']}={got}")
    problems = ([f"stale: {stale[:6]}" + (f" (+{len(stale)-6} more)" if len(stale) > 6 else "")] if stale else []) \
        + ([f"no date in START marker: {undated[:6]}"] if undated else [])
    if problems:
        res.fail("A8 block freshness",
                 f"block not written this cycle ({scan_date}) -- "
                 + "; ".join(problems)
                 + ". Its agent did not finish; re-run it or leave the project out of this cycle.")
    else:
        res.ok("A8 block freshness", f"every block dated {scan_date} or later")


# ---------------------------------------------------------------- A6
def check_cve_canary(res):
    """Ask NVD a question with a known answer; fail if it answers wrongly.

    A1-A5 verify the scan wrote coherent files. None of them prove it actually ran
    its checks. The 2026-08-29 run sent the NVD key as a query param when NVD wants
    a header: it answered HTTP 200 with an empty body, so every CVE lookup reported
    zero results and looked exactly like a clean portfolio.

    Distinguishing the two failure modes is the whole point:
      transport error  -> WARN (network flake, offline run; not evidence of anything)
      200 but empty    -> FAIL (the verifier is answering, and answering wrong)
    """
    key = os.environ.get("NVD_API_KEY", "")
    if not key:
        env = Path.home() / ".claude" / ".env"
        if env.exists():
            m = re.search(r"^NVD_API_KEY=(.+)$", env.read_text(encoding="utf-8", errors="replace"),
                          re.MULTILINE)
            if m:
                key = m.group(1).strip().strip('"').strip("'")

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CANARY_CVE}"
    req = urllib.request.Request(url, headers={"User-Agent": "watchtower-integrity/1.0"})
    if key:
        req.add_header("apiKey", key)  # HEADER, not a query param -- this is the bug A6 exists for
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            body = r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        res.warn("A6 CVE canary", f"NVD unreachable ({e.__class__.__name__}); not evidence of a "
                                  f"dead verifier, but this cycle's CVE data is unverified")
        return
    try:
        total = json.loads(body).get("totalResults")
    except json.JSONDecodeError:
        res.fail("A6 CVE canary",
                 f"NVD returned {len(body)} bytes that are not JSON. A non-JSON 200 is exactly how "
                 f"the query-param auth bug presented -- every CVE lookup silently read as clean.")
        return
    if not total:
        res.fail("A6 CVE canary",
                 f"NVD reported {total!r} results for {CANARY_CVE}, which certainly exists. The "
                 f"lookup is answering but answering wrong -- treat every CVE finding this cycle "
                 f"as unverified, and check that the API key is sent as a HEADER.")
    else:
        res.ok("A6 CVE canary", f"NVD returned {total} result(s) for {CANARY_CVE}"
                                + (" (authenticated)" if key else " (unauthenticated)"))


def main():
    ap = argparse.ArgumentParser(description="Verify a scan cycle's artifacts before publishing.")
    ap.add_argument("--date", default=None, help="Cycle date (YYYY-MM-DD). Defaults to today (UTC).")
    ap.add_argument("--skip-network", action="store_true",
                    help="Skip A6, the external CVE canary. Use offline; it makes the run's CVE "
                         "data unverified, so do not use it to get past a failing canary.")
    args = ap.parse_args()

    scan_date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    config = load_config()
    portfolio_root = Path(config["portfolioRoot"])
    active = [p for p in config["projects"]
              if p.get("category") != "Archived"
              and (portfolio_root / p["folder"]).is_dir()]

    todays = [f for f in SCANS_DIR.glob(f"*-{scan_date}.json")
              if not f.name.startswith("integrity-")]
    if not todays:
        print(f"ERROR: no scans/*-{scan_date}.json found. Run write_scan_jsons.py first.")
        return 2

    res = Result()
    print(f"Verifying scan cycle {scan_date} -- {len(todays)} files, {len(active)} active projects\n")

    check_contamination(res, config, portfolio_root, active)
    check_archived(res, config, scan_date)
    check_parse_loss(res, portfolio_root, active, scan_date)
    check_watch_list_parse_loss(res, portfolio_root, active, scan_date)
    check_flag_table_present(res, portfolio_root, active, scan_date)
    check_metric_drift(res, active, scan_date)
    check_scan_version(res, active, scan_date, detect_prompt_version(config))
    check_block_freshness(res, active, scan_date)
    check_prompt_lint(res, config)
    if args.skip_network:
        res.warn("A6 CVE canary", "skipped by --skip-network; CVE data this cycle is unverified")
    else:
        check_cve_canary(res)

    for p in res.passes:
        print(f"  PASS  {p['check']:22s} {p['detail']}")
    for w in res.warnings:
        print(f"  WARN  {w['check']:22s} {w['detail']}")
    for f in res.failures:
        print(f"  FAIL  {f['check']:22s} {f['detail']}")

    print(f"\n{len(res.passes)} passed, {len(res.warnings)} warning(s), {len(res.failures)} failure(s)")

    passed_stamp = SCANS_DIR / f"integrity-pass-{scan_date}.stamp"
    if res.failures:
        # An unattended run that stops silently is just a different silent failure.
        # Leave evidence on disk so the next person finds a reason, not an absence.
        passed_stamp.unlink(missing_ok=True)
        out = SCANS_DIR / f"integrity-failure-{scan_date}.json"
        out.write_text(json.dumps({
            "scanDate": scan_date,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "failures": res.failures,
            "warnings": res.warnings,
            "verdict": "DO NOT PUBLISH THIS CYCLE",
        }, indent=2), encoding="utf-8")
        print(f"\nWrote {out.name}. Do not run phase_c_update.py until these are resolved.")
        return 1

    stale = SCANS_DIR / f"integrity-failure-{scan_date}.json"
    if stale.exists():
        stale.unlink()
    # phase_c_update.py refuses a full merge without this stamp, or when any scan JSON
    # for the date is newer than it. "STOP on exit 1" used to be a sentence in the
    # skill; now the merge enforces it. .stamp, not .json: the stats scripts glob
    # *-<date>.json and would count it as a project.
    passed_stamp.write_text(json.dumps({
        "scanDate": scan_date,
        "passedAt": datetime.now(timezone.utc).isoformat(),
        "files": sorted(f.name for f in todays),
        "warnings": res.warnings,
    }, indent=2), encoding="utf-8")
    print(f"Wrote {passed_stamp.name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
