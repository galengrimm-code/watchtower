#!/usr/bin/env python3
"""Phase B.5 structural validator. Checks each SCANNED project's CLAUDE.md
SCAN:AUTO block against the canonical template's required sections.
Skips Archived projects and projects with no scan JSON for the date (argv[1], default
today). Validates both the pre-v7.8 single-file block and the v7.8 CLAUDE.md +
docs/security-scan.md split."""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = json.loads((ROOT / "watchtower.config.json").read_text(encoding="utf-8"))
PORTFOLIO = Path(CONFIG["portfolioRoot"])
DATE = sys.argv[1] if len(sys.argv) > 1 else __import__("datetime").date.today().isoformat()

def scan_block(text):
    m = re.search(r'<!-- SCAN:AUTO:START\b[^>]*-->(.*?)<!-- SCAN:AUTO:END', text, re.DOTALL)
    return m.group(1) if m else ""

def check(block):
    fails = []
    # 1 Tech Stack + required rows
    if "## Tech Stack" not in block:
        fails.append("no ## Tech Stack")
    else:
        for row in ("Frontend", "Backend", "Data", "Auth", "Hosting", "Testing"):
            if not re.search(r'\|\s*%s\s*\|' % row, block):
                fails.append(f"Tech Stack missing {row} row")
    # 2 Architecture + 4 subheadings
    if "## Architecture" not in block:
        fails.append("no ## Architecture")
    for sub in ("### Folder Structure", "### Key Files", "### Data Flow", "### External API Calls"):
        if sub not in block:
            fails.append(f"missing {sub}")
    # 3 Environment Variables
    if "## Environment Variables" not in block:
        fails.append("no ## Environment Variables")
    # 4 Security Notes + 4 subheadings
    if "## Security Notes" not in block:
        fails.append("no ## Security Notes")
    for sub in ("### Active Flags", "### Watch List", "### Accepted Risks", "### Resolved"):
        if sub not in block:
            fails.append(f"missing {sub}")
    # 5 Guardrails + Universal 9 items + Project-Specific
    if "### Universal" not in block:
        fails.append("no ### Universal guardrails")
    else:
        uni = block.split("### Universal", 1)[1]
        uni = uni.split("### Project-Specific", 1)[0] if "### Project-Specific" in uni else uni
        nums = re.findall(r'^\s*([1-9])\.\s', uni, re.MULTILINE)
        if len(nums) != 9:
            fails.append(f"Universal guardrails = {len(nums)} numbered items (need 9)")
    if "### Project-Specific" not in block:
        fails.append("no ### Project-Specific")
    # 6 Deployed Surface
    if "## Deployed Surface" not in block:
        fails.append("no ## Deployed Surface")
    # 7 Metrics + 7 bullets
    if "## Metrics" not in block:
        fails.append("no ## Metrics")
    else:
        for label in ("Total lines", "Components", "Files over", "Repo", "Production URL",
                      "Last commit scanned", "Scan prompt version"):
            if label not in block:
                fails.append(f"Metrics missing '{label}'")
    return fails

MOVED = ("## Security Notes", "## Deployed Surface", "## Strengths", "## Metrics")

def check_split(block, companion):
    """v7.8 layout: CLAUDE.md keeps what a coding session needs; the audit record lives in
    docs/security-scan.md (not auto-loaded). Reuses check() for the shared headings."""
    fails = [f for f in check(block + "\n" + companion)]
    if "## Security Scan" not in block or "docs/security-scan.md" not in block:
        fails.append("CLAUDE.md missing ## Security Scan pointer to docs/security-scan.md")
    if "## Dev Commands" not in block:
        fails.append("no ## Dev Commands")
    for h in MOVED:
        if h in block:
            fails.append(f"CLAUDE.md still carries {h} (migration did not happen)")
        if h not in companion:
            fails.append(f"docs/security-scan.md missing {h}")
    if not companion:
        fails.append("docs/security-scan.md has no SCAN:AUTO block")
    return fails

results = {}
for p in CONFIG["projects"]:
    if p.get("category") == "Archived":
        continue
    slug = p["slug"]
    if not (ROOT / "scans" / f"{slug}-{DATE}.json").exists():
        continue
    cmd = PORTFOLIO / p["folder"] / "CLAUDE.md"
    if not cmd.exists():
        results[slug] = ["NO CLAUDE.md"]
        continue
    block = scan_block(cmd.read_text(encoding="utf-8", errors="replace"))
    if not block:
        results[slug] = ["NO SCAN:AUTO block"]
        continue
    if "## Security Notes" in block:
        results[slug] = check(block)          # pre-v7.8 single-file layout
    else:
        comp_path = cmd.parent / "docs" / "security-scan.md"
        comp = scan_block(comp_path.read_text(encoding="utf-8", errors="replace")) if comp_path.exists() else ""
        results[slug] = check_split(block, comp)

if not results:
    # Validating nothing is not a pass: a wrong date or a missing write_scan_jsons.py
    # run used to print "All scanned projects passed" over zero projects.
    print(f"ERROR: no scanned projects to validate -- no scans/<slug>-{DATE}.json found. "
          f"Run write_scan_jsons.py --date {DATE} first.")
    sys.exit(2)

passed = [s for s, f in results.items() if not f]
failed = {s: f for s, f in results.items() if f}
print(f"Validated {len(results)} scanned projects.")
print(f"PASS: {len(passed)}")
for s in sorted(passed):
    print(f"  OK  {s}")
if failed:
    print(f"\nFAIL: {len(failed)}")
    for s, f in failed.items():
        print(f"  XX  {s}: {'; '.join(f)}")
    # Exit nonzero so a failure can stop something. It used to print FAIL lines and
    # exit 0, so Phase B.5 was a gate only if an agent chose to read the output.
    sys.exit(1)
else:
    print("\nAll scanned projects passed structural validation.")
