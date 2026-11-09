#!/usr/bin/env python3
"""lint_prompt.py -- structural checks on the scan methodology prompt.

Every check here encodes a drift that was found by hand on 2026-11-09:
  - The prompt carried ~35 KB of release history every scan agent paid for. Size
    now has a ceiling, so it cannot creep back unnoticed.
  - Integrity rules I14-I21 sat after GUARDRAILS RULES, so an agent reading top-down
    finished "the rules" before half of them. Rules must be numbered I1..In with no
    gap, in order, with no `## ` section between the first and the last.
  - The CLAUDE.md template inlined in STEP 3 had lost the v7.3 deployed-runtime
    Backend row that prompts/claude-md-template.md carried. The inlined templates
    and the template files must keep the same heading structure. (Heading-level
    only: a reworded line under an unchanged heading -- which is what the Backend
    drift was -- is NOT caught. Some lines differ on purpose, e.g. first-run
    Active Work text, so a line-level diff would cry wolf.)
  - SCAN:AUTO marker examples drifted (one read v7.1 in a v7.9 prompt), and the
    runtime now reads each block's version AND date from its marker (A5, A8). Every
    marker example must carry the title version and an `on {YYYY-MM-DD}` date.
  - The scheduled run's upstream-drift check greps for an `Upstream pin:` line.

Usage:  python scans/lint_prompt.py [--prompts-root DIR]
Exit:   0 clean, 1 problems found, 2 could not read the prompt.
verify_scan_integrity.py runs the same checks as a WARN (they describe the
methodology, not this cycle's findings).
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

WATCHTOWER_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = WATCHTOWER_ROOT / "watchtower.config.json"
MAX_PROMPT_BYTES = 290_000  # 2026-11-09 restructure landed at ~285 KB. Lower it as the prompt shrinks.

TEMPLATES = [
    # (template file, regex for the first line of the template, inside the prompt and the file)
    ("claude-md-template.md", r"^# \{Project Name\}$"),
    ("security-scan-md-template.md", r"^# Security Scan — \{Project Name\}$"),
]


def prompts_root(arg):
    if arg:
        return Path(arg)
    if CONFIG_PATH.exists():
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if cfg.get("promptsRoot"):
            return Path(cfg["promptsRoot"])
    return WATCHTOWER_ROOT / "prompts"


def _headings(lines, start_pat):
    """## / ### headings from the template's first line to its SCAN:AUTO:END marker."""
    try:
        s = next(i for i, l in enumerate(lines) if re.match(start_pat, l))
        e = next(i for i in range(s + 1, len(lines)) if lines[i].startswith("<!-- SCAN:AUTO:END"))
    except StopIteration:
        return None
    return [l.strip() for l in lines[s:e] if re.match(r"^#{2,3} ", l)]


def lint(root):
    """Return a list of problem strings. Raises OSError if the prompt can't be read."""
    root = Path(root)
    text = (root / "security-scan-prompt.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    lines = text.split("\n")
    problems = []

    size = len(text.encode("utf-8"))
    if size > MAX_PROMPT_BYTES:
        problems.append(f"prompt is {size:,} bytes, over the {MAX_PROMPT_BYTES:,} ceiling "
                        f"(every scan agent reads all of it)")

    title = re.search(r"^# Security Scan Prompt (v\d+\.\d+)", text, re.M)
    version = title.group(1) if title else None
    if not version:
        problems.append("no '# Security Scan Prompt vX.Y' title line")

    dupes = [h for h, n in collections.Counter(l for l in lines if l.startswith("## ")).items() if n > 1]
    if dupes:
        problems.append(f"duplicate ## headings: {dupes[:5]}")

    rules = [(i, int(m.group(1))) for i, l in enumerate(lines) for m in [re.match(r"^### I(\d+)\. ", l)] if m]
    nums = [n for _, n in rules]
    if nums != list(range(1, len(nums) + 1)):
        problems.append(f"integrity rules are not I1..I{len(nums)} in order: {nums}")
    elif rules:
        between = [lines[i].strip() for i in range(rules[0][0], rules[-1][0]) if lines[i].startswith("## ")]
        if between:
            problems.append(f"integrity rules are split by other sections: {between[:3]}")

    if not re.search(r"Upstream pin: [\w.-]+/[\w.-]+@[0-9a-f]{40}", text):
        problems.append("no 'Upstream pin: <owner>/<repo>@<40-hex sha>' line (the drift check reads it)")

    marker_files = {"security-scan-prompt.md": text}
    for name, start in TEMPLATES:
        path = root / name
        if not path.exists():
            problems.append(f"template file missing: {name}")
            continue
        ftext = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        marker_files[name] = ftext
        inline = _headings(lines, start)
        filed = _headings(ftext.split("\n"), start)
        if inline is None or filed is None:
            problems.append(f"{name}: template not found {'in the prompt' if inline is None else 'in the file'}")
        elif inline != filed:
            only_in = [h for h in filed if h not in inline] + [h for h in inline if h not in filed]
            problems.append(f"{name}: inlined template headings differ from the file "
                            f"({only_in[:4] or 'same headings, different order'})")

    for name, body in marker_files.items():
        # "{version ...}" spells the marker as a pattern (STEP 3's stamping rule), not an example.
        for m in re.finditer(r"Generated by security-scan-prompt(?!\s*\{)\s*(v\d+\.\d+)?([^.>]*)", body):
            if version and m.group(1) != version:
                problems.append(f"{name}: marker example says {m.group(1)!r}, title says {version}")
            if "{YYYY-MM-DD}" not in (m.group(2) or ""):
                problems.append(f"{name}: marker example has no 'on {{YYYY-MM-DD}}' date "
                                f"(A8 reads the block's date from its marker)")
    return problems


def main():
    ap = argparse.ArgumentParser(description="Lint the scan methodology prompt's structure.")
    ap.add_argument("--prompts-root", default=None, help="Directory holding security-scan-prompt.md.")
    args = ap.parse_args()
    root = prompts_root(args.prompts_root)
    try:
        problems = lint(root)
    except OSError as e:
        print(f"ERROR: could not read the prompt under {root}: {e}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"  FAIL  {p}")
    print(f"{'clean' if not problems else f'{len(problems)} problem(s)'}: {root / 'security-scan-prompt.md'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
