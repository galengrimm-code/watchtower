#!/usr/bin/env python3
"""Phase C dashboard updater: merge fresh scan JSONs into the APPS array.

Reads watchtower.config.json for portfolio layout. Targets data/apps.js
(where APPS lives after the 2026-05-21 refactor). Scan date defaults to today
unless --date YYYY-MM-DD is passed. Scan version is extracted from the header
of prompts/security-scan-prompt.md so it can't drift.

Rules:
- Replace active flags (no `status:` field) with new ones from the scan JSON
- Preserve accepted/resolved flags
- Update lastUpdated, lastScanned, scanVersion
- Update metrics, tech, structure if present in the scan
- Add new APPS entries for slugs not yet present in apps.js
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

WATCHTOWER_ROOT = Path(__file__).resolve().parent.parent
SCANS = WATCHTOWER_ROOT / "scans"
APPS_JS = WATCHTOWER_ROOT / "data" / "apps.js"
CONFIG_PATH = WATCHTOWER_ROOT / "watchtower.config.json"


def load_config():
    if not CONFIG_PATH.exists():
        sys.exit(f"ERROR: {CONFIG_PATH} not found.")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_prompt_path(config):
    """promptsRoot from config overrides the default <watchtowerRoot>/prompts/.
    Lets the runtime point at a shared methodology folder (e.g., the public
    watchtower repo) without duplicating prompts/. Fails loud if the resolved
    path doesn't exist — silently shipping scanVersion="unknown" produces
    misleading commit messages and apps.js metadata."""
    prompts_root = config.get("promptsRoot")
    if prompts_root:
        path = Path(prompts_root) / "security-scan-prompt.md"
        if not path.exists():
            sys.exit(
                f"ERROR: promptsRoot is set to {prompts_root!r} but "
                f"security-scan-prompt.md is not there. Either correct promptsRoot "
                f"in watchtower.config.json, or unset it to fall back to "
                f"<watchtowerRoot>/prompts/."
            )
        return path
    fallback = WATCHTOWER_ROOT / "prompts" / "security-scan-prompt.md"
    if not fallback.exists():
        sys.exit(
            f"ERROR: no scan prompt found. promptsRoot is unset/null in "
            f"watchtower.config.json and the default fallback at {fallback} "
            f"does not exist. Set promptsRoot to your Watchtower methodology "
            f"folder, or restore prompts/ inside the runtime repo."
        )
    return fallback


def detect_scan_version(prompt_path):
    """Read 'v6.x' from the first matching header line in the scan prompt.
    Callers must guarantee prompt_path.exists() — resolve_prompt_path does this."""
    with open(prompt_path, "r", encoding="utf-8") as f:
        for line in f:
            m = re.search(r"\bv\d+\.\d+\b", line)
            if m:
                return m.group(0)
    sys.exit(
        f"ERROR: scan prompt at {prompt_path} contains no v\\d+\\.\\d+ header. "
        f"Phase C needs a version string to stamp on apps.js entries and the Phase D "
        f"commit message."
    )


# Module-level state populated by main() before any helper that needs it runs.
SCAN_DATE = None
SCAN_VERSION = None
SLUG_TO_APP_NAME = {}


def jstr(s):
    """Encode a string as a JS string literal (double-quoted)."""
    if s is None:
        return "null"
    return json.dumps(s, ensure_ascii=False)


def fmt_flag(flag):
    """Format a flag dict from a scan JSON as a single-line JS object literal."""
    parts = [
        f"text: {jstr(flag['text'])}",
        f"severity: {jstr(flag['severity'])}",
        f"category: {jstr(flag['category'])}",
        f"confidence: {flag['confidence']:.2f}",
    ]
    if flag.get("exploit"):
        parts.append(f"exploit: {jstr(flag['exploit'])}")
    if flag.get("fix"):
        parts.append(f"fix: {jstr(flag['fix'])}")
    return "      { " + ", ".join(parts) + " }"


# -- Parser for the JS APPS array (object-aware string literal handling) --

def find_app_block(content, app_name):
    """Find the start..end indices of an app object literal in APPS array.

    Returns (start_brace, end_brace_exclusive) where text[start_brace] == '{'
    and text[end_brace_exclusive-1] == '}'.
    """
    # Line-anchored so a flag text / description that merely *mentions*
    # `name: "X"` mid-line can never be mistaken for the field itself.
    m = re.search(r'^\s*name: "' + re.escape(app_name) + r'"', content, re.MULTILINE)
    if m is None:
        return None
    name_idx = m.start()
    # Walk backward to the opening '{' of this object
    i = name_idx
    while i > 0 and content[i] != "{":
        i -= 1
    start = i
    # Walk forward to matching '}' (string-aware)
    depth = 0
    in_string = False
    string_char = None
    escape = False
    j = start
    while j < len(content):
        c = content[j]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == string_char:
                in_string = False
        else:
            if c == '"' or c == "'":
                in_string = True
                string_char = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return (start, j + 1)
        j += 1
    raise ValueError(f"unbalanced braces for app {app_name}")


def find_field_in_block(text, field):
    """Return (start, end) of a top-level field's VALUE within a JS object literal.

    `text` is the object literal `{ ... }`. `field` is the unquoted key name.
    Only matches at depth 1 (top-level of object). Returns None if not found.
    end is exclusive; value ends just before the trailing `,\n` or `\n}`.
    """
    pat = re.compile(r"^(\s*)" + re.escape(field) + r":\s*", re.MULTILINE)
    # Walk through the object tracking depth/strings
    depth = 0
    in_string = False
    string_char = None
    escape = False
    i = 0
    field_starts = []
    while i < len(text):
        c = text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == string_char:
                in_string = False
        else:
            if c == '"' or c == "'":
                in_string = True
                string_char = c
            elif c == "{":
                depth += 1
                # Check if this is the outer brace
                if depth == 1:
                    pass
            elif c == "}":
                depth -= 1
            else:
                # Look for "<field>:" at depth 1
                if depth == 1 and c.isalpha() and (i == 0 or text[i-1] in " \t\n\r,{"):
                    m = re.match(re.escape(field) + r":\s*", text[i:])
                    if m:
                        # Confirm the chars right before are whitespace/start
                        # Also ensure this is the field name, not a substring
                        # The match is ok if next char after field is `:` and we have the right key length.
                        if i > 0 and text[i-1] not in " \t\n\r,{":
                            pass
                        else:
                            field_starts.append(i + m.end() - len(m.group(0)) + len(field) + 1)
                            # Actually simpler: re-find. We'll do it differently below.
        i += 1
    # Use a simpler approach via regex w/ string-aware skipping
    # ... fall through to regex-based scan below
    return None


def parse_object_value_end(text, value_start):
    """Given index where a value begins (after `field: `), return index after the value.

    Stops at `,\n` (followed by whitespace + identifier) or at `\n}` at depth 0.
    String- and bracket-aware.
    """
    depth_brace = 0
    depth_brack = 0
    in_string = False
    string_char = None
    escape = False
    i = value_start
    while i < len(text):
        c = text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == string_char:
                in_string = False
        else:
            if c == '"' or c == "'":
                in_string = True
                string_char = c
            elif c == "{":
                depth_brace += 1
            elif c == "}":
                if depth_brace == 0:
                    return i  # we hit the object's closing brace
                depth_brace -= 1
            elif c == "[":
                depth_brack += 1
            elif c == "]":
                depth_brack -= 1
            elif c == "," and depth_brace == 0 and depth_brack == 0:
                return i
        i += 1
    return i


def find_top_level_field(obj_text, field):
    """String/bracket-aware search for a top-level `field: VALUE` in `{ ... }`.

    Returns (key_start, value_start, value_end) where value_end is index of comma or close brace.
    Returns None if not found.
    """
    # Skip the outer `{`
    assert obj_text[0] == "{", f"expected '{{' got {obj_text[:20]!r}"
    depth_brace = 0
    depth_brack = 0
    in_string = False
    string_char = None
    escape = False
    i = 0
    pattern = re.compile(r"\b" + re.escape(field) + r":\s*")
    while i < len(obj_text):
        c = obj_text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == string_char:
                in_string = False
            i += 1
            continue
        if c == '"' or c == "'":
            in_string = True
            string_char = c
            i += 1
            continue
        if c == "{":
            depth_brace += 1
            i += 1
            continue
        if c == "}":
            depth_brace -= 1
            i += 1
            continue
        if c == "[":
            depth_brack += 1
            i += 1
            continue
        if c == "]":
            depth_brack -= 1
            i += 1
            continue
        # At top-level of the object?
        if depth_brace == 1 and depth_brack == 0:
            m = pattern.match(obj_text, i)
            if m:
                # Verify previous char is a separator (whitespace or `{` or `,`)
                prev = obj_text[i-1] if i > 0 else "{"
                if prev in " \t\n\r,{":
                    key_start = i
                    value_start = m.end()
                    value_end = parse_object_value_end(obj_text, value_start)
                    return (key_start, value_start, value_end)
        i += 1
    return None


def replace_top_level_field(obj_text, field, new_value_str, indent="    "):
    """Replace the value of `field` in obj_text. If field not present, append it
    just before the closing brace of the object."""
    found = find_top_level_field(obj_text, field)
    if found:
        ks, vs, ve = found
        return obj_text[:vs] + new_value_str + obj_text[ve:]
    # Append new field. Find the closing brace at depth 0.
    depth_brace = 0
    depth_brack = 0
    in_string = False
    string_char = None
    escape = False
    last_nonws = None
    i = 0
    while i < len(obj_text):
        c = obj_text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == string_char:
                in_string = False
        else:
            if c == '"' or c == "'":
                in_string = True
                string_char = c
            elif c == "{":
                depth_brace += 1
            elif c == "}":
                depth_brace -= 1
                if depth_brace == 0:
                    # Insert before this brace
                    # Find position after last non-whitespace before this brace
                    j = i - 1
                    while j > 0 and obj_text[j] in " \t\n\r":
                        j -= 1
                    # Ensure there's a comma after the last value
                    insertion = ""
                    if obj_text[j] != "," and obj_text[j] != "{":
                        insertion = ","
                    insertion += "\n" + indent + field + ": " + new_value_str + ",\n  "
                    return obj_text[:j+1] + insertion + obj_text[i:]
            elif c == "[":
                depth_brack += 1
            elif c == "]":
                depth_brack -= 1
        i += 1
    raise ValueError("could not find closing brace")


# -- Flag array merging --

def parse_flags_array(text):
    """Parse a `flags: [\n ...\n]` section. text starts at `flags: [`.

    Returns (entries: list[str], end_idx: int after `]`)
    """
    assert text.startswith("flags: ["), f"expected 'flags: [' got {text[:30]!r}"
    i = 8  # after `[`
    depth = 1
    in_string = False
    string_char = None
    escape = False
    entries = []
    obj_depth = 0
    obj_start = None
    while i < len(text):
        c = text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == string_char:
                in_string = False
        else:
            if c == '"' or c == "'":
                in_string = True
                string_char = c
            elif c == "{":
                if obj_depth == 0:
                    obj_start = i
                obj_depth += 1
            elif c == "}":
                obj_depth -= 1
                if obj_depth == 0:
                    entries.append(text[obj_start:i+1])
                    obj_start = None
            elif c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    return entries, i + 1
        i += 1
    raise ValueError("flags array not closed")


def is_active(entry_text):
    """An entry is 'active' if it has no `status:` field at the top level."""
    return not re.search(r"\bstatus:", entry_text)


def merge_flags(obj_text, new_flags):
    """Replace active flags in obj_text's `flags: [...]` with new_flags (list of dicts).
    Preserve accepted/resolved entries.

    Returns new obj_text.
    """
    flags_idx = obj_text.find("flags: [")
    if flags_idx == -1:
        # No flags array — append one
        flags_str = "flags: [\n" + ",\n".join(fmt_flag(f) for f in new_flags) + ",\n    ]"
        return replace_top_level_field(obj_text, "flags", flags_str)
    entries, end_after = parse_flags_array(obj_text[flags_idx:])
    end_idx = flags_idx + end_after
    historical = [e for e in entries if not is_active(e)]
    new_lines = [fmt_flag(f) for f in new_flags]
    historical_lines = ["      " + e.strip() for e in historical]
    all_lines = new_lines + historical_lines
    if not all_lines:
        new_array = "flags: []"
    else:
        new_array = "flags: [\n" + ",\n".join(all_lines) + ",\n    ]"
    return obj_text[:flags_idx] + new_array + obj_text[end_idx:]


# -- Field updates from scan JSON --

def js_obj_inline(d):
    """Format a small Python dict as a single-line JS object literal."""
    items = []
    for k, v in d.items():
        if isinstance(v, str):
            items.append(f"{k}: {jstr(v)}")
        elif isinstance(v, bool):
            items.append(f"{k}: {'true' if v else 'false'}")
        elif v is None:
            items.append(f"{k}: null")
        elif isinstance(v, (int, float)):
            items.append(f"{k}: {v}")
        elif isinstance(v, dict):
            items.append(f"{k}: {js_obj_inline(v)}")
        elif isinstance(v, list):
            items.append(f"{k}: {js_arr_inline(v)}")
        else:
            items.append(f"{k}: {jstr(str(v))}")
    return "{ " + ", ".join(items) + " }"


def js_arr_inline(lst):
    parts = []
    for v in lst:
        if isinstance(v, str):
            parts.append(jstr(v))
        elif isinstance(v, bool):
            parts.append("true" if v else "false")
        elif v is None:
            parts.append("null")
        elif isinstance(v, (int, float)):
            parts.append(str(v))
        elif isinstance(v, dict):
            parts.append(js_obj_inline(v))
        elif isinstance(v, list):
            parts.append(js_arr_inline(v))
        else:
            parts.append(jstr(str(v)))
    return "[" + ", ".join(parts) + "]"


def js_metrics(scan_metrics):
    """Format scan.metrics as a JS object spread across multiple lines (matches existing style).

    Codex review 2026-05-21: previously emitted only totalLines + linesByType + a couple
    of count fields, dropping codeLines / dataLines / duplicationAreas even when the scan
    JSON included them. The UI expects all of these; missing fields caused the dashboard's
    aggregate stats to silently fall back to totalLines (correct only by accident) and the
    Duplication card to render literal "undefined". Emit every field the UI consumes.
    """
    lines = ["{"]
    if "codeLines" in scan_metrics and scan_metrics["codeLines"] is not None:
        lines.append(f"      codeLines: {scan_metrics['codeLines']},")
    if "totalLines" in scan_metrics:
        lines.append(f"      totalLines: {scan_metrics['totalLines']},")
    if "dataLines" in scan_metrics and scan_metrics["dataLines"] is not None:
        lines.append(f"      dataLines: {scan_metrics['dataLines']},")
    if "linesByType" in scan_metrics:
        lbt = scan_metrics["linesByType"]
        # Skip null/None entries; quote-string values; numbers raw
        lbt_parts = []
        for k, v in lbt.items():
            if v is None:
                continue
            if isinstance(v, str):
                lbt_parts.append(f"{jstr(k)}: {jstr(v)}")
            elif isinstance(v, bool):
                lbt_parts.append(f"{jstr(k)}: {'true' if v else 'false'}")
            else:
                lbt_parts.append(f"{jstr(k)}: {v}")
        if lbt_parts:
            lines.append(f"      linesByType: {{ {', '.join(lbt_parts)} }},")
    for k in ("components", "pages", "apiRoutes", "duplicationAreas"):
        if k in scan_metrics:
            v = scan_metrics[k]
            if v is None:
                continue  # skip null counts
            lines.append(f"      {k}: {v},")
    fo500 = scan_metrics.get("filesOver500Lines")
    if fo500 is not None:
        if isinstance(fo500, list):
            lines.append(f"      filesOver500: {len(fo500)},")
        else:
            lines.append(f"      filesOver500: {fo500},")
    elif "filesOver500" in scan_metrics:
        v = scan_metrics["filesOver500"]
        if v is not None:
            lines.append(f"      filesOver500: {v},")
    lines.append("    }")
    return "\n".join(lines)


def js_structure(scan_structure):
    """Format scan.structure as a multi-line JS object."""
    lines = ["{"]
    if scan_structure.get("folderMap") is not None:
        lines.append(f"      folderMap: {jstr(scan_structure['folderMap'])},")
    if scan_structure.get("dataFlow") is not None:
        lines.append(f"      dataFlow: {jstr(scan_structure['dataFlow'])},")
    if scan_structure.get("externalCalls") is not None:
        ec = scan_structure["externalCalls"]
        ec_str = "[" + ", ".join(jstr(s) for s in ec) + "]"
        lines.append(f"      externalCalls: {ec_str},")
    if scan_structure.get("sharedUtils") is not None:
        su = scan_structure["sharedUtils"]
        su_str = "[" + ", ".join(jstr(s) for s in su) + "]"
        lines.append(f"      sharedUtils: {su_str},")
    if scan_structure.get("duplication") is not None:
        dup = scan_structure["duplication"]
        dup_str = "[" + ", ".join(jstr(s) for s in dup) + "]"
        lines.append(f"      duplication: {dup_str},")
    lines.append("    }")
    return "\n".join(lines)


def js_tech(scan):
    """Build tech object literal from scan top-level fields."""
    fields = []
    for src_key, label in [
        ("frontend", "frontend"),
        ("backend", "backend"),
        ("dataStorage", "dataStorage"),
        ("integrations", "integrations"),
        ("auth", "auth"),
        ("testing", "testing"),
        ("hosting", "hosting"),
    ]:
        v = scan.get(src_key)
        if v is None or v == "":
            continue
        fields.append(f"      {label}: {jstr(v)},")
    if not fields:
        return None
    return "{\n" + "\n".join(fields) + "\n    }"


def update_app(obj_text, scan, app_name):
    """Update an existing app object literal with scan data.

    Updates: lastUpdated, scanVersion, flags (preserve accepted/resolved),
             tech (if changed), metrics, structure (if present).
    """
    # 1) Merge flags (preserves accepted/resolved)
    flags = scan.get("flags", [])
    obj_text = merge_flags(obj_text, flags)

    # 2) lastUpdated
    obj_text = replace_top_level_field(obj_text, "lastUpdated", jstr(SCAN_DATE))

    # 3) lastScanned (keep in sync; existing files use lastScanned)
    obj_text = replace_top_level_field(obj_text, "lastScanned", jstr(SCAN_DATE))

    # 4) scanVersion
    obj_text = replace_top_level_field(obj_text, "scanVersion", jstr(SCAN_VERSION))

    # 5) tech — replace whole object if scan provides info
    new_tech = js_tech(scan)
    if new_tech:
        obj_text = replace_top_level_field(obj_text, "tech", new_tech)

    # 6) envSecrets
    if scan.get("envSecrets"):
        es = scan["envSecrets"]
        obj_text = replace_top_level_field(
            obj_text, "envSecrets", "[" + ", ".join(jstr(s) for s in es) + "]"
        )

    # 7) metrics — replace with scan values, but carry over curated-only keys
    #    (codeLines / dataLines / duplicationAreas / linesByType) the CLAUDE.md-derived
    #    scans never provide, so a merge doesn't silently drop them from hand-curated
    #    entries (index.html renders a Duplication tile from duplicationAreas).
    if scan.get("metrics"):
        merged = dict(scan["metrics"])
        loc = find_top_level_field(obj_text, "metrics")
        if loc:
            existing = obj_text[loc[1]:loc[2]]
            for key in ("codeLines", "dataLines", "duplicationAreas", "filesOver500"):
                if key not in merged:
                    km = re.search(r'\b%s:\s*(\d+)' % key, existing)
                    if km:
                        merged[key] = int(km.group(1))
            if "linesByType" not in merged:
                lm = re.search(r'linesByType:\s*(\{[^{}]*\})', existing)
                if lm:
                    try:
                        merged["linesByType"] = json.loads(lm.group(1))
                    except ValueError:
                        pass
        obj_text = replace_top_level_field(obj_text, "metrics", js_metrics(merged))

    # 8) structure
    if scan.get("structure"):
        obj_text = replace_top_level_field(obj_text, "structure", js_structure(scan["structure"]))

    # 8b) strengths (v7.0) — replace whenever the scan provides one; each scan's
    #     strengths line reflects the codebase as of that scan.
    if scan.get("strengths"):
        obj_text = replace_top_level_field(obj_text, "strengths", jstr(scan["strengths"]))

    # 9) repoUrl (keep current — sometimes scan disagrees with dashboard intentionally).
    #    url: same rule, EXCEPT fill it when currently null — a curated URL is never
    #    overwritten, but auto-created skeleton entries get theirs from the scan.
    if scan.get("url"):
        loc = find_top_level_field(obj_text, "url")
        if loc and obj_text[loc[1]:loc[2]].strip() == "null":
            obj_text = replace_top_level_field(obj_text, "url", jstr(scan["url"]))
    return obj_text


def make_new_app_entry(scan, app_name, category, description, completion=None, next_action=None):
    """Build a fresh app object literal for a project not yet in APPS."""
    lines = []
    lines.append("  {")
    lines.append(f"    name: {jstr(app_name)},")
    lines.append(f"    category: {jstr(category)},")
    url = scan.get("url")
    if url:
        lines.append(f"    url: {jstr(url)},")
    else:
        lines.append("    url: null,")
    lines.append(f"    description: {jstr(description)},")
    if completion is not None:
        lines.append(f"    completion: {completion},")
    lines.append(f"    nextAction: {jstr(next_action) if next_action else 'null'},")
    lines.append("    scanned: true,")
    lines.append(f"    repoVisibility: {jstr(scan.get('repoVisibility','private'))},")
    if scan.get("repoUrl"):
        lines.append(f"    repoUrl: {jstr(scan['repoUrl'])},")
    lines.append(f"    lastUpdated: {jstr(SCAN_DATE)},")
    lines.append(f"    lastScanned: {jstr(SCAN_DATE)},")
    lines.append(f"    scanVersion: {jstr(SCAN_VERSION)},")
    tech = js_tech(scan)
    if tech:
        lines.append(f"    tech: {tech},")
    if scan.get("envSecrets"):
        es = scan["envSecrets"]
        lines.append("    envSecrets: [" + ", ".join(jstr(s) for s in es) + "],")
    flags = scan.get("flags", [])
    if flags:
        lines.append("    flags: [")
        lines.append(",\n".join(fmt_flag(f) for f in flags) + ",")
        lines.append("    ],")
    else:
        lines.append("    flags: [],")
    if scan.get("metrics"):
        lines.append(f"    metrics: {js_metrics(scan['metrics'])},")
    if scan.get("strengths"):
        lines.append(f"    strengths: {jstr(scan['strengths'])},")
    if scan.get("structure"):
        lines.append(f"    structure: {js_structure(scan['structure'])},")
    lines.append("  }")
    return "\n".join(lines)


def main():
    global SCAN_DATE, SCAN_VERSION, SLUG_TO_APP_NAME
    parser = argparse.ArgumentParser(description="Merge scan JSONs into data/apps.js.")
    parser.add_argument("--date", default=None, help="Scan date (YYYY-MM-DD). Defaults to today (UTC).")
    parser.add_argument("--only-slug", default=None, help="Only merge this slug's scan; leave every other app entry (and its lastScanned) untouched.")
    args = parser.parse_args()

    SCAN_DATE = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    config = load_config()
    SCAN_VERSION = detect_scan_version(resolve_prompt_path(config))
    print(f"Phase C update: date={SCAN_DATE}, scan version={SCAN_VERSION}")
    # slug -> displayName for all configured projects. None = "needs a new entry"
    # only for slugs in the legacy SLUG_TO_APP_NAME set (kept below for backward compat).
    SLUG_TO_APP_NAME = {p["slug"]: p["displayName"] for p in config["projects"]}

    if not APPS_JS.exists():
        # First run on a fresh clone — the repo ships only data/apps.example.js.
        # Bootstrap an empty APPS array; every configured project merges in as new.
        APPS_JS.write_text(
            "// data/apps.js — generated and updated by scans/phase_c_update.py.\n"
            "// Bootstrapped empty on first run; see data/apps.example.js for the entry shape.\n"
            "window.APPS = [\n];\n",
            encoding="utf-8",
        )
        print(f"BOOTSTRAP: {APPS_JS} did not exist — created empty APPS array (first run).")

    content = APPS_JS.read_text(encoding="utf-8")
    backup = APPS_JS.with_suffix(".js.phasec.bak")
    backup.write_text(content, encoding="utf-8")
    print(f"Backup -> {backup}")

    report = []

    # Process existing apps first
    new_app_entries = []
    for slug, app_name in SLUG_TO_APP_NAME.items():
        if args.only_slug and slug != args.only_slug:
            continue
        scan_path = SCANS / f"{slug}-{SCAN_DATE}.json"
        if not scan_path.exists():
            print(f"SKIP {slug}: no scan file")
            continue
        scan = json.loads(scan_path.read_text(encoding="utf-8"))

        if app_name is None:
            # NEW APP — defer until we know where to add
            new_app_entries.append((slug, scan))
            continue

        block = find_app_block(content, app_name)
        if block is None:
            print(f"WARN  {slug}: app name '{app_name}' not found in APPS — adding as new")
            new_app_entries.append((slug, scan))
            continue

        start, end = block
        obj_text = content[start:end]

        # Count active flags before
        flags_idx = obj_text.find("flags: [")
        active_before = 0
        if flags_idx != -1:
            entries, _ = parse_flags_array(obj_text[flags_idx:])
            active_before = sum(1 for e in entries if is_active(e))
            historical = sum(1 for e in entries if not is_active(e))
        else:
            historical = 0

        new_obj = update_app(obj_text, scan, app_name)

        # Count active flags after
        flags_idx2 = new_obj.find("flags: [")
        if flags_idx2 != -1:
            entries2, _ = parse_flags_array(new_obj[flags_idx2:])
            active_after = sum(1 for e in entries2 if is_active(e))
        else:
            active_after = 0

        content = content[:start] + new_obj + content[end:]
        report.append(
            f"OK    {slug:<22s} -> {app_name:<30s} flags {active_before:2d} -> {active_after:2d}  ({historical} historical preserved)"
        )

    # Add new app entries — insert them before the closing `];` of the APPS array.
    if new_app_entries:
        apps_start = content.find("window.APPS = [")
        if apps_start == -1:
            # Older builds might still use `const APPS = [` (pre-refactor); be tolerant.
            apps_start = content.find("const APPS = [")
            if apps_start == -1:
                raise RuntimeError("APPS array not found in apps.js")
            i = apps_start + len("const APPS = ")
        else:
            i = apps_start + len("window.APPS = ")
        depth = 0
        in_string = False
        string_char = None
        escape = False
        end_idx = None
        while i < len(content):
            c = content[i]
            if in_string:
                if escape:
                    escape = False
                elif c == "\\":
                    escape = True
                elif c == string_char:
                    in_string = False
            else:
                if c == '"' or c == "'":
                    in_string = True
                    string_char = c
                elif c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
                    if depth == 0:
                        end_idx = i
                        break
            i += 1
        if end_idx is None:
            raise RuntimeError("APPS array close `]` not found")

        # Build entries — pull display name + category from config.projects.
        slug_to_proj = {p["slug"]: p for p in config["projects"]}
        for slug, scan in new_app_entries:
            proj = slug_to_proj.get(slug, {})
            display_name = proj.get("displayName", slug)
            category = proj.get("category", "Other").capitalize()
            description = scan.get("scope", "") or proj.get("description", "")
            entry = make_new_app_entry(scan, display_name, category, description)

            # Insert before `]`. The character at end_idx is `]`. We need to insert ",\n<entry>\n"
            # The text right before `]` should have the previous entry's `}` and possibly already a comma.
            # Walk back to last non-ws char.
            j = end_idx - 1
            while j > 0 and content[j] in " \t\n\r":
                j -= 1
            # If the char is `}`, we need to add a comma (if not already)
            insertion_prefix = ""
            if content[j] == "}":
                # Check whether there's already a comma after it
                k = j + 1
                while k < end_idx and content[k] in " \t\n\r":
                    k += 1
                if k == end_idx:
                    # No comma — add one
                    insertion_prefix = ","
            insertion = insertion_prefix + "\n" + entry + ",\n"
            content = content[:j+1] + insertion + content[j+1:]
            # Recompute end_idx after insertion
            end_idx = end_idx + len(insertion)
            report.append(f"NEW   {slug:<22s} added as new APPS entry")

    # Write final, then verify the result is still parseable JS. A merge bug here
    # corrupts the served dashboard dataset, so fail loud and restore the backup.
    APPS_JS.write_text(content, encoding="utf-8")
    check = subprocess.run(["node", "--check", str(APPS_JS)], capture_output=True, text=True)
    if check.returncode != 0:
        APPS_JS.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
        sys.exit(f"ERROR: merged apps.js failed `node --check` — restored backup.\n{check.stderr.strip()}")
    print(f"\nWrote {APPS_JS} ({len(content)} chars) — node --check passed")
    print()
    for line in report:
        print(line)


if __name__ == "__main__":
    main()
