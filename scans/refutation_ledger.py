#!/usr/bin/env python3
"""Refutation precision ledger: verifier verdicts per check key, across scan cycles (v7.10).

Phase B.65 sends flags to a fresh verifier that tries to refute them. Until v7.10 its
verdicts were annotated on the report and then forgotten, so nothing ever learned which
checks are reliable. Eighteen PROVISIONAL checks sat on the Watch List since June (v7.1)
and November (v7.9) with no path out, and no noisy check had a path down.

This script keeps the verdicts. `record` appends one line per verifier verdict to
scans/refutation-ledger.jsonl, joined to that cycle's scan JSON so each verdict carries
its check key (category), lane and severity. `report` aggregates per check key and
prints a recommendation. Recommendations are never applied: promoting or demoting a check
is a prompt edit the owner approves.

The ledger stores no flag text. A verdict is identified by a hash of
(date, slug, category, text prefix), which makes `record` idempotent. A second `finding`
hash leaves out the date, so `report` counts distinct findings: one unchanged finding that
stands three months running is one finding, not three.

Calibration resets: when a check's text is edited (tightened, promoted), add
"<category>": "YYYY-MM-DD" to scans/refutation-resets.json. `report` ignores that check's
verdicts dated before the reset, so evidence about the old rule never judges the new one.
Each row also records the prompt version it was gathered under.

The sample is biased by design: B.65 challenges P1/P2 Active Flags and PROVISIONAL Watch
List items, nothing else. Recommendations describe that sample, not the whole check.

Usage:
  python -I scans/refutation_ledger.py record --date 2026-12-07 --dir <scratchpad>/refutation
  python -I scans/refutation_ledger.py report
  python -I scans/refutation_ledger.py report --json <scratchpad>/precision.json

Verifier files: <slug>.json, or <slug>.b2.json, <slug>.b3.json ... when Phase B.65 split a
project into batches. Each holds the JSON array the B.65 brief defines.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

WATCHTOWER_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = WATCHTOWER_ROOT / "watchtower.config.json"
LEDGER_PATH = WATCHTOWER_ROOT / "scans" / "refutation-ledger.jsonl"
RESETS_PATH = WATCHTOWER_ROOT / "scans" / "refutation-resets.json"

VERDICTS = {"STANDS", "DOWNGRADE", "UNRESOLVED", "REJECT"}
BATCH_RE = re.compile(r"^(?P<slug>.+?)(?:\.b\d+)?$")
PROVISIONAL_ROW_RE = re.compile(r"^\|\s*([a-z0-9][a-z0-9-]*)\s*\|[^|]*\|\s*PROVISIONAL\b", re.M)
DISPUTED_RE = re.compile(r"^DISPUTED:[^;]*;\s*owner review pending\.?\s*", re.I)
# Scan text opens with a lifecycle word that changes month to month ("NEW. ...", then
# "CARRIED. ..."). Strip it for the cross-cycle finding identity only.
LIFECYCLE_RE = re.compile(r"^(?:new|carried|regression|still open)\b\s*(?:\(provisional\))?\s*[.:-]?\s*")
PREFIX_CHARS = 60
MIN_PREFIX = 12
TIER_RE = re.compile(r"^P([1-4])$")

# Thresholds. Deliberately conservative: a promotion moves a check's findings into Active
# Flags and the grades, so it needs decided evidence from more than one cycle and from
# several distinct findings.
MIN_DECIDED = 3          # distinct findings with a STANDS / DOWNGRADE / REJECT verdict
PROMOTE_MIN_CYCLES = 2   # cycles holding a decided verdict (an UNRESOLVED-only cycle does not count)
PROMOTE_MIN_REAL = 0.8
NOISY_MIN_DECIDED = 4
NOISY_MAX_REAL = 0.5
INFLATED_MIN_RATE = 0.5


def norm(text):
    text = DISPUTED_RE.sub("", str(text or ""))
    text = re.sub(r"[`*_]", "", text)
    return " ".join(text.lower().split())


def _hash(*parts):
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


def verdict_key(date, slug, category, flag_text):
    return _hash(date, slug, category or "", norm(flag_text)[:PREFIX_CHARS])


def finding_key(slug, category, flag_text):
    return _hash(slug, category or "", LIFECYCLE_RE.sub("", norm(flag_text))[:PREFIX_CHARS])


def load_ledger():
    rows = []
    if LEDGER_PATH.exists():
        for n, line in enumerate(LEDGER_PATH.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                sys.exit(f"ERROR: {LEDGER_PATH.name}:{n} is not valid JSON; fix it by hand")
    return rows


def load_resets():
    if not RESETS_PATH.exists():
        return {}
    data = json.loads(RESETS_PATH.read_text(encoding="utf-8"))
    bad = [k for k, v in data.items() if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(v))]
    if bad:
        sys.exit(f"ERROR: {RESETS_PATH.name}: dates must be YYYY-MM-DD for {bad}")
    return data


def _prompt_text():
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return (Path(config["promptsRoot"]) / "security-scan-prompt.md").read_text(encoding="utf-8")


def prompt_version(text):
    m = re.search(r"^# Security Scan Prompt (v\d+\.\d+)", text, re.M)
    return m.group(1) if m else None


def provisional_keys(text):
    """Read the PROVISIONAL set from the prompt's taxonomy table, so it cannot drift from it."""
    keys = set(PROVISIONAL_ROW_RE.findall(text))
    if not keys:
        sys.exit("ERROR: found no PROVISIONAL rows in the prompt; the taxonomy table format changed")
    return keys


def match_flag(entry, scan):
    """Find the one flag this verdict is about. None when zero or several match: never guess."""
    cat = entry.get("category")
    want = norm(entry.get("text_start"))[:PREFIX_CHARS]
    if len(want) < MIN_PREFIX:
        return None
    hits = []
    for lane, items in (("active", scan.get("flags") or []), ("watch", scan.get("watchList") or [])):
        for f in items:
            if f.get("category") == cat and norm(f.get("text")).startswith(want):
                hits.append((lane, f))
    return hits[0] if len(hits) == 1 else None


def bad_tier(entry, flag):
    """A DOWNGRADE must name a tier strictly below the flag's severity."""
    m = TIER_RE.match(str(entry.get("tier") or ""))
    if not m:
        return f"DOWNGRADE without a P1-P4 tier ({entry.get('tier')!r})"
    cur = TIER_RE.match(str(flag.get("severity") or ""))
    if cur and int(m.group(1)) <= int(cur.group(1)):
        return f"DOWNGRADE to {entry.get('tier')} is not below {flag.get('severity')}"
    return None


def cmd_record(args):
    src = Path(args.dir)
    if not src.is_dir():
        sys.exit(f"ERROR: {src} is not a directory")
    existing = {r["key"]: r["verdict"] for r in load_ledger()}
    version = prompt_version(_prompt_text())
    pending, dropped = {}, set()
    unmatched, bad, conflicts = [], [], []
    for path in sorted(src.glob("*.json")):
        slug = BATCH_RE.match(path.stem).group("slug")
        scan_path = WATCHTOWER_ROOT / "scans" / f"{slug}-{args.date}.json"
        if not scan_path.exists():
            bad.append(f"{path.name}: no scan JSON {scan_path.name}")
            continue
        try:
            verdicts = json.loads(path.read_text(encoding="utf-8"))
            scan = json.loads(scan_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            bad.append(f"{path.name}: unreadable ({type(exc).__name__})")
            continue
        if not isinstance(verdicts, list):
            bad.append(f"{path.name}: not a JSON array")
            continue
        for i, e in enumerate(verdicts):
            if not isinstance(e, dict):
                bad.append(f"{path.name}[{i}]: not an object")
                continue
            v = str(e.get("verdict", "")).upper()
            if v not in VERDICTS:
                bad.append(f"{path.name}[{i}]: verdict {e.get('verdict')!r} for {e.get('category')!r}")
                continue
            hit = match_flag(e, scan)
            if hit is None:
                unmatched.append(f"{slug}/{e.get('category')}: {norm(e.get('text_start'))[:PREFIX_CHARS]!r}")
                continue
            lane, flag = hit
            cat = flag.get("category")
            if v == "DOWNGRADE":
                why = bad_tier(e, flag)
                if why:
                    bad.append(f"{path.name}[{i}] {slug}/{cat}: {why}")
                    continue
            key = verdict_key(args.date, slug, cat, flag.get("text"))
            if key in existing:
                if existing[key] != v:
                    conflicts.append(f"{slug}/{cat}: ledger has {existing[key]}, {path.name} says {v} "
                                     "(ledger kept; correct it by hand)")
                continue
            if key in pending:
                if pending[key]["verdict"] != v:
                    conflicts.append(f"{slug}/{cat}: batches disagree ({pending[key]['verdict']} vs {v}); "
                                     "neither recorded")
                    dropped.add(key)
                continue
            pending[key] = {
                "key": key,
                "finding": finding_key(slug, cat, flag.get("text")),
                "date": args.date,
                "promptVersion": version,
                "slug": slug,
                "category": cat,
                "lane": lane,
                "severity": flag.get("severity"),
                "scannerVerdict": flag.get("verdict"),
                "verdict": v,
                "tier": e.get("tier") if v == "DOWNGRADE" else None,
            }
    added = [r for k, r in pending.items() if k not in dropped]
    if added and not args.dry_run:
        with LEDGER_PATH.open("a", encoding="utf-8", newline="\n") as fh:
            for r in added:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"recorded {len(added)} verdict(s){' (dry run)' if args.dry_run else ''}; "
          f"{len(unmatched)} unmatched; {len(bad)} unreadable; {len(conflicts)} conflict(s)")
    for u in unmatched:
        print(f"  UNMATCHED {u}")
    for b in bad:
        print(f"  UNREADABLE {b}")
    for c in conflicts:
        print(f"  CONFLICT {c}")
    # Reported, not fatal: B.65 never blocks the pipeline.
    return 0


def aggregate(rows, provisional, resets=None):
    resets = resets or {}
    by = {}
    for r in rows:
        if r["date"] < resets.get(r["category"], ""):
            continue
        a = by.setdefault(r["category"], {
            "category": r["category"], "provisional": r["category"] in provisional,
            "decidedDates": set(), "decidedFindings": set(),
            "STANDS": 0, "DOWNGRADE": 0, "UNRESOLVED": 0, "REJECT": 0,
        })
        a[r["verdict"]] += 1
        if r["verdict"] != "UNRESOLVED":
            a["decidedDates"].add(r["date"])
            a["decidedFindings"].add(r.get("finding") or r.get("key"))
    out = []
    for a in by.values():
        decided = a["STANDS"] + a["DOWNGRADE"] + a["REJECT"]
        distinct = len(a["decidedFindings"])
        cycles = len(a["decidedDates"])
        real = (a["STANDS"] + a["DOWNGRADE"]) / decided if decided else None
        infl = a["DOWNGRADE"] / decided if decided else None
        recs = []
        if distinct < MIN_DECIDED:
            recs.append("collecting")
        else:
            if decided >= NOISY_MIN_DECIDED and real < NOISY_MAX_REAL:
                recs.append("NOISY in the challenged sample: tighten the FLAG condition")
            elif (a["provisional"] and cycles >= PROMOTE_MIN_CYCLES and a["REJECT"] == 0
                  and real >= PROMOTE_MIN_REAL):
                recs.append("PROMOTE candidate: move out of PROVISIONAL (owner approves a prompt edit)")
            # Independent of the two above: a promotable check can still run hot on severity.
            if decided >= NOISY_MIN_DECIDED and infl >= INFLATED_MIN_RATE:
                recs.append("INFLATED: severity guidance runs high")
            if not recs:
                recs.append("holding")
        out.append({
            "category": a["category"], "provisional": a["provisional"], "cycles": cycles,
            "distinctFindings": distinct,
            "challenged": decided + a["UNRESOLVED"], "stands": a["STANDS"],
            "downgrade": a["DOWNGRADE"], "unresolved": a["UNRESOLVED"], "reject": a["REJECT"],
            "realRate": None if real is None else round(real, 2),
            "resetSince": resets.get(a["category"]),
            "recommendation": "; ".join(recs),
        })
    order = {"N": 0, "P": 1, "I": 2, "h": 3, "c": 4}
    out.sort(key=lambda x: (order.get(x["recommendation"][0], 9), -x["challenged"], x["category"]))
    return out


def cmd_report(args):
    rows = load_ledger()
    stats = aggregate(rows, provisional_keys(_prompt_text()), load_resets())
    dates = sorted({r["date"] for r in rows})
    print("Sample: B.65 scope only (P1/P2 Active Flags + PROVISIONAL Watch List items).")
    print(f"REFUTATION PRECISION - {len(rows)} verdicts, {len(dates)} cycle(s)"
          + (f" ({dates[0]} .. {dates[-1]})" if dates else ""))
    if not stats:
        print("_No verdicts recorded yet._")
    for s in stats:
        rr = "-" if s["realRate"] is None else f"{s['realRate']:.2f}"
        since = f" since reset {s['resetSince']}" if s["resetSince"] else ""
        print(f"  {s['category']}{' [PROVISIONAL]' if s['provisional'] else ''}: "
              f"{s['challenged']} challenged ({s['distinctFindings']} distinct decided) over "
              f"{s['cycles']} cycle(s){since} - "
              f"S{s['stands']} D{s['downgrade']} U{s['unresolved']} R{s['reject']}, "
              f"real {rr} -> {s['recommendation']}")
    if args.json:
        Path(args.json).write_text(json.dumps({"dates": dates, "checks": stats}, indent=2),
                                   encoding="utf-8")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record", help="append this cycle's verifier verdicts")
    r.add_argument("--date", required=True, help="cycle date, YYYY-MM-DD (matches scan JSON names)")
    r.add_argument("--dir", required=True, help="directory holding <slug>[.bN].json verifier files")
    r.add_argument("--dry-run", action="store_true", help="match and count, write nothing")
    p = sub.add_parser("report", help="per-check precision and recommendations")
    p.add_argument("--json", help="also write the aggregate to this path")
    args = ap.parse_args()
    if args.cmd == "record" and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
        sys.exit("ERROR: --date must be YYYY-MM-DD")
    return cmd_record(args) if args.cmd == "record" else cmd_report(args)


if __name__ == "__main__":
    sys.exit(main())
