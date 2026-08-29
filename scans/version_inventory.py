#!/usr/bin/env python3
"""
version_inventory.py — framework/runtime version inventory for the fleet.

For every configured project, records the RESOLVED version (from package-lock.json,
not the package.json caret range) of a curated set of framework/runtime packages
the app DIRECTLY declares, plus the declared Node engine. Writes data/versions.js
(`window.VERSIONS`) for the dashboard's Framework Versions panel.

Design decisions (each closes a real failure mode):
  - Resolve from the lockfile, not package.json ranges: "^15.5.0" covers both a
    vulnerable 15.5.23 and a patched 15.5.24 — the range answers nothing.
  - Gate on DIRECT declaration: an npm-v3 `node_modules/<dep>` entry is an install
    location, so a hoisted TRANSITIVE dep appears there too. Only report a dep the
    app actually declares in package.json, or the matrix shows deps apps don't use.
  - Scan functions/ too: Firebase apps declare backend deps (firebase-admin,
    stripe, @anthropic-ai/sdk) under functions/, with their own lockfile — that's
    the DEPLOYED version. Root-only scanning would miss or mis-resolve them.
  - Distinguish absent vs unparseable lockfile: a corrupt lockfile must not
    silently degrade to a declared range dressed up as resolved.
  - Node isn't a lockfile dep: read from engines (functions/ first = deployed),
    marked DECLARED.

Per-dep source `s`: "lock" (exact, from lockfile) · "declared" (range, no/absent
lockfile) · "lock-error" (lockfile present but unparseable — range shown, flagged).

Run:  python scans/version_inventory.py [--date YYYY-MM-DD]
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CONFIG = ROOT / "watchtower.config.json"
OUT = ROOT / "data" / "versions.js"

# Curated, CVE-relevant packages. Order = matrix column order; the dashboard drops
# any column no app uses. Extend as the stack grows.
CURATED = [
    "next", "react", "react-dom", "vite", "react-router-dom",
    "@supabase/supabase-js", "firebase", "firebase-admin", "stripe",
    "@anthropic-ai/sdk",
]

# Where deps may be declared: root (frontend) then functions/ (deployed backend).
# functions/ is scanned second so a backend dep declared there wins the cell.
DEP_ROOTS = ["", "functions"]


def read_json_status(p):
    """(data, status) with status in {ok, absent, error} — so a malformed-but-present
    lockfile is distinguishable from a missing one."""
    p = Path(p)
    if not p.exists():
        return None, "absent"
    try:
        return json.loads(p.read_text(encoding="utf-8")), "ok"
    except Exception:
        return None, "error"


def lock_version(lock, dep):
    """Exact resolved version of dep from an npm package-lock (v3 `packages`,
    fallback v1/v2 `dependencies`). None if not resolved."""
    if not lock:
        return None
    pkgs = lock.get("packages")
    if isinstance(pkgs, dict) and pkgs:
        e = pkgs.get(f"node_modules/{dep}")
        return e.get("version") if e else None
    deps = lock.get("dependencies")
    if isinstance(deps, dict):
        e = deps.get(dep)
        return e.get("version") if e else None
    return None


def direct_deps(pkg):
    """Names the package.json DIRECTLY declares (deps + devDeps)."""
    d = {}
    for k in ("dependencies", "devDependencies"):
        d.update(pkg.get(k, {}) or {})
    return d


def collect_deps(proj_dir):
    """{dep: {"v": version, "s": source}} for curated deps the app directly declares,
    scanning root then functions/. Later roots override earlier for the same dep."""
    out = {}
    for sub in DEP_ROOTS:
        base = proj_dir / sub if sub else proj_dir
        pkg, pstat = read_json_status(base / "package.json")
        if pstat != "ok":
            continue
        declared = direct_deps(pkg)
        lock, lstat = read_json_status(base / "package-lock.json")
        for dep in CURATED:
            if dep not in declared:
                continue
            if lstat == "ok":
                v = lock_version(lock, dep)
                out[dep] = {"v": v, "s": "lock"} if v else {"v": declared[dep], "s": "declared"}
            elif lstat == "error":
                out[dep] = {"v": declared[dep], "s": "lock-error"}
            else:  # absent
                out[dep] = {"v": declared[dep], "s": "declared"}
    return out


def node_engine(proj_dir):
    """Declared Node runtime — functions/ engines (deployed, per v7.3) then root."""
    fn, st = read_json_status(proj_dir / "functions" / "package.json")
    if st == "ok" and fn.get("engines", {}).get("node"):
        return fn["engines"]["node"], "functions/engines"
    root, st = read_json_status(proj_dir / "package.json")
    if st == "ok" and root.get("engines", {}).get("node"):
        return root["engines"]["node"], "engines"
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default="")
    args = ap.parse_args()

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    portfolio_root = Path(config["portfolioRoot"])

    versions = {}
    for proj in config["projects"]:
        d = portfolio_root / proj["folder"]
        if not d.is_dir():
            continue
        pkg, st = read_json_status(d / "package.json")
        if st != "ok":
            continue  # not a JS project — nothing to inventory
        deps = collect_deps(d)
        if not deps and not (d / "functions").is_dir():
            # a JS project that declares none of the curated deps; still record so
            # its Node engine shows, but skip if truly nothing.
            pass
        node, node_src = node_engine(d)
        entry = {"deps": deps}
        if node:
            entry["node"] = node
            entry["nodeSource"] = node_src
        # only record apps that yielded at least one tracked signal
        if deps or node:
            versions[proj["displayName"]] = entry

    body = json.dumps(versions, indent=2, ensure_ascii=False)
    header = (
        "// Framework/runtime version inventory. Per-dep source `s`: lock = exact\n"
        "// (from package-lock.json), declared = range (no lockfile), lock-error =\n"
        "// lockfile present but unparseable. Only DIRECTLY-declared deps are listed\n"
        "// (root + functions/). node = declared engine, not a lockfile value.\n"
        "// Generated by scans/version_inventory.py — do not hand-edit.\n"
        "// window.VERSIONS[displayName] = { deps: {pkg: {v, s}}, node, nodeSource }\n"
    )
    if args.date:
        header += f"// scannedAt: {args.date}\n"
    OUT.write_text(header + f"window.VERSIONS = {body};\n", encoding="utf-8")

    # summary
    lock_n = sum(1 for v in versions.values() for x in v["deps"].values() if x["s"] == "lock")
    err_n = sum(1 for v in versions.values() for x in v["deps"].values() if x["s"] == "lock-error")
    dec_n = sum(1 for v in versions.values() for x in v["deps"].values() if x["s"] == "declared")
    print(f"Wrote {OUT.relative_to(ROOT)} — {len(versions)} apps | dep cells: {lock_n} lock, {dec_n} declared, {err_n} lock-error")
    for dep in CURATED:
        n = sum(1 for v in versions.values() if dep in v["deps"])
        if n:
            print(f"  {dep:26} {n} apps")
    return 0


if __name__ == "__main__":
    sys.exit(main())
