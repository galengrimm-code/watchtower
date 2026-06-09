#!/usr/bin/env python3
"""Pre-commit gate: detect credential-shaped strings in committed/served scan artifacts.

Scans data/*.js and scans/*.json for secret fragments (API keys, OAuth client IDs,
tokens, JWTs, private keys). Per the project guardrail, scan artifacts must refer to
credentials by variable name only -- never any value characters.

Usage:
    python scans/scrub_artifacts.py          # report + exit 1 if anything found
    python scans/scrub_artifacts.py --fix    # redact matches in place, then exit 0

Matched values are NEVER printed -- only file, line number, and pattern name.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (pattern name, regex, replacement used by --fix)
# Patterns require value characters beyond the bare marker so that prose like
# "the AIzaSy marker" or "sk_live keys" never false-positives.
PATTERNS = [
    ("google-api-key", re.compile(r"AIzaSy[A-Za-z0-9_\-]{8,}"), "GOOGLE_API_KEY (value redacted)"),
    ("google-oauth-client-id", re.compile(r"\b\d{11,13}-[a-z0-9]{4,}[\w.\-]*"), "GOOGLE_CLIENT_ID (value redacted)"),
    ("google-oauth-client-prefix", re.compile(r"\b\d{11,13}-(?=\.\.\.|…)"), "GOOGLE_CLIENT_ID (value redacted)"),
    ("stripe-secret-key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}"), "STRIPE_SECRET_KEY (value redacted)"),
    ("stripe-webhook-secret", re.compile(r"\bwhsec_[A-Za-z0-9]{8,}"), "STRIPE_WEBHOOK_SECRET (value redacted)"),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9\-]{8,}"), "ANTHROPIC_API_KEY (value redacted)"),
    ("openai-key", re.compile(r"\bsk-proj-[A-Za-z0-9\-]{8,}"), "OPENAI_API_KEY (value redacted)"),
    ("openai-legacy-key", re.compile(r"\bsk-(?!ant-|proj-)[A-Za-z0-9]{20,}"), "OPENAI_API_KEY (value redacted)"),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"), "GITHUB_TOKEN (value redacted)"),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{12,}"), "AWS_ACCESS_KEY_ID (value redacted)"),
    ("jwt", re.compile(r"\beyJhbGciOi[A-Za-z0-9_\-]{8,}"), "JWT (value redacted)"),
    ("resend-key", re.compile(r"\bre_[A-Za-z0-9]{16,}"), "RESEND_API_KEY (value redacted)"),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{8,}"), "SLACK_TOKEN (value redacted)"),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PRIVATE_KEY (value redacted)"),
]


def target_files():
    files = sorted((ROOT / "data").glob("*.js")) + sorted((ROOT / "scans").glob("*.json"))
    return [f for f in files if f.is_file()]


def main():
    ap = argparse.ArgumentParser(description="Detect/redact secret fragments in scan artifacts.")
    ap.add_argument("--fix", action="store_true", help="Redact matches in place instead of just reporting.")
    args = ap.parse_args()

    findings = 0
    for path in target_files():
        text = path.read_text(encoding="utf-8")
        new_text = text
        for name, rx, replacement in PATTERNS:
            for m in rx.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                print(f"FOUND  {path.relative_to(ROOT)}:{line_no}  [{name}]  ({m.end() - m.start()} chars, value not shown)")
                findings += 1
            if args.fix:
                new_text = rx.sub(replacement, new_text)
        if args.fix and new_text != text:
            path.write_text(new_text, encoding="utf-8")
            print(f"FIXED  {path.relative_to(ROOT)}")

    if findings == 0:
        print(f"CLEAN  {len(target_files())} artifact files scanned, no secret fragments.")
        return 0
    if args.fix:
        print(f"REDACTED  {findings} fragment(s). Re-run without --fix to verify clean.")
        return 0
    print(f"BLOCKED  {findings} secret fragment(s) found. Run with --fix to redact, then re-verify.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
