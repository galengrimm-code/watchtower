# Contributing to Watchtower

Thanks for considering a contribution. This project is run as a single-maintainer
artifact, so the bar is "useful to me and at least one other person" rather than
"feature-complete." Small, well-scoped PRs land faster than ambitious rewrites.

## What I'm looking for

- **New scan checks** that close a real gap (e.g., a misconfiguration that bit you
  in production). Include the threat model, not just the regex.
- **Cross-platform fixes** for the scripts. Watchtower was built on Windows + Git
  Bash; macOS and Linux fixes are welcome.
- **Dashboard improvements** that work without changing the data schema.
- **Docs** — examples, troubleshooting, install steps for environments I haven't
  tried.

## What's out of scope

- Forking the methodology into a different "framework" (write your own and link to
  it, that's better).
- Adding heavy dependencies. The scripts are intentionally stdlib-only.
- Replacing `/codex` with a different second-opinion tool. Codex is the chosen
  adversarial reviewer; alternative providers are fine as separate PRs but won't
  replace it.
- Removing the manual-config requirement in favor of auto-discovery. Watchtower
  treats the project list as a human-curated artifact on purpose.

## Proposing a new check

1. Open an issue first with the check name, threat model, and example.
2. Reference the OWASP Top 10 (2021) category if applicable. Not every check maps
   to OWASP — that's fine, leave the field unset.
3. If the check is non-obvious or expensive (network probes, large file reads),
   include a flag to make it opt-in.

## PR checklist

- [ ] One concern per PR. Refactors and new features in the same PR get split.
- [ ] Tests if the change touches `scans/*.py` or `scans/*.js`. Manual repro
      instructions if the change is dashboard-only.
- [ ] No new dependencies without a written reason.
- [ ] No personal data in examples (folder names, domains, secrets — including
      partial secrets like prefixes/suffixes).
- [ ] Updated `CHANGELOG.md` under "Unreleased" if user-visible.

## Reporting a security issue

Don't file a public issue for security bugs in Watchtower itself (irony noted).
Open a private security advisory via GitHub's Security tab.

## Communication

GitHub issues for everything else. Replies happen on a triweekly-ish schedule —
this is a side project, not a job.
