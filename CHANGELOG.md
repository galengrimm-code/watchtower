# Changelog

All notable changes to the scan methodology. The methodology version is in the
prompt file header (`prompts/security-scan-prompt.md`, line 8) and is the source
of truth — Watchtower itself doesn't have a separate semver. Treat each `v6.x`
prompt bump as a release.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely.

## 2026-06-12 — skill template + onboarding (no prompt change)

The scan prompt is unchanged (still v7.0); this release fixes the public install story so the skill template works on a machine that isn't the author's.

### Added

- **Phase 0.5 (methodology + repo sync)** in the skill template — fast-forward-only `git fetch` + `merge --ff-only` across every project repo, `watchtowerRoot`, and `promptsRoot` before each scan. This is how scan-prompt updates reach you automatically; it also prevents auditing stale code after pushes from another machine. Previously this phase existed only in the author's private skill while the template referenced its output ("Phase 0.5 sync summary") without defining it. Pin `promptsRoot` to a release tag if you want to review prompt changes before adopting them.
- **Public-clone runtime mode** — documented that a plain clone of this repo works as a complete runtime (all data files are gitignored, so `git pull` never conflicts). Phase D now skips commit/push gracefully in this mode. The private-runtime two-repo setup remains the recommended path for portfolios with a commercial app.

### Changed

- **Scheduler-agnostic Phase 0 + install instructions** — the template no longer hardcodes `mcp__scheduled-tasks__*` tool calls (a private MCP nobody else has). Install = drop the skill into `~/.claude/skills/`, then tell Claude Code to schedule a one-time run; Phase 0 re-arms each subsequent run with whatever scheduler fired it.
- README architecture + scan-cycle diagrams and quick start rewritten to match: single-clone setup, Phase 0.5 sync arrow, Phase E in the sequence.

### Fixed (Codex review findings)

- **First-run crash**: `phase_c_update.py` hard-exited when `data/apps.js` didn't exist — the state of every fresh clone. It now bootstraps an empty APPS array and merges all configured projects in as new (verified end-to-end against a simulated fresh clone).
- Phase 0.5's `merge --ff-only "@{u}"` is now quoted — PowerShell parses a bare `@{u}` as a hash literal.
- Public-clone-mode Phase D now states that per-project CLAUDE.md commits (step 5) still run; skipping them left every project repo dirty and tripped the next cycle's dirty-tree gate.
- Quick start notes that the commands are bash (Git Bash on Windows).

## v7.0 — 2026-06-09

Audit-dimension release: silent-failure and memory-growth sweeps, per-app strengths, A–F health grades. Adapted from community "repo audit" prompt patterns.

### Added

- **Swallowed-exception sweep (STEP 1)** — empty `catch {}` / `except: pass` blocks and catch bodies that neither log, rethrow, nor surface the error. New category `swallowed-exception` (P3; escalates to P2 on auth/payment/webhook/data-write paths). Maps to OWASP A09.
- **Unbounded in-memory growth sweep (STEP 1)** — module-level Map/Set/array/object collections written from request handlers with no eviction path (delete/clear/TTL/LRU/max-size). New category `unbounded-growth` (P3; escalates to P2 when keyed by unbounded user input on a long-running server). Complements `serverless-memory-state`, which covers cold-start resets; this covers growth.
- **Strengths line** — STEP 2 JSON gains a required `strengths` field and the SCAN:AUTO block gains a required `## Strengths` heading (enforced by STEP 4): one concrete, verified sentence on what the codebase does well. Renders on the dashboard card and in PDF export. Pipeline: `write_scan_jsons.py` parses it, `phase_c_update.py` merges it into `data/apps.js`.
- **Health grade (A–F)** — each scanned app gets a health ring beside its completion ring, computed from active flag severities (accepted/resolved excluded), files over the 1,500-line threshold, test-framework presence, and scan recency. Click for the deduction breakdown. The formula lives in `scans/grade-model.js` (single source shared by the dashboard and `generate-portfolio-stats.js`, which persists per-scan score history for ▲/▼ trend arrows). Plus: worst-grade-first sort and a Portfolio GPA stat card.
- **Docs-freshness audit** — `scans/check_docs_freshness.py`, a deterministic script (code, not LLM judgment) that validates hand-written doc claims per project: dev commands vs package.json scripts, backticked repo-relative path references vs disk (abbreviated-path suffix matching, cross-root resolution, intentional-nonexistence filtering so "create `x`" and "`y` is missing" lines don't false-positive), SESSION-HANDOFF freshness vs commit history, and `Last reviewed: YYYY-MM-DD` ages. Runs in Phase C with `--merge`; emits at most ONE consolidated P4 `stale-docs` flag per project. New category `stale-docs`.
- **Machine-written `## Dev Commands`** — new SCAN:AUTO heading generated from package.json scripts every scan (STEP 4 now validates 9 headings). Derivable content can't go stale when a machine rewrites it; the prompt's new-file template no longer creates a hand-written duplicate.
- **Client-prefix env grep narrowed** — flags credential-shaped names (SECRET / SERVICE_ROLE / PRIVATE, or ending _KEY / _TOKEN) or credential-looking values, with a documented-client-safe exception list (Supabase anon, Firebase web API, Stripe publishable). `NEXT_PUBLIC_ADMIN_URL` no longer false-positives.

### Changed

- STEP 4 validation now requires 8 headings (added `## Strengths`); blocks missing it re-emit from scratch, same as any other structural gap.
- Pipeline: `scans/write_scan_jsons.py` now parses each project's SCAN:AUTO `## Metrics`
  section into the scan JSON (`metrics` key: `totalLines`, `components`, `pages`,
  `apiRoutes`, `filesOver500`). `filesOver500` keeps its legacy key name but counts
  files over the v6.8 1,500-line threshold, converting pre-v6.8 lists to the current
  semantics (mixed legacy formats handled: backticked or plain filenames, annotated
  size parens, count-only lines, v6.8 heading variants, pre-template inline blocks).
  `phase_c_update.py` merges scan metrics into existing entries while preserving
  curated-only keys (`codeLines`, `dataLines`, `duplicationAreas`, `linesByType`,
  and `filesOver500` when the scan can't derive one). Auto-created dashboard entries
  now show code metrics from their first scan instead of "Not scanned", and all
  entries' metrics refresh on every merge.
- Pipeline: `scans/write_scan_jsons.py` now parses each project's SCAN:AUTO `## Tech Stack`
  table and `Production URL` line into the scan JSON (top-level `frontend`/`backend`/
  `dataStorage`/`integrations`/`auth`/`testing`/`hosting` keys + `url`). `phase_c_update.py`
  consumes them: tech refreshes on every merge (explicit "None" values are kept — they're
  data, not empty cells), and `url` is filled on existing entries only when currently
  `null` (a curated dashboard URL is never overwritten). Dashboard entries auto-created
  for newly scanned projects now arrive with tech stack and live URL instead of empty
  skeletons.
- Dashboard: "Large File" labels updated from 500+ to 1500+ to match the v6.8 threshold
  the tile and explainer already used.

## v6.9 — 2026-06-09

Supabase Edge Function secrets, client-prefix env misnaming, prompt bug fixes, dashboard + pipeline hardening.

### Added

- **STEP 1: Supabase Edge Function secret sweep.** Greps `supabase/functions/` for hardcoded keys/tokens/JWTs and inline service-role assignment. Edge Function source is committed and shipped in the deploy bundle; secrets belong in `supabase secrets set` + `Deno.env.get()`. Uses the existing `hardcoded-secrets` category (critical).
- **STEP 1: client-prefix env var misnaming grep.** `NEXT_PUBLIC_*` / `VITE_*` names containing SECRET/SERVICE/PRIVATE/ADMIN/WEBHOOK ship to the client bundle by framework convention — the name itself is the leak. Uses the existing `env-exposure` category.
- **Dashboard: ⚡ Velocity stat card + cycle panel.** Optional `data/cycle-stats.js` (generated by new `scans/compute-cycle-stats.js`) renders commits, churn, busiest/churniest repo, portfolio scale, and per-tier flag-posture deltas vs the prior cycle. Card hides gracefully when the file is absent. Example shape in `data/cycle-stats.example.js`.
- **Pipeline: `scans/scrub_artifacts.py`.** Pre-commit gate that detects credential-shaped strings (Google/Stripe/Anthropic/OpenAI/GitHub/AWS/Resend/Slack keys, JWTs, private-key blocks) in `data/*.js` and `scans/*.json`. Report mode exits non-zero on a hit; `--fix` redacts in place. Matched values are never printed.
- **Pipeline: `phase_c_update.py --only-slug`.** One-off single-project merges no longer touch every other app's `lastScanned`.

### Fixed

- **NVD API key prose bug.** The prompt said to send `NVD_API_KEY` as a query param; NVD API 2.0 takes it as the `apiKey` request header — which the curl examples already did. Prose now matches the examples.
- **Stale SCAN:AUTO marker examples.** STEP 3 and `claude-md-template.md` examples were frozen at "v6.4"; they now track the current prompt version.
- **Dashboard XSS hardening.** `escHtml()` is now applied in the live render paths (flag text/notes, app name/category/description/nextAction, icon `alt`), not just the PDF export. Flag text originates from LLM scan output and is untrusted by definition.
- **Flag modal mismatch.** Structured flags whose category isn't in the explanation KB now get the generic modal instead of a fuzzy text match picking an unrelated entry.
- **`phase_c_update.py` merge safety.** App-object lookup is line-anchored (flag text mentioning `name: "X"` can no longer corrupt the merge); the merged `data/apps.js` is validated with `node --check` and the backup is restored automatically if the merge produced invalid JS.
- **`write_scan_jsons.py`** fallback regex can no longer match `SCAN:AUTO:END`-prefixed words.

### Notes

- Phase 11 (memory hash drift): added Windows path note — `~/.claude/` is `%USERPROFILE%\.claude\`; use Git Bash `sha256sum` or PowerShell `Get-FileHash`.
- No new flag categories; both new checks reuse existing taxonomy keys, so scan history and dashboards need no migration.

## v6.8 — 2026-06-06

Relax `file-over-500` to a uniform 1500-line threshold.

### Changed

- `file-over-500` threshold raised from 500 to **1500 lines, uniformly across all file types** (.js, .ts, .jsx, .tsx, .css, .html, .py, etc.). The prior 500-line cutoff was 2000s-era guidance for humans reading on small monitors; AI-readable code can be denser without becoming unworkable, and the proxy weakens as humans stop being the primary readers.
- The earlier .jsx/.tsx-specific 1500 carveout from v6.6 is now the default for all extensions; no per-extension exception.

### Notes

- Category key stays `file-over-500` for backwards compatibility with existing scan history and dashboard fields (`metrics.filesOver500`). Semantic meaning shifts to "files over the split threshold" with threshold = 1500.
- Empirical impact on a 25-project portfolio: 16 active flags dropped to 9 — roughly 44% noise reduction. The 9 survivors are all genuinely monolithic (1500+ lines), worth keeping on the radar.
- Cohesion still matters more than raw line count. A 1200-line file doing one thing is fine; a 300-line file doing six things is worse. Treat the flag as a "consider splitting" signal, not a mandatory refactor trigger.

## v6.7 — 2026-05-21

OWASP Top 10 (2021) categorization across the taxonomy.

### Added

- Every flag category in the taxonomy now maps to an OWASP Top 10 (2021)
  category where applicable. AI supply-chain and project-hygiene flags have no
  OWASP equivalent and are left unmapped on purpose.
- Optional `owasp` field on flag JSON (e.g., `"owasp": "A05"`) for downstream
  filtering and reporting.
- "OWASP TOP 10 MAPPING" section in the scan prompt as the single source of
  truth for flag → OWASP mapping.

### Notes

- Mapping inspired by the structured threat-modeling approach in gstack's
  `cso` skill. No code copied; implementation is original.
- Mapping reference: https://owasp.org/Top10/ (CC BY-SA 4.0).

## v6.6 — 2026-05-15

Codex adversarial review of v6.5 produced 8 net-new gaps. All landed in one
bump.

### Added

- STEP 1 grep checks: SSRF user-URL-fetch, webhook replay protection, open
  redirect detection, path traversal in file read/download, prototype-pollution
  merge grep, auth-endpoint rate-limiting check.
- STEP 1B live probes: CORS origin reflection + credentials probe, SSRF live
  probe against `/api/proxy?url=`-style routes, exposed-endpoint curl sweep
  (`/.env`, `/.git/HEAD`, `/backup.sql`, `/actuator`, etc.).
- New flag categories: `cors-origin-reflection`, `ssrf-user-url-fetch`,
  `webhook-replay-unprotected`, `open-redirect-unvalidated`,
  `path-traversal-file-read`, `prototype-pollution-merge`,
  `public-sensitive-endpoint`, `auth-endpoint-no-rate-limit`.

### Notes

- Additions sourced from an OpenAI Codex adversarial review run against the
  v6.5 prompt.

## v6.5 — 2026-05-15

Identity, AI, and supply-chain checks. The cycle that broadened scope from
"code grep" to "code + DNS + AI environment + auth provider config."

### Added

- STEP 1 grep checks: service_role key surface count, Stripe webhook signature
  pattern, GitHub Actions unpinned-uses check, LLM-output-into-DOM trace,
  audit-log + period-locking schema check (formalized from DATA INTEGRITY
  RULES).
- STEP 1B: DMARC/SPF/DKIM/CAA DNS audit, unauthenticated cron/webhook endpoint
  audit.
- STEP 1C: Phase 11 (memory file hash drift detection), Phase A LLM spend-cap
  inventory reminder.
- New flag categories: `missing-dmarc`, `dmarc-policy-none`, `missing-spf`,
  `missing-caa`, `excess-service-role-surface`, `stripe-webhook-unverified`,
  `gha-unpinned-action`, `llm-output-dom-render`, `missing-audit-log`,
  `missing-period-lock`, `ai-memory-file-drift`, `llm-spend-cap-unverified`,
  `unauthenticated-cron`, `unauthenticated-webhook`.

## v6.4 — 2026-05-06

Baseline. Numbered explicitly here because v6.6 and v6.7 both reference it
when narrowing earlier checks.

### Added

- CORS Verification probe (wildcard `Access-Control-Allow-Origin: *` detector).
  Later extended in v6.6 with the origin-reflection + credentials check.
- General rate-limiting check across endpoints (later specialized in v6.6 to a
  separate auth-endpoint variant).

## v6.3

### Added

- Phase 10 NVD cross-validation. The community-maintained threat-db produces
  candidate `ai-mcp-cve` flags; Phase 10 cross-checks each against the NIST
  National Vulnerability Database before they ship. Treats the community DB as
  advisory, NVD as authoritative.
- Optional `NVD_API_KEY` from `~/.claude/.env` for higher rate limits.

## Earlier (v6.0–v6.2)

Pre-public-release iterations focused on the core scan structure:
package.json/config inspection, git-history secret sweeps, deployed-surface
HTTP header probes, MCP/skill/plugin auditing. Detailed notes live in the
internal commit history rather than this changelog.

## Attribution

- v6.6 adversarial-review additions: [OpenAI Codex](https://github.com/openai/codex)
- v6.7 OWASP framing: inspired by [gstack](https://github.com/garrettmoon/gstack)'s
  `cso` skill (no code copied)
- AI tool threat database: [FlorianBruniaux/claude-code-ultimate-guide](https://github.com/FlorianBruniaux/claude-code-ultimate-guide)
- CVE cross-validation: [NIST National Vulnerability Database](https://nvd.nist.gov/)
