# Claude Code Security Scan & Tech Stack Extraction Prompt

Paste this into Claude Code inside a project directory (single-project mode) or a parent directory containing multiple projects (batch mode).

---

```
# Security Scan Prompt v6.7

Scan this project and give me a full security audit and code analysis.

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
- Check production dependencies for install scripts that could be supply chain attacks: look for preinstall, postinstall, or install scripts in direct production dependencies' package.json files (devDependency install scripts are lower risk)
- Check if source maps (.map files) are included in the production build output
- Run `gh repo view --json visibility -q .visibility` to check if the repo is public or private (if gh CLI is available, otherwise note "unknown")
- Count total lines of code: `find . -type f \( -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" -o -name "*.css" -o -name "*.html" -o -name "*.json" \) -not -path "*/node_modules/*" -not -path "*/.next/*" -not -path "*/dist/*" -not -path "*/build/*" -not -name "package-lock.json" | xargs wc -l`
- Map folder structure: `find . -maxdepth 2 -type d -not -path "*/node_modules/*" -not -path "*/.next/*" -not -path "*/dist/*" -not -path "*/.git/*"`
- Run `npx license-checker --summary --production` and flag any GPL/AGPL/copyleft licenses
- Check .nvmrc or package.json "engines" for Node.js version and flag if EOL or 2+ major versions behind current LTS
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
  - If absent AND the project is a financial app (farm-budget, farm-fin) OR a commercial app (mntlog) → flag `missing-audit-log` severity moderate. Text: "No audit_log / changelog / history table found in migrations. {project} handles {commercial/financial} data; absence means disputed changes have no evidence trail."
  - Fix: add an `audit_log(id, table_name, record_id, action, changed_by, changed_at, old_values jsonb, new_values jsonb)` table and a generic trigger that fires on INSERT/UPDATE/DELETE on tracked tables.
  - Skip for non-commercial / non-financial projects (Daily-trivia, market-dashboard, etc. don't need this).

- **Period locking check** (financial projects: farm-budget, farm-fin, mntlog):
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

Also extract the deployed URL:
- Check vercel.json for "alias" or "domains" fields
- Check package.json for "homepage" field
- Check for CNAME file in root or public/
- Prefer custom domains over *.vercel.app URLs
- Return the production URL if found, otherwise null

---

## STEP 1B: DEPLOYED SURFACE SCAN (optional — skip if no URL found)

If a production URL was extracted in Step 1, run these checks against the live site using `curl`. If no URL was found, skip this step and set `deployedSurface` to `null` in the JSON output.

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
Extract the apex domain from the deployed URL (e.g., `mntlog.net` from `https://mntlog.net`, `precisionfarms.llc` from `https://budget.precisionfarms.llc`). Run:

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

Each hit → P1 flag, category `ai-config-dangerous`, text includes the file path and the secret pattern type (never include the secret value itself).

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

Rate limits without an API key: 5 requests / 30 seconds. With a free API key (instant signup at https://nvd.nist.gov/developers/request-an-api-key), 50 / 30 seconds. If `~/.claude/.env` contains `NVD_API_KEY=...`, send it as the `apiKey` query param.

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
    "Farm-Budget": { sha256: "...", changedSincePrior: false },
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
  }
}

Rules:
- Only include what you actually find in the code, don't guess
- For envSecrets, list the variable NAMES only, not values
- If something isn't present, use null or []
- No explanation, just the JSON
- Every flag MUST be an object with text, severity, category, and confidence fields (see FLAG OUTPUT RULES)

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

<!-- SCAN:AUTO:START — Generated by security-scan-prompt v6.4. Do not edit this section manually. -->

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

## Metrics

- **Total lines:** {N, excluding node_modules/.next/dist/build/package-lock.json}
- **Components:** {N} | **Pages:** {N} | **API routes:** {N}
- **Files over 500 lines:** {list with line counts, or "_None_"}
- **Repo:** {URL or "Local-only"} ({PUBLIC/PRIVATE/unknown})
- **Production URL:** {URL, or "_Not deployed_"}
- **Last commit scanned:** {YYYY-MM-DD} ({short SHA})
- **Scan prompt version:** v6.4

<!-- SCAN:AUTO:END -->

## Auth

<!-- Auth method, roles, session handling. Filled from scan if detectable, otherwise leave for user. -->

## API Route Conventions

<!-- The pattern every route follows: auth middleware, validation, error handling. -->

## Testing
{filled from scan if test infrastructure detected: framework, test count, how to run}

## Dev Commands
```bash
npm run dev
npm run build
```

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
7. `## Metrics` — bullet list with all 7 lines (Total lines, Components/Pages/API routes, Files over 500 lines, Repo, Production URL, Last commit scanned, Scan prompt version)

If ANY required heading is missing, ANY subheading is omitted, OR the Universal Guardrails list does not contain exactly 9 numbered items, re-emit the entire SCAN:AUTO block from scratch — do not patch. Do not output success until the block is structurally complete.

After successful validation, output exactly two lines:
```
CLAUDE.md updated
STRUCTURE: PASS
```
(or "CLAUDE.md created" for new files). The `STRUCTURE: PASS` token is what the orchestrating SKILL checks for in Phase B.5 — without it, the project is queued for re-scan.

---

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
- Known critical CVEs from npm audit → category: npm-cve-critical
- Known high severity CVEs from npm audit → category: npm-cve-high
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
- Unparameterized NoSQL queries with user input → category: nosql-injection
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
- No rate limiting on public API routes → category: no-rate-limiting
- In-memory rate limiters, caches, or session stores (Map, Set, module-level variables) on serverless platforms (Vercel, Netlify, AWS Lambda, Cloud Functions) that reset on every cold start → category: serverless-memory-state
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
- Node.js version in .nvmrc or package.json engines is EOL or 2+ major versions behind → category: outdated-runtime
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
- Files over 500 lines that should be split → category: file-over-500. **For `.jsx` and `.tsx` files, use a 1500-line threshold instead** — prettier's `printWidth: 100` multiplies JSX prop-per-line wrapping 2-10x without representing real code growth, and some portfolios intentionally ship monolithic React components. Use 500 for `.js`, `.ts`, `.css`, `.html`, `.py`, etc.
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
| npm-cve-critical | P1 | Critical CVE from npm audit |
| npm-cve-high | P1 | High CVE from npm audit |
| npm-cve-moderate | P4 | Moderate CVE from npm audit |
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
| file-over-500 | P4 | Files that should be split. Threshold: 500 for non-JSX, **1500 for `.jsx`/`.tsx`** (prettier wrapping multiplies JSX line counts without real growth). |
| stack-trace-leakage | P1 | Error handlers expose internals in production |
| open-redirect | P1 | User-controlled redirect without validation |
| exposed-env-in-build | P1 | .env files bundled into dist/build output |
| outdated-runtime | P3 | Old Node.js version in .nvmrc/engines |
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
| nosql-injection | P1 | Unparameterized NoSQL queries with user input |
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
| route-protection-gap | A01 |
| license-risk | — |
| cdn-no-sri | A08 |
| unpinned-cdn | A08 |
| gha-unpinned-action | A08 |
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
- Files over 500 lines → "Do not add to {filename} ({N} lines) — split before adding features"
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
