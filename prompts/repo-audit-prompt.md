# Repo Audit Prompt — v1.0

A one-shot quality audit for solo-builder projects, designed to be run by Claude Code (or any capable coding agent) inside a project directory. It answers two questions a continuous security scan doesn't: **does this thing actually still work**, and **what's the quality debt worth fixing at this project's maturity**.

This is the companion to Watchtower's continuous security scan (`security-scan-prompt.md`). They're independent — you can run this audit without ever setting up Watchtower. If the project DOES have a Watchtower SCAN:AUTO block in its CLAUDE.md, the audit reads it and skips re-auditing security.

**How to use:** open Claude Code in the project root, paste everything below the line, answer the one question it asks, and read the report. Nothing is modified until you explicitly say go.

---

```
# Repo Audit v1.0 — quality + does-it-run

You are auditing this repository for a solo builder. Evidence first, judgments second, nothing modified without an explicit "go." Work the phases in order.

## STEP 0: One question before anything else

Ask the user (then calibrate EVERYTHING below to the answer):

> Which best describes this project?
> A) Hobby / personal — only I use it
> B) Shared — other people use it, but no money involved
> C) Commercial — it takes payment or holds other people's data

This answer is a ceiling on your recommendations:
- (A) gets NO recommendations for CI pipelines, test coverage targets, monitoring, or refactors. Broken things and footguns only.
- (B) adds: input validation on anything public, error handling users would hit, basic abuse resistance (can a bored stranger spam this form?).
- (C) adds: the full security checklist below, test coverage on the money paths, and a "fix before your next customer" section.

Over-recommending is a failure mode. A church sign-up sheet does not need Terraform.

## PHASE 0: PROVE IT RUNS (facts, not opinions)

Run each step. Record PASS / FAIL / N/A with real output (last ~10 lines on failure):

1. Install: `npm ci` (or `npm install` if there's no lockfile — and note the missing lockfile)
2. Build: `npm run build` (or whatever the manifest declares)
3. Lint: `npm run lint` if the script exists
4. Tests: run whatever test runner package.json declares; record pass/fail COUNTS
5. Boot: start the dev server, fetch the homepage, capture any console errors, kill the server

A failure here is severity BROKEN and outranks everything else in the report. A project that doesn't build has exactly one priority.

## PHASE 1: DISCOVERY (read before judging)

- Map the structure: project type, framework, where the code actually lives.
- Read the manifest, lockfile, build config, .env.example, README, and CLAUDE.md if present.
- If CLAUDE.md contains a Watchtower SCAN:AUTO block: its Active Flags are the security findings. Read them, reference them, do NOT re-audit security beyond the stack checklist below.
- Identify the core 20% of code that does 80% of the work. Spend your depth there; name what got lighter review.

## PHASE 2: AUDIT

Every finding: what, where (file:line), the concrete consequence, severity (BROKEN / HIGH / MEDIUM / LOW), and whether it's a verified FACT or a JUDGMENT. Prefer 10 high-confidence findings over 40 speculative ones. Healthy dimension = one sentence, move on.

**Write every finding twice:**
- **For you:** one plain-English sentence about what this means in the real world. ("Anyone can submit your contact form 10,000 times overnight and you pay for every email it sends.")
- **For Claude:** the technical detail a future coding session needs to fix it. (file:line, root cause, suggested approach.)

### Quality dimensions

- **Duplication:** the same logic written twice — across files, or 800 lines apart in the same file.
- **Dead code:** unused exports, unreferenced files, big commented-out blocks, `-old` / `-backup` / `-v2` files.
- **Complexity hotspots:** the 3 longest FUNCTIONS (not files) with line counts. Big files that do one thing cohesively are fine; flag incoherence, not length.
- **Error handling:** catch blocks that swallow errors silently (no log, no rethrow, no user feedback — `catch {}` and `catch { return null }` both count); failures users would actually hit.
- **Type safety** (TypeScript projects): `any` density in core modules, `@ts-ignore` count.
- **Tests** (tiers B/C only): do existing tests assert behavior or just "it didn't crash"? What's untested that handles money or user data?
- **Dependencies:** `npm outdated` summary; deprecated packages; anything unmaintained for 2+ years that the project leans on.
- **Docs:** does the README's setup actually work (you just ran it in Phase 0 — compare)? Stale docs that contradict code?

### Stack checklist (the failure modes that actually burn this kind of project)

Check whichever apply; skip the rest silently:

- **Vercel/serverless:** module-level Map/Set/array used for rate limiting, caching, or sessions — resets on every cold start AND can grow unbounded on warm instances. Both are bugs.
- **Supabase:** any table queried from the client without Row Level Security enabled. The anon key is public by design; RLS is the only wall.
- **Firebase:** Firestore/Storage rules that allow open reads or writes (`allow read, write: if true`).
- **Stripe:** webhook handlers that process the payload before verifying the signature (`stripe.webhooks.constructEvent`).
- **Env vars:** `NEXT_PUBLIC_*` / `VITE_*` prefixed variables ship to the browser bundle by framework convention. Any such name containing SECRET, SERVICE, PRIVATE, ADMIN, or WEBHOOK is a leak regardless of intent.
- **Secrets:** anything key-shaped hardcoded in source or visible in git history (`git log -p` spot-check on config files). If it was ever committed, it needs rotation — deleting it later doesn't unship history.
- **Auth:** tokens in localStorage instead of httpOnly cookies; API routes that mutate data with no auth check.
- **DOM:** `innerHTML` / `dangerouslySetInnerHTML` fed anything that isn't a hardcoded string — including LLM output, which is untrusted user data.

(These checks are distilled from Watchtower's scan methodology — for continuous coverage of this list plus ~110 more categories, see security-scan-prompt.md in this repo.)

### Strengths

2–4 concrete things this codebase does well. This tells the next session — human or AI — what NOT to break.

## PHASE 3: WHAT NOT TO FIX

Name what you are deliberately NOT recommending and why, calibrated to the Step 0 tier. This section is mandatory — restraint is part of the audit.

## PHASE 4: THE FIX PLAN (executable, not a document)

Sort every accepted finding into three buckets:

1. **Fix now** — BROKEN items and anything an attacker or accident triggers tomorrow.
2. **Fix before you share it** (or "before your next customer" on tier C) — the HIGH items.
3. **Nice to have** — everything else that survived Phase 3.

For each task: a one-paragraph paste-ready prompt a fresh Claude Code session can execute, the files involved, how to verify it worked, and an honest time estimate for an AI session (minutes, not human days).

End the report with:
- A scorecard: Phase 0 results + one overall grade A–F (BROKEN anywhere = automatic F until fixed; each unaddressed HIGH costs a letter).
- The line: **"Say go and I'll fix the 'Fix now' bucket right now."** Do not touch code before that go.

## CONSTRAINTS

- Analysis only until "go". No code changes, no new dependencies.
- Never claim something builds, passes, or works unless you ran it in this session and saw the output.
- Cite file:line for every fact. Say "couldn't verify" instead of guessing.
- Don't pad the report. Short and true beats long and impressive.
```
