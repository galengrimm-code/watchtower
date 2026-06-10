<p align="center">
  <img src="icon-512.png" alt="Watchtower" width="140" />
</p>

<h1 align="center">Watchtower</h1>

<p align="center">
  <em>Triweekly security scan for solo-dev and small-team code portfolios.</em><br>
  <em>Catches drift across code, DNS, deployed surface, and AI tool supply chain.</em><br>
  <em>Built for Claude Code. MIT licensed.</em>
</p>

Watchtower is a methodology + dashboard for the kind of developer who runs a dozen side projects, ships a paid SaaS app, and forgets which one has Stripe webhooks without signature verification. The scan runs on whatever cadence you set in `watchtower.config.json` (default: every 21 days — hence the "triweekly" branding), finds what's drifted, and refreshes a static HTML dashboard so you can see the whole portfolio at a glance.

It does **not** replace per-PR review tools, professional penetration testing, or a real CSPM. It's a continuous low-effort hygiene loop for portfolios where a full security program would be overkill.

---

## What you get

| Piece | What it does | Where it lives |
|---|---|---|
| Scan prompt | 1900+ lines of "what to check, what to flag," currently at v7.0 with OWASP Top 10 (2021) categorization, per-app strengths, and silent-failure / memory-growth sweeps | `prompts/security-scan-prompt.md` |
| Dashboard | Static HTML viewer for flag burndown, OWASP coverage, AI tool intel, and per-app A–F health grades | `index.html` (data populates over time from your scheduled scans) |
| Helper scripts | Three small Python + Node scripts that parse CLAUDE.md scan blocks, merge results, and generate stats | `scans/` |
| Scheduled-scan skill | The orchestrator that wires Phases 0 → A → B → B.5 → B.7 → C → D into a self-rescheduling loop on whatever cadence you configure (default: every 21 days) | `examples/triweekly-security-scan.SKILL.md.template` |
| Config | One JSON file with your project list, portfolio root, and exclusions — everything else derives from this | `watchtower.config.example.json` |

---

## Architecture

Watchtower is three pieces: a **public methodology repo** (this one), a **private runtime instance** on your machine where the scan actually executes, and a **local skill** in `~/.claude/scheduled-tasks/` that the scheduled-tasks MCP fires on whatever cadence you set in `watchtower.config.json` (default: every 21 days). The public repo has no data — your runtime instance and skill stay private.

```mermaid
graph TB
    subgraph public["PUBLIC: github.com/galengrimm-code/watchtower (this repo)"]
        Prompt[Scan Prompt v7.0]
        Shell[Dashboard Shell - index.html]
        Scripts[Helper Scripts - Python + Node]
        Template[Skill Template - examples/]
        Docs[README + LICENSE + CHANGELOG]
    end

    subgraph local["Your Local Machine"]
        subgraph private["Your private runtime clone of watchtower"]
            Clone[Same files as public + your real watchtower.config.json + data/apps.js + scans/*.json]
        end

        subgraph skillhome["~/.claude/scheduled-tasks/triweekly-security-scan/"]
            Skill[SKILL.md - your orchestrator]
        end

        subgraph env["~/.claude/.env"]
            Secrets[NVD_API_KEY - optional]
        end
    end

    public -.->|"manual file sync on prompt updates"| private
    Skill -->|"reads scan prompt + writes findings"| private
    Skill -.->|"reads NVD key"| Secrets
    Skill -->|"NVD lookups for Phase 10"| NVD[(NVD API)]
```

The runtime instance is whatever you want — public if you're brave, private if you have a paying app in the portfolio (recommended). The public methodology repo is just the shell. **Two-repo architecture, no fork relationship**, manual file sync when the methodology bumps.

---

## The scan cycle (default 21 days, configurable)

```mermaid
sequenceDiagram
    autonumber
    participant Cron as scheduled-tasks MCP
    participant Skill as SKILL.md (Phase 0..D)
    participant Code as Per-project agents
    participant Codex as /codex (optional)
    participant Dash as Watchtower dashboard

    Cron->>Skill: fire (default 21 days, fireAt-based — configurable via scanCadenceDays)
    Skill->>Skill: Phase 0 — self-reschedule next run FIRST
    Skill->>Skill: Phase A — AI tool supply chain audit (once)
    Skill->>Code: Phase B — parallel scans per project
    Code-->>Skill: results in each project's CLAUDE.md
    Skill->>Skill: Phase B.5 — validate every CLAUDE.md block
    Skill->>Codex: Phase B.7 — challenge net-new P1s + commercial app diff
    Codex-->>Skill: disagreements (or timeout)
    Skill->>Dash: Phase C — merge into data/apps.js + regenerate stats
    Skill->>Skill: Phase D — commit + push
```

Phase 0 self-reschedules first, **before anything else runs**. If the scan crashes anywhere downstream, the next run is still armed. Skip this and a crashed scan means a dead chain until you notice.

---

## Prerequisites

- [Claude Code](https://claude.com/claude-code) 2.1.34 or newer
- Node.js 18+
- Python 3.10+
- `gh` CLI (optional; used for repo visibility checks during scans)
- [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (optional, free, 30-second signup) — gives Phase 10 cross-validation higher rate limits
- [Codex CLI](https://github.com/openai/codex) (optional) — required only if you want Phase B.7 adversarial review

Everything optional is genuinely optional. The scan runs and produces a dashboard with none of them. The "best" run uses all of them.

---

## Quick start (~5 minutes)

```bash
# 1. Clone the public methodology repo into a private home for your runtime
gh repo create your-org/watchtower-runtime --private --clone
cd watchtower-runtime
git remote add upstream https://github.com/galengrimm-code/watchtower
git pull upstream main
# (keep upstream as your sync source when the methodology bumps)

# 2. Copy the example config and edit it
cp watchtower.config.example.json watchtower.config.json
$EDITOR watchtower.config.json   # set portfolioRoot, watchtowerRoot, projects

# 3. Install the scheduled-scan skill into ~/.claude/scheduled-tasks/
mkdir -p ~/.claude/scheduled-tasks/triweekly-security-scan
cp examples/triweekly-security-scan.SKILL.md.template \
   ~/.claude/scheduled-tasks/triweekly-security-scan/SKILL.md
$EDITOR ~/.claude/scheduled-tasks/triweekly-security-scan/SKILL.md
# replace <WATCHTOWER_CONFIG_PATH> with the absolute path to your watchtower.config.json

# 4. (Optional) add NVD API key for higher Phase 10 rate limits
echo "NVD_API_KEY=YOUR_KEY_HERE" >> ~/.claude/.env

# 5. Open the dashboard locally to confirm it loads
# Windows
start index.html
# macOS
open index.html
```

On first run the dashboard is empty (no `data/apps.js` yet). It populates after your first scheduled scan. To force the first run, ask Claude Code to invoke the skill manually — or arm a fireAt timestamp a minute in the future and let the MCP fire it.

---

## What the scan catches

Roughly 120+ flag categories grouped by what they look at:

| Surface | Examples |
|---|---|
| Code (STEP 1) | Hardcoded secrets, git-history secret leaks, npm audit P1s, SSRF user-URL-fetch, webhook replay, path traversal, prototype pollution, source maps in prod, dangerous innerHTML, LLM output rendered to DOM, swallowed exceptions (silent catch blocks), unbounded in-memory growth |
| DNS + deployed surface (STEP 1B) | Missing security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy), CORS origin reflection + credentials, exposed sensitive endpoints (/.env, /.git/HEAD, /backup.sql), DMARC/SPF/DKIM/CAA gaps, unauthenticated cron/webhook endpoints |
| AI tool supply chain (STEP 1C, runs once per cycle) | Vulnerable MCP servers, unsafe-list skills/plugins/hooks, memory-poisoning patterns, secrets in `.claude/`, outdated Claude Code, NVD cross-validation against the community threat-db |
| Hygiene + tooling | Files over 1,500 lines (uniform threshold since v6.8), missing ESLint config, no `lint` script, missing .nvmrc, no security.txt, Prettier drift, CI not gating on lint |

Severity follows P1 (active risk) → P4 (hygiene). Each project's `CLAUDE.md` gets a SCAN:AUTO block with the same shape — easy to diff across runs.

### Health grades & strengths (v7.0)

Two outputs aimed at "how is the portfolio doing," not just "what's broken":

- **Health grade (A–F)** — each scanned app gets a letter badge on its dashboard card, computed client-side from data the scan already emits: active flag severities, files over the size threshold, test-framework presence, and scan recency. Accepted and resolved flags don't count — accepting a risk is a decision, not a defect. Click the badge for the full deduction breakdown. The formula lives in one function (`healthGradeFor` in `index.html`) — tune the weights to your own taste.
- **Strengths line** — every scan writes one concrete, verified sentence on what the codebase does *well* ("Signature-verified Stripe webhooks, RLS on every queried table"). It renders on the card and tells a future refactor — human or AI — what not to break.

---

## OWASP Top 10 (2021) coverage

Each flag category that maps to an OWASP Top 10 (2021) item carries an optional `owasp` field. AI supply-chain and hygiene flags intentionally don't map — those are real risks OWASP doesn't track.

| OWASP | Watchtower coverage |
|---|---|
| A01 Broken Access Control | webhook signature, period locking, audit log gaps |
| A02 Cryptographic Failures | hardcoded secrets, secrets in git history, weak auth cookie attrs |
| A03 Injection | SSRF, path traversal, open redirect, dangerous innerHTML, LLM-output DOM render |
| A04 Insecure Design | missing rate limiting, missing audit log, missing period locks |
| A05 Security Misconfiguration | missing security headers, source maps in prod, CORS reflection, exposed endpoints |
| A06 Vulnerable & Outdated Components | npm audit, EOL Node versions, unpinned GHA actions |
| A07 Identification & Auth Failures | auth-endpoint rate limiting, tokens in localStorage |
| A08 Software & Data Integrity | webhook replay, unpinned actions, prototype pollution, install scripts |
| A09 Logging & Monitoring | missing audit log, debug logging in prod, swallowed exceptions |
| A10 SSRF | dedicated SSRF user-URL-fetch grep + live probe |

The mapping was inspired by the structured threat-modeling approach in gstack's `cso` skill; the implementation is original.

---

## Phase B.7 — Codex adversarial review (optional)

If `/codex` is installed and authenticated, Watchtower runs a focused second-opinion pass after Phase B finishes:

1. **Net-new P1 challenge** — diffs this cycle's P1 flags against the previous cycle. Up to 3 net-new entries get sent to `/codex challenge`, which is asked to argue the flag is wrong or find a counterexample.
2. **Commercial-app CLAUDE.md review** — if `config.commercialAppSlug` is set, the diff to that project's CLAUDE.md gets sent to `/codex review`. Codex's job is to check whether the scan actually read the codebase or hallucinated architecture details.

Every Codex call is wrapped in a 60-second timeout. If Codex hangs on an auth prompt, the scan still ships — just without the second opinion.

Codex disagreements land in the Phase D commit message under `## Codex second opinion` so you see them in the next time you `git log`.

---

## Customizing the scan

- **Add a new check**: edit `prompts/security-scan-prompt.md`. The taxonomy and OWASP mapping live in dedicated sections — keep both in sync when adding categories.
- **Add a new project**: append an entry to `watchtower.config.json`'s `projects` array. The next scheduled run picks it up.
- **Skip a project for one cycle**: add its folder to `exclusions`. Re-enable by removing.
- **Change the cadence**: set `scanCadenceDays` in `watchtower.config.json`. The skill computes the next fire date as `now + scanCadenceDays`, so this can be anything from daily (`1`) to monthly (`30`) to quarterly (`90`) or longer. Default is `21`. The name "triweekly" is just the default — pick whatever cadence matches how fast your portfolio drifts.
- **Drop a check**: delete the relevant grep block from the prompt. The dashboard tolerates missing categories — it renders whatever's there.

### Configuring display categories

Each project on the dashboard belongs to a **display category** (the colored chip on its card, the filter pill at the top of the grid). These are user-defined — name them whatever fits your portfolio.

The dashboard reads display categories from `watchtower.config.json` under the `categories` key:

```json
"categories": {
  "Active":     { "color": "#4caf50", "excludeFromStats": false, "sortOrder": 1 },
  "Commercial": { "color": "#5b9bd5", "excludeFromStats": false, "sortOrder": 2 },
  "Tool":       { "color": "#b388d9", "excludeFromStats": false, "sortOrder": 3 },
  "Experiment": { "color": "#d4a843", "excludeFromStats": true,  "sortOrder": 4 },
  "Archived":   { "color": "#888888", "excludeFromStats": true,  "sortOrder": 99, "dim": true }
}
```

Per entry:

- `color` — either a single hex string (used as the accent) or a full object `{bg, border, accent, tag}` for fully tinted cards (matches the styling on the screenshot at the top of this README).
- `excludeFromStats` — when true, projects in this category are dropped from aggregate dashboard stats (P1/P2/P3/P4 totals, completion average, etc.) but still appear in the grid. Useful for "Archived" / "Experiment" categories you want to see but not include in the headline numbers.
- `sortOrder` — lower sorts earlier in the filter pill bar. Use `99+` to sink the category to the bottom of the grid (Watchtower's legacy "Archived sorts last" behavior is just `sortOrder: 99`).
- `dim` — optional. When true, cards in this category render at 72% opacity until expanded. Visual hint for "this is a parked project."

**Categories not in the map still appear** — they just get neutral gray styling and sort middle. So you can leave `categories` empty (or delete it) and the dashboard still works; it just looks flatter. Add entries only for categories you want styled.

Projects reference categories by exact-match in their `data/apps.js` entry's `category` field. If you add a new category to the config, set at least one project's `category` to that name and re-open the dashboard.

---

## Security considerations

A few caveats this project doesn't try to hide:

- **Not a replacement for `/security-review`.** Per-PR diff review and Watchtower's portfolio sweep solve different problems. Run both.
- **Not a replacement for professional pentesting.** Watchtower catches drift and misconfigurations. It doesn't model adversaries, run fuzzing, or exercise business logic flaws.
- **Community threat-db is single-maintainer** (~30 source advisories). Treat findings as advisory. Cross-check critical flags against NVD/Snyk before acting on commercial code. Phase 10 helps but isn't a replacement for human judgment.
- **STEP 1B live probes hit your own deployed sites.** Never point Watchtower at domains you don't own. The probes are benign GETs against your own apex — read the prompt before running.
- **The dashboard is static HTML with no auth.** Don't serve `data/apps.js` publicly if it contains private repo URLs, internal paths, or vulnerability details.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: small PRs, one concern at a time, threat model required for new checks.

For security issues in Watchtower itself, open a private security advisory through GitHub's Security tab.

---

## License

MIT — see [LICENSE](LICENSE). Use it however you want.

---

## Acknowledgments

- **v6.6 adversarial-review additions**: [OpenAI Codex](https://github.com/openai/codex)
- **v6.7 OWASP framing**: inspired by [gstack](https://github.com/garrettmoon/gstack)'s `cso` skill (no code copied, implementation is original)
- **v7.0 audit dimensions** (silent failures, memory growth, strengths, health grade): adapted from community "repo audit" prompt patterns
- **AI tool threat database**: [FlorianBruniaux/claude-code-ultimate-guide](https://github.com/FlorianBruniaux/claude-code-ultimate-guide)
- **CVE cross-validation**: [NIST National Vulnerability Database](https://nvd.nist.gov/)
- **Claude Code**: [Anthropic](https://claude.com/claude-code)
