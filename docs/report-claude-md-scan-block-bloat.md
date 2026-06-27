# Watchtower report: the SCAN:AUTO block is heavy in `CLAUDE.md`

**For:** Galen's agent (Watchtower maintainer)
**From:** a downstream operator running Watchtower across a ~29-project portfolio
**Re:** `prompts/security-scan-prompt.md` (v7.1) + `prompts/claude-md-template.md`
**Date:** 2026-06-27

---

## TL;DR

The auto-generated `<!-- SCAN:AUTO ... -->` block in each project's `CLAUDE.md` runs **100–154 lines** (portfolio average ~128). Because `CLAUDE.md` is auto-loaded into context at the **start of every session**, this is a per-session token tax on every project — paid whether or not the session has anything to do with security.

Only ~50 of those lines are genuinely security-bearing scan output. The other ~80–90 are orientation, reporting data, and one block of **byte-identical duplication repeated across all projects**.

The block is regenerated and *enforced* by the scan, so downstream operators can't trim it by editing `CLAUDE.md` — any change is overwritten on the next scan. **The only effective fix is in the generator + template.** This report proposes three changes, the first two of which are pure wins (zero information loss).

---

## 1. The observation

A user noticed that `feedlot-insights/CLAUDE.md` had ~142 lines consumed by the security-scan block and asked whether that was reasonable, and whether it was true of other projects.

It is true of every project — feedlot is *average*, not an outlier.

## 2. Evidence: it's systemic, set by the template

Measured SCAN:AUTO block size (`SCAN:AUTO:START` → `SCAN:AUTO:END`, inclusive) across the portfolio:

| Project | scan block (lines) | % of whole `CLAUDE.md` |
|---|---:|---:|
| consulting/RSI | 154 | 74% |
| crop-track | 144 | 46% |
| feedlot-insights | 143 | 25% |
| old-kb-rag | 137 | 51% |
| gf-financial | 133 | **87%** |
| Nutradrip-Ops | 132 | 34% |
| gf-tools | 126 | 73% |
| darins-app | 121 | 50% |
| kb-app | 122 | 70% |
| web-ai-native | 120 | 67% |
| Nutradrip-Tools | 117 | 69% |
| local-ai | 112 | **80%** |
| deep-research | 100 | 68% |

The "% of file" varies only because hand-maintained sections differ in size. The **absolute** block size is tightly clustered (100–154) because it's generated from a fixed template with a fixed set of required headings. In small projects the scan block *is* essentially the entire `CLAUDE.md` (80–87%).

## 3. Where the lines go (feedlot, 143-line block as representative)

| Section | ~lines | Nature |
|---|---:|---|
| Architecture (Folder Structure + Key Files + Data Flow + External API Calls) | 34 | Orientation prose |
| Security Notes (Active Flags / Watch List / Accepted / Resolved) | 26 | **Security payload** |
| Guardrails → Universal | 11 | **Identical in every project** |
| Dev Commands | 12 | Duplicate of `package.json` scripts |
| Tech Stack | 11 | Orientation |
| Deployed Surface | 9 | Security posture |
| Metrics | 9 | Reporting data (dashboard already owns it) |
| Environment Variables | 8 | Security payload |
| Guardrails → Project-Specific | 5 | **Security payload** |
| Strengths | 3 | "What not to break" (debatable value) |

The genuinely security-actionable payload a coding session needs — Active Flags, Project-Specific Guardrails, Env handling, Deployed posture — is roughly **50 lines**. The remaining ~90 is orientation, reporting, and duplication.

## 4. Root cause: it's generated and enforced, not editable downstream

This matters because it rules out the obvious "just delete the lines" fix. Three mechanisms in `prompts/security-scan-prompt.md` lock the block in:

1. **Whole-block overwrite, not merge** — STEP 3, ~line 1313:
   > "Replace everything between `<!-- SCAN:AUTO:START` and `<!-- SCAN:AUTO:END -->` (inclusive of marker lines) with fresh auto-generated content."
   Any manual deletion inside the markers is gone on the next scan.

2. **Universal Guardrails hardcoded in the prompt** — `## GUARDRAILS RULES`, line 2057:
   > "Always include these 9 universal guardrails:" followed by the 9 items verbatim.
   The template (`claude-md-template.md`, `### Universal (apply to all projects)`) carries the same 9.

3. **A validation gate that re-creates the block on tamper** — STEP 4, lines 1332–1344. It requires **9 headings in order** and specifically:
   > "If ANY required heading is missing … OR the Universal Guardrails list does not contain exactly 9 numbered items, re-emit the entire SCAN:AUTO block from scratch — do not patch."

Net: the block is self-healing by design. The fix must live in the generator (`security-scan-prompt.md`) and the mirror (`claude-md-template.md`), never in per-project `CLAUDE.md` files.

## 5. The cost framing

`CLAUDE.md` is read into context on **every** session in a project. So this isn't a one-time disk cost — it's ~128 lines (~1,500–2,500 tokens) re-paid every session, in every project, regardless of whether the session is security-related. Across a 29-project portfolio the Universal Guardrails alone are ~11 lines × 29 ≈ **320 lines of byte-identical text** stamped into the tree and re-loaded on every session that touches those repos.

---

## 6. Recommendations

Ordered by bang-for-buck. (1) and (2) are pure wins — no information is lost, only relocated or de-duplicated. (3) is a genuine design decision worth its own discussion.

### Recommendation 1 — Stop stamping the Universal Guardrails into every project *(cheapest, safest)*

The 9 Universal Guardrails are global, byte-identical, and project-independent. They don't belong in per-project output that's re-loaded every session; they belong in one place the agent already reads (e.g. the operator's global `~/.claude/CLAUDE.md`, or a single `GUARDRAILS.md` the scan references by link).

Changes:
- `security-scan-prompt.md` line ~2057 (`## GUARDRAILS RULES`): drop the "Always include these 9 universal guardrails" emit instruction (keep the project-specific generation that follows at line 2068).
- `claude-md-template.md`: remove the `### Universal (apply to all projects)` subsection; keep `### Project-Specific`.
- `security-scan-prompt.md` STEP 4 (lines 1338, 1344): relax the validator — heading #5 should require only `### Project-Specific`, and **remove the "exactly 9 numbered items" check** so the gate stops re-emitting the block when the Universal list is absent.

**Saves ~11 lines/project, zero information loss.** Optionally replace with a single pointer line (e.g. *"Universal guardrails: see `GUARDRAILS.md`."*).

> ⚠️ One caveat to weigh: the Universal block currently makes each repo's `CLAUDE.md` *self-contained*, which matters if a repo is ever opened standalone by an agent that does **not** have the operator's global `CLAUDE.md` loaded (e.g. a handoff, a fresh clone, a CI agent). If self-contained repos are a goal, prefer a one-line pointer to a committed `GUARDRAILS.md` over outright removal, so the content is one hop away rather than absent.

### Recommendation 2 — Move reporting-only sections out of the auto-loaded block

Two sections are duplicates of data that already lives in an authoritative source:

- **`## Metrics`** (line counts, repo URL, last-commit-scanned, scan version) — the Watchtower **dashboard** already aggregates this. It's reporting data, not coding context; it's noise in a per-session load. Recommend: keep it in the scan's JSON output (which feeds the dashboard) and **drop it from `CLAUDE.md`**, or relocate it to a non-auto-loaded file.
- **`## Dev Commands`** — regenerated from `package.json` scripts each scan. It's a duplicate of an already-authoritative file. The "machine-written so it can't go stale" rationale (v7.0 note, prompt line ~1229) is sound, but `package.json` is *already* the machine-authoritative source; duplicating it into the every-session context adds ~12 lines for little gain.

Changes: remove the emit blocks for these two sections in both files, and remove headings #8 and #9 from the STEP 4 checklist (lines 1341–1342) — dropping the validator from 9 headings to 7.

**Saves ~20 more lines/project, zero information loss.**

### Recommendation 3 — Split: lean security core in `CLAUDE.md`, full report in a non-auto-loaded file *(design change — discuss)*

The larger lever. Re-scope `CLAUDE.md`'s SCAN:AUTO block to only what a coding session must know to avoid breaking security:

- **Stays in `CLAUDE.md`:** Active Flags, Project-Specific Guardrails, Environment Variables handling, a 1–2 line security-architecture summary (auth model + enforcement point).
- **Moves to a non-auto-loaded `docs/security-scan.md` (or `SECURITY-SCAN.md`):** full Architecture prose (folder tree, key files, data-flow paragraph), Deployed Surface detail, Strengths, Watch List, Resolved history, Metrics.
- `CLAUDE.md` keeps a one-line pointer to the full report.

This preserves every piece of information the scan produces (nothing is deleted — it's relocated to a file that's read on demand, not auto-loaded) while cutting the per-session block to ~40–50 lines. It's a bigger change to STEP 3/STEP 4 and to where the scan writes, so it deserves a separate decision rather than being bundled with (1)+(2).

### Recommendation 4 — Tighten template prose (minor, optional)

Independent of structure: Architecture / Data Flow / Strengths are authored as full paragraphs. The template could ask for terser, bulletized output to shave another handful of lines per project. Low priority next to 1–3.

---

## 7. Suggested rollout

1. Ship **Rec 1 + Rec 2** together — they're low-risk, drop the STEP 4 checklist from 9 headings to ~6, and shed ~30 lines/project with no information loss. All 29 projects shed the lines automatically on their next scheduled scan; no per-repo edits required, and the change *sticks* (the validator no longer fights it).
2. Decide **Rec 3** separately. If adopted, it's the biggest reduction and keeps every byte of scan output — just in a file that isn't paid for on every session.
3. Bump the prompt version and the `Generated by security-scan-prompt vX.Y` marker so the change is traceable in the SCAN:AUTO header.

## 8. Files referenced

- `prompts/security-scan-prompt.md` — generator. Key anchors: STEP 3 overwrite (~L1313), STEP 4 validation (L1332–1344), `## GUARDRAILS RULES` (L2055–2067), Dev-Commands v7.0 note (~L1229).
- `prompts/claude-md-template.md` — human-readable mirror of the emitted block (Guardrails L60–75, Dev Commands L84–86, Metrics L88–96).
- Per-project `CLAUDE.md` (e.g. `feedlot-insights/CLAUDE.md`) — generated output; **not** a fix site.
