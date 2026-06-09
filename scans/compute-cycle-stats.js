#!/usr/bin/env node
/**
 * compute-cycle-stats.js — "By the numbers" stats for the Watchtower email debrief.
 *
 * Computes, for the current scan cycle:
 *   - Velocity: git commits + source churn (added/removed) since the prior scan,
 *     per non-archived repo, aggregated; busiest repo; biggest-churn repo.
 *   - Scale: total LOC, source files, largest file, files >500, components/pages/API
 *     routes — parsed from each scanned CLAUDE.md SCAN:AUTO Metrics section.
 *   - Posture: active flag counts by severity + delta vs prior cycle; oldest open
 *     flag (from portfolio-stats burndown/age); ESLint/Prettier/lint-gate coverage.
 *   - Highlights: most-improved app (biggest flag drop), cleanest apps (0 P1/P2).
 *
 * Reads watchtower.config.json for layout. Auto-detects the prior scan date as the
 * newest scan date strictly before --date (ignoring *-test.json). Churn excludes
 * lockfiles, node_modules, build output, source maps, and minified bundles so the
 * number reflects real code, not generated noise.
 *
 * Usage:  node scans/compute-cycle-stats.js --date 2026-06-05 [--since 2026-05-06]
 * Output: prints a Markdown "## 📊 By the numbers" section to stdout. Also writes
 *         data/cycle-stats.js (window.CYCLE_STATS) for optional dashboard use.
 * Read-only except for data/cycle-stats.js. Never throws on a single bad repo.
 */
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const WT_ROOT = path.resolve(__dirname, "..");
const CONFIG = path.join(WT_ROOT, "watchtower.config.json");
const SCANS = path.join(WT_ROOT, "scans");

function arg(name, def = null) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG, "utf-8"));
}

const DATE = arg("--date") || new Date().toISOString().slice(0, 10);

function detectPriorDate(cfg, today) {
  const dates = new Set();
  for (const f of fs.readdirSync(SCANS)) {
    if (f.endsWith(".json") && !f.includes("test")) {
      const m = f.match(/(\d{4}-\d{2}-\d{2})\.json$/);
      if (m && m[1] < today) dates.add(m[1]);
    }
  }
  return [...dates].sort().pop() || null;
}

function git(repo, args) {
  try {
    return execSync(`git ${args}`, {
      cwd: repo,
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 64 * 1024 * 1024,
    }).toString();
  } catch {
    return "";
  }
}

const NOISE = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$|(^|\/)(node_modules|dist|build|\.next|out|coverage)\/|\.min\.js$|\.map$/;

function repoChurn(repo, since) {
  // commit count
  const log = git(repo, `log --since="${since} 00:00" --oneline`).trim();
  const commits = log ? log.split("\n").length : 0;
  if (!commits) return { commits: 0, add: 0, del: 0, files: 0 };
  // numstat, filter noise
  const ns = git(repo, `log --since="${since} 00:00" --pretty=tformat: --numstat`);
  let add = 0, del = 0;
  const files = new Set();
  for (const line of ns.split("\n")) {
    const parts = line.split("\t");
    if (parts.length !== 3) continue;
    const [a, d, f] = parts;
    if (a === "-" || d === "-") continue; // binary
    if (NOISE.test(f)) continue;
    add += parseInt(a, 10) || 0;
    del += parseInt(d, 10) || 0;
    files.add(f);
  }
  return { commits, add, del, files: files.size };
}

function readBlock(folder) {
  const p = path.join(loadConfig().portfolioRoot, folder, "CLAUDE.md");
  if (!fs.existsSync(p)) return "";
  const c = fs.readFileSync(p, "utf-8");
  const m = c.match(/<!-- SCAN:AUTO:START\b[\s\S]*?-->([\s\S]*?)<!-- SCAN:AUTO:END/);
  return m ? m[1] : "";
}

function parseMetrics(block) {
  const out = {};
  let m;
  if ((m = block.match(/Total lines:\*?\*?\s*~?\s*([\d,]+)/i))) out.totalLines = parseInt(m[1].replace(/,/g, ""), 10);
  if ((m = block.match(/Components:\*?\*?\s*(\d+)/i))) out.components = parseInt(m[1], 10);
  if ((m = block.match(/Pages:\*?\*?\s*(\d+)/i))) out.pages = parseInt(m[1], 10);
  if ((m = block.match(/API routes:\*?\*?\s*(\d+)/i))) out.apiRoutes = parseInt(m[1], 10);
  // largest file from "Files over 500 lines" list: capture "name (1234)" pairs
  const fo = block.match(/Files over 500 lines:[^\n]*\n?([\s\S]*?)(?:\n- |\n\n|$)/i);
  out.filesOver500 = 0;
  out.largest = null;
  const region = (fo ? fo[0] : "") + block;
  let best = 0, bestName = null, count = 0;
  // match "name.ext (1234)" OR "name.ext 1234" OR "name.ext: 1234"; bound 500..200000
  const re = /([\w./-]+\.[a-zA-Z]{1,5})\s*[(:]?\s*([\d,]{3,})\)?/g;
  let r;
  while ((r = re.exec(region))) {
    const n = parseInt(r[2].replace(/,/g, ""), 10);
    if (n < 500 || n > 200000) continue;
    count++;
    if (n > best) { best = n; bestName = r[1]; }
  }
  out.filesOver500 = count;
  if (bestName) out.largest = { file: bestName, lines: best };
  return out;
}

function loadScan(slug, date) {
  const p = path.join(SCANS, `${slug}-${date}.json`);
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf-8")); } catch { return null; }
}

function counts(scan) {
  const c = { P1: 0, P2: 0, P3: 0, P4: 0 };
  if (!scan) return c;
  if (scan.flagCount) for (const k of Object.keys(c)) c[k] = scan.flagCount[k] || 0;
  else for (const f of scan.flags || []) if (c[f.severity] !== undefined) c[f.severity]++;
  return c;
}

function priorScanFor(slug, today) {
  let best = null;
  for (const f of fs.readdirSync(SCANS)) {
    const m = f.match(new RegExp(`^${slug.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-(\\d{4}-\\d{2}-\\d{2})\\.json$`));
    if (m && !f.includes("test") && m[1] < today) {
      if (!best || m[1] > best) best = m[1];
    }
  }
  return best;
}

function num(n) { return n.toLocaleString("en-US"); }

function main() {
  const cfg = loadConfig();
  const since = arg("--since") || detectPriorDate(cfg, DATE);
  const active = cfg.projects.filter((p) => p.category !== "Archived");

  // --- Velocity ---
  let commits = 0, add = 0, del = 0, files = 0, activeRepos = 0;
  let busiest = { name: "", n: 0 }, churniest = { name: "", n: 0 };
  if (since) {
    for (const p of active) {
      const repo = path.join(cfg.portfolioRoot, p.folder);
      if (!fs.existsSync(path.join(repo, ".git")) && !fs.existsSync(repo)) continue;
      const ch = repoChurn(repo, since);
      if (ch.commits > 0) activeRepos++;
      commits += ch.commits; add += ch.add; del += ch.del; files += ch.files;
      if (ch.commits > busiest.n) busiest = { name: p.displayName, n: ch.commits };
      const churn = ch.add + ch.del;
      if (churn > churniest.n) churniest = { name: p.displayName, n: churn };
    }
  }

  // --- Scale + Posture + Highlights ---
  let totalLines = 0, totalFiles = 0, comps = 0, pages = 0, apis = 0, files500 = 0;
  let largest = { file: null, lines: 0 };
  const cur = { P1: 0, P2: 0, P3: 0, P4: 0 }, pri = { P1: 0, P2: 0, P3: 0, P4: 0 };
  const clean = [], improved = [];
  for (const p of active) {
    const blk = readBlock(p.folder);
    if (blk) {
      const mt = parseMetrics(blk);
      if (mt.totalLines) { totalLines += mt.totalLines; }
      if (mt.components) comps += mt.components;
      if (mt.pages) pages += mt.pages;
      if (mt.apiRoutes) apis += mt.apiRoutes;
      if (mt.filesOver500) files500 += mt.filesOver500;
      if (mt.largest && mt.largest.lines > largest.lines) largest = { ...mt.largest, app: p.displayName };
    }
    const cs = loadScan(p.slug, DATE);
    if (!cs) continue;
    const cc = counts(cs);
    for (const k of Object.keys(cur)) cur[k] += cc[k];
    const pd = priorScanFor(p.slug, DATE);
    const pc = counts(pd ? loadScan(p.slug, pd) : null);
    for (const k of Object.keys(pri)) pri[k] += pc[k];
    if (cc.P1 === 0 && cc.P2 === 0) clean.push(p.displayName);
    const drop = (pc.P1 + pc.P2 + pc.P3 + pc.P4) - (cc.P1 + cc.P2 + cc.P3 + cc.P4);
    if (drop > 0) improved.push({ name: p.displayName, drop });
  }
  improved.sort((a, b) => b.drop - a.drop);

  // --- Coverage + burndown + oldest flag from portfolio-stats.js ---
  let coverage = null, burndown = null, oldest = null;
  try {
    const g = {};
    new Function("window", fs.readFileSync(path.join(WT_ROOT, "data", "portfolio-stats.js"), "utf-8"))(g);
    const ps = g.PORTFOLIO_STATS || {};
    coverage = ps.coverage || null;
    burndown = ps.burndown || ps.flagBurndown || null;
    // oldest flag: flagAges is an object map "App|category" -> firstSeen "YYYY-MM-DD"
    // (generate-portfolio-stats.js shape). Legacy array shape kept as a fallback.
    const ages = ps.flagAges || ps.oldestFlags || null;
    if (ages && !Array.isArray(ages) && typeof ages === "object") {
      const today = new Date(DATE + "T00:00:00Z");
      for (const [key, firstSeen] of Object.entries(ages)) {
        const days = Math.round((today - new Date(firstSeen + "T00:00:00Z")) / 86400000);
        if (!Number.isFinite(days)) continue;
        if (!oldest || days > oldest.ageDays) {
          const [app, category] = key.split("|");
          oldest = { app, category, ageDays: days };
        }
      }
    } else if (Array.isArray(ages) && ages.length) {
      oldest = ages.reduce((a, b) => ((b.ageDays || b.days || 0) > (a.ageDays || a.days || 0) ? b : a));
    }
  } catch { /* portfolio-stats optional */ }

  const d = (c, p) => { const x = c - p; return x === 0 ? "±0" : (x > 0 ? `+${x}` : `${x}`); };
  const scanned = active.filter((p) => loadScan(p.slug, DATE)).length;

  // --- Markdown ---
  const L = [];
  L.push("## 📊 By the numbers");
  L.push("");
  L.push(`**Velocity** — since last scan (${since || "n/a"})`);
  if (since) {
    L.push(`- **${num(commits)} commits** across ${activeRepos} active repos · **+${num(add)} / −${num(del)}** lines of source (net ${add - del >= 0 ? "+" : ""}${num(add - del)}), ${num(files)} files touched`);
    if (busiest.name) L.push(`- Busiest: **${busiest.name}** (${busiest.n} commits) · Biggest churn: **${churniest.name}** (${num(churniest.n)} lines)`);
  } else {
    L.push("- _No prior scan to diff against._");
  }
  L.push("");
  L.push("**Scale** — latest known metrics across the active portfolio (from each project's CLAUDE.md, not just this cycle's scans)");
  L.push(`- **~${num(totalLines)} lines of code** across ${active.length} active projects (${scanned} scanned this cycle)` + (comps || pages || apis ? ` · ${comps} components · ${pages} pages · ${apis} API routes` : ""));
  if (largest.file) L.push(`- Largest file: \`${largest.file}\` (${num(largest.lines)} lines${largest.app ? `, ${largest.app}` : ""}) · ${files500} files over 500 lines`);
  L.push("");
  L.push("**Security posture**");
  L.push(`- Active flags: **P1 ${cur.P1} · P2 ${cur.P2} · P3 ${cur.P3} · P4 ${cur.P4}** (Δ vs prior: P1 ${d(cur.P1, pri.P1)}, P2 ${d(cur.P2, pri.P2)}, P3 ${d(cur.P3, pri.P3)}, P4 ${d(cur.P4, pri.P4)})`);
  if (oldest) L.push(`- Oldest open flag: ${oldest.category || oldest.text || "?"}${oldest.app ? ` in ${oldest.app}` : ""} (${oldest.ageDays || oldest.days}d)`);
  if (coverage) {
    const c = coverage;
    const pick = (k) => (c[k] && c[k].have != null ? `${c[k].have}/${c[k].total}` : (c[k] != null ? c[k] : "?"));
    L.push(`- Coverage: ESLint ${pick("eslint")} · Prettier ${pick("prettier")} · lint-gate ${pick("lintGate") || pick("lint_gate")}`);
  }
  L.push("");
  L.push("**Highlights**");
  if (improved.length) L.push(`- Most improved: **${improved[0].name}** (−${improved[0].drop} flags vs prior)`);
  if (clean.length) L.push(`- Cleanest (0 P1/P2): ${clean.slice(0, 6).join(", ")}${clean.length > 6 ? `, +${clean.length - 6} more` : ""}`);

  const md = L.join("\n");

  // write data/cycle-stats.js for optional dashboard use
  const blob = {
    scanDate: DATE, priorDate: since,
    velocity: { commits, added: add, removed: del, filesTouched: files, activeRepos, busiest, churniest },
    scale: { totalLines, components: comps, pages, apiRoutes: apis, filesOver500: files500, largest },
    posture: { current: cur, prior: pri },
    highlights: { mostImproved: improved[0] || null, clean },
  };
  try {
    fs.writeFileSync(
      path.join(WT_ROOT, "data", "cycle-stats.js"),
      "window.CYCLE_STATS = " + JSON.stringify(blob, null, 2) + ";\n",
      "utf-8"
    );
  } catch { /* non-fatal */ }

  process.stdout.write(md + "\n");
}

main();
