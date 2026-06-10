#!/usr/bin/env node
// Generate data/portfolio-stats.js for the Watch Tower dashboard.
// Reads watchtower.config.json for portfolio root + project list. Walks each
// project's CLAUDE.md and package.json to compute adherence + tooling coverage,
// then aggregates scans/*.json into a flag burndown + per-flag age map.
// Output: data/portfolio-stats.js as `window.PORTFOLIO_STATS = {...}`.
//
// Re-run after touching project CLAUDE.md / ESLint / Prettier configs.
// The triweekly-security-scan SKILL fires this as part of Phase C.

const fs = require('fs');
const path = require('path');

const WATCHTOWER_ROOT = path.resolve(__dirname, '..');
const CONFIG_PATH = path.join(WATCHTOWER_ROOT, 'watchtower.config.json');
const SCANS_DIR = path.join(WATCHTOWER_ROOT, 'scans');
const OUT = path.join(WATCHTOWER_ROOT, 'data', 'portfolio-stats.js');

if (!fs.existsSync(CONFIG_PATH)) {
  console.error(`ERROR: ${CONFIG_PATH} not found.`);
  process.exit(1);
}
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
const PORTFOLIO_ROOT = config.portfolioRoot;
const PROJECTS = config.projects.map(p => ({ name: p.displayName, dir: p.folder }));

const out = { version: 1, generated: new Date().toISOString().slice(0, 10), byName: {}, burndown: null };

// --- Flag burndown over time ---
function computeBurndown() {
  const files = fs.readdirSync(SCANS_DIR).filter(f => /-\d{4}-\d{2}-\d{2}\.json$/.test(f));
  const byDate = {};
  for (const f of files) {
    const m = f.match(/-(\d{4}-\d{2}-\d{2})\.json$/);
    if (!m) continue;
    const date = m[1];
    let scan;
    try { scan = JSON.parse(fs.readFileSync(path.join(SCANS_DIR, f), 'utf8')); }
    catch { continue; }
    const flags = scan.flags || [];
    if (!byDate[date]) byDate[date] = { P1: 0, P2: 0, P3: 0, P4: 0, projects: 0 };
    byDate[date].projects++;
    for (const flag of flags) {
      if (flag.status === 'accepted' || flag.status === 'resolved') continue;
      const sev = flag.severity;
      if (sev && byDate[date][sev] !== undefined) byDate[date][sev]++;
    }
  }
  const dates = Object.keys(byDate).sort();
  return {
    dates,
    series: {
      P1: dates.map(d => byDate[d].P1),
      P2: dates.map(d => byDate[d].P2),
      P3: dates.map(d => byDate[d].P3),
      P4: dates.map(d => byDate[d].P4),
    },
    projectCounts: dates.map(d => byDate[d].projects),
  };
}

for (const p of PROJECTS) {
  const root = path.join(PORTFOLIO_ROOT, p.dir);
  const claudeMdPath = path.join(root, 'CLAUDE.md');
  const pkgPath = path.join(root, 'package.json');

  let claudeMd = null;
  if (fs.existsSync(claudeMdPath)) {
    const content = fs.readFileSync(claudeMdPath, 'utf8');
    const lines = content.split('\n');
    const total = lines.length;
    let inScan = false;
    let scanBlock = 0;
    for (const l of lines) {
      if (/SCAN:AUTO:START/.test(l)) inScan = true;
      if (inScan) scanBlock++;
      if (/SCAN:AUTO:END/.test(l)) inScan = false;
    }
    claudeMd = { total, scanBlock, handCurated: total - scanBlock };
  }

  let eslint = false, prettier = false, lintGate = false;
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const scripts = pkg.scripts || {};
    const devDeps = pkg.devDependencies || {};
    const deps = pkg.dependencies || {};
    eslint = !!(devDeps.eslint || deps.eslint || pkg.eslintConfig
      || fs.existsSync(path.join(root, 'eslint.config.js'))
      || fs.existsSync(path.join(root, 'eslint.config.mjs'))
      || fs.existsSync(path.join(root, '.eslintrc.json'))
      || fs.existsSync(path.join(root, '.eslintrc.js')));
    prettier = !!(devDeps.prettier || deps.prettier
      || fs.existsSync(path.join(root, '.prettierrc'))
      || fs.existsSync(path.join(root, '.prettierrc.json'))
      || fs.existsSync(path.join(root, '.prettierrc.js'))
      || pkg.prettier);
    lintGate = !!(scripts.lint && eslint);
  }

  out.byName[p.name] = { claudeMd, coverage: { eslint, prettier, lintGate } };
}

out.burndown = computeBurndown();

// --- Per-flag age tracking ---
// For each (app name, flag category) pair, find the earliest scan date where it
// was active. The dashboard uses this to badge how long each active flag has
// been open. Simple version: ignores "resolve and reappear" — if a flag
// category was first seen on date X, that's its firstSeen even if it briefly
// dropped off a scan between X and now.
function computeFlagAges() {
  const files = fs.readdirSync(SCANS_DIR).filter(f => /-\d{4}-\d{2}-\d{2}\.json$/.test(f));
  files.sort((a, b) => {
    const da = a.match(/(\d{4}-\d{2}-\d{2})/)[1];
    const db = b.match(/(\d{4}-\d{2}-\d{2})/)[1];
    return da.localeCompare(db);
  });
  const firstSeen = {};
  for (const f of files) {
    const m = f.match(/-(\d{4}-\d{2}-\d{2})\.json$/);
    if (!m) continue;
    const date = m[1];
    let scan;
    try { scan = JSON.parse(fs.readFileSync(path.join(SCANS_DIR, f), 'utf8')); }
    catch { continue; }
    const appName = scan.app || scan.name || scan.appName;
    if (!appName) continue;
    const flags = scan.flags || [];
    for (const flag of flags) {
      if (flag.status === 'accepted' || flag.status === 'resolved') continue;
      if (!flag.category) continue;
      const key = `${appName}|${flag.category}`;
      if (!firstSeen[key]) firstSeen[key] = date;
    }
  }
  return firstSeen;
}
out.flagAges = computeFlagAges();

// stale-docs flags come from check_docs_freshness.py (different cadence, not in
// the dated scan stream by design — see that script). Feed their first-flagged
// dates into flagAges so the "days open" badge works for them too.
(function mergeDocsFreshnessAges() {
  const df = path.join(SCANS_DIR, 'docs-freshness.json');
  if (!fs.existsSync(df)) return;
  try {
    const firstFlagged = JSON.parse(fs.readFileSync(df, 'utf8')).firstFlagged || {};
    for (const [appName, date] of Object.entries(firstFlagged)) {
      const key = `${appName}|stale-docs`;
      if (!out.flagAges[key]) out.flagAges[key] = date;
    }
  } catch { /* fail open */ }
})();

// --- Health-grade history (v7.0 trend arrows) ---
// Score every app in data/apps.js with the shared grade model and record ONE
// immutable {date, score} snapshot per app per SCAN (keyed to the app's
// lastScanned date, not the generation date — this script also reruns for
// CLAUDE.md/tooling refreshes, and the staleness penalty would otherwise make
// arrows move because time passed rather than because a scan happened).
// Prior history is carried forward from the existing portfolio-stats.js so
// trends survive regeneration. The dashboard shows ▲/▼ once an app has two
// snapshots.
function computeGradeHistory() {
  const model = require('./grade-model.js');
  const appsPath = path.join(WATCHTOWER_ROOT, 'data', 'apps.js');
  if (!fs.existsSync(appsPath)) return {};

  // data/apps.js assigns window.APPS — evaluate it with a window shim.
  const sandbox = { window: {} };
  try {
    new Function('window', fs.readFileSync(appsPath, 'utf8'))(sandbox.window);
  } catch (e) {
    console.warn('gradeHistory: could not evaluate data/apps.js —', e.message);
    return {};
  }
  const apps = sandbox.window.APPS || [];

  // Carry forward existing history from the current output file.
  let history = {};
  if (fs.existsSync(OUT)) {
    const prev = fs.readFileSync(OUT, 'utf8');
    const m = prev.match(/window\.PORTFOLIO_STATS = (\{[\s\S]*?\});\n/);
    if (m) {
      try { history = JSON.parse(m[1]).gradeHistory || {}; } catch { /* fresh start */ }
    }
  }

  const MAX_ENTRIES = 12; // ~8 months of triweekly cycles
  for (const app of apps) {
    const r = model.scoreFor(app);
    if (!r || !app.lastScanned) continue;
    const entries = history[app.name] || [];
    // One snapshot per scan date; reruns between scans never touch history.
    if (!entries.some(e => e.date === app.lastScanned)) {
      entries.push({ date: app.lastScanned, score: r.score });
      entries.sort((a, b) => a.date.localeCompare(b.date));
    }
    history[app.name] = entries.slice(-MAX_ENTRIES);
  }
  return history;
}
out.gradeHistory = computeGradeHistory();

const categories = config.categories || {};

const js = '// Auto-generated portfolio stats — CLAUDE.md adherence + tooling coverage + flag burndown.\n'
  + '// Generated by scans/generate-portfolio-stats.js — re-run when project CLAUDE.md or tooling changes,\n'
  + '// or when new scan JSONs land in scans/.\n'
  + 'window.PORTFOLIO_STATS = ' + JSON.stringify(out, null, 2) + ';\n'
  + '\n'
  + '// Display categories from watchtower.config.json — drives dashboard filter chips,\n'
  + '// stats exclusion, and per-category styling. Empty object means fully auto-derive\n'
  + '// (neutral chips, no excludes).\n'
  + 'window.WATCHTOWER_CATEGORIES = ' + JSON.stringify(categories, null, 2) + ';\n';
fs.writeFileSync(OUT, js);

console.log('Wrote', OUT);
console.log('\nSummary:');
let cE = 0, cP = 0, cG = 0, cClaude = 0;
for (const [n, v] of Object.entries(out.byName)) {
  const c = v.coverage;
  const e = c.eslint ? 'Y' : '.';
  const pr = c.prettier ? 'Y' : '.';
  const g = c.lintGate ? 'Y' : '.';
  const hand = v.claudeMd ? String(v.claudeMd.handCurated).padStart(3) : ' ? ';
  console.log('  ' + n.padEnd(28) + ' E' + e + ' P' + pr + ' G' + g + '  hand:' + hand);
  if (c.eslint) cE++;
  if (c.prettier) cP++;
  if (c.lintGate) cG++;
  if (v.claudeMd) cClaude++;
}
const n = Object.keys(out.byName).length;
console.log(`\nCoverage: ESLint ${cE}/${n}, Prettier ${cP}/${n}, Lint gate ${cG}/${n}, CLAUDE.md ${cClaude}/${n}`);
