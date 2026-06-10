// Health-grade model — the ONE place the grading formula lives.
// Loaded by index.html (window.HEALTH_GRADE) for live rendering AND required by
// scans/generate-portfolio-stats.js (module.exports) to persist per-cycle score
// history. Tune weights here and both stay in lockstep.
//
// Weights calibrated 2026-06-09 against the live portfolio so grades spread
// meaningfully: clean recently-scanned apps reach A, flag-heavy stale apps fail.
(function (factory) {
  if (typeof module !== "undefined" && module.exports) module.exports = factory();
  else window.HEALTH_GRADE = factory();
})(function () {
  const WEIGHTS = { P1: 30, P2: 10, P3: 2, P4: 0.5, p4Cap: 3, file: 1.5, fileCap: 5, noTests: 6, stale: 5, staleDays: 45 };

  // Normalize a flag to P1..P4, or null for accepted/resolved/unclassifiable.
  // Legacy word severities map exactly like the dashboard's classifyFlag().
  function classify(f) {
    if (!f || typeof f !== "object") return null; // legacy string flags don't grade
    if (f.status === "accepted" || f.status === "resolved") return null;
    const s = f.severity;
    if (s === "P1" || s === "critical") return "P1";
    if (s === "P2") return "P2";
    if (s === "P3" || s === "moderate") return "P3";
    if (s === "P4" || s === "maintenance") return "P4";
    return null;
  }

  // now: ms timestamp for staleness math (injectable so node + browser agree in tests)
  function scoreFor(app, now) {
    if (!app || !app.scanned || !app.lastScanned) return null;
    const W = WEIGHTS;
    const counts = { P1: 0, P2: 0, P3: 0, P4: 0 };
    for (const f of app.flags || []) {
      const p = classify(f);
      if (p) counts[p]++;
    }
    const parts = [];
    let score = 100;
    for (const p of ["P1", "P2", "P3", "P4"]) {
      if (!counts[p]) continue;
      const d = p === "P4" ? Math.min(counts.P4 * W.P4, W.p4Cap) : counts[p] * W[p];
      score -= d;
      parts.push(`−${d} · ${counts[p]} active ${p} flag${counts[p] !== 1 ? "s" : ""}`);
    }
    const fo = Number((app.metrics && app.metrics.filesOver500) || 0) || 0;
    if (fo) {
      const d = Math.min(fo * W.file, W.fileCap);
      score -= d;
      parts.push(`−${d} · ${fo} file${fo !== 1 ? "s" : ""} over 1,500 lines`);
    }
    const testing = ((app.tech && app.tech.testing) || "").trim();
    if (!testing || /^none/i.test(testing)) {
      score -= W.noTests;
      parts.push(`−${W.noTests} · no test framework`);
    }
    const ageDays = ((now || Date.now()) - new Date(app.lastScanned + "T00:00:00")) / 86400000;
    if (ageDays > W.staleDays) {
      score -= W.stale;
      parts.push(`−${W.stale} · last scan ${Math.round(ageDays)} days old`);
    }
    score = Math.max(0, Math.round(score));
    return { score, parts };
  }

  function letterFor(score) {
    return score >= 97 ? "A+" : score >= 93 ? "A" : score >= 90 ? "A-" :
      score >= 87 ? "B+" : score >= 83 ? "B" : score >= 80 ? "B-" :
      score >= 77 ? "C+" : score >= 73 ? "C" : score >= 70 ? "C-" :
      score >= 67 ? "D+" : score >= 63 ? "D" : score >= 60 ? "D-" : "F";
  }

  function colorFor(score) {
    return score >= 90 ? "#4caf50" : score >= 80 ? "#a3c14a" : score >= 70 ? "#e0c030" : score >= 60 ? "#e0a030" : "#e05050";
  }

  return { WEIGHTS, classify, scoreFor, letterFor, colorFor };
});
