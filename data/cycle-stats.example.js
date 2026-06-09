// Example shape for window.CYCLE_STATS — the dashboard's "⚡ Velocity" stat card.
//
// Optional. Generate the live file (data/cycle-stats.js, gitignored) with
// scans/compute-cycle-stats.js after each scan cycle. If the file is absent,
// the Velocity card and its detail panel simply don't render — nothing breaks.
//
// "prior" posture counts come from the previous cycle's scan, so the panel can
// show per-tier deltas (P1 5 → 4 ▼1, etc.).

window.CYCLE_STATS = {
  "scanDate": "2026-01-22",
  "priorDate": "2026-01-01",
  "velocity": {
    "commits": 412,
    "added": 98500,
    "removed": 31200,
    "filesTouched": 760,
    "activeRepos": 12,
    "busiest": { "name": "Example App", "n": 85 },
    "churniest": { "name": "Another App", "n": 21400 }
  },
  "scale": {
    "totalLines": 185000,
    "components": 210,
    "pages": 95,
    "apiRoutes": 80,
    "filesOver500": 9,
    "largest": { "file": "Dashboard.jsx", "lines": 4200, "app": "Example App" }
  },
  "posture": {
    "current": { "P1": 1, "P2": 8, "P3": 30, "P4": 22 },
    "prior":   { "P1": 3, "P2": 9, "P3": 28, "P4": 25 }
  },
  "highlights": {
    "mostImproved": { "name": "Example App", "drop": 2 },
    "clean": ["Tidy App", "Other Tidy App"]
  }
};
