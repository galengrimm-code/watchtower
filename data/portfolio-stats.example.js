// Example shape for window.PORTFOLIO_STATS — adherence + tooling coverage + burndown.
//
// In the public Watchtower repo, this is the only stats file that ships.
// At runtime the live file at data/portfolio-stats.js (gitignored) is generated
// by scans/generate-portfolio-stats.js during each scheduled run.
//
// Three top-level pieces:
//   - byName: per-project CLAUDE.md adherence + lint/format coverage
//   - burndown: time-series of active flag counts per severity per scan date
//   - flagAges: {appName|category: firstSeenISODate} for badging stale flags

window.PORTFOLIO_STATS = {
  version: 1,
  generated: "2026-01-15",
  byName: {
    "Example Active App": {
      claudeMd: {
        total: 280,
        scanBlock: 215,
        handCurated: 65
      },
      coverage: {
        eslint: true,
        prettier: true,
        lintGate: true
      }
    },
    "Example Commercial App": {
      claudeMd: {
        total: 410,
        scanBlock: 280,
        handCurated: 130
      },
      coverage: {
        eslint: true,
        prettier: true,
        lintGate: true
      }
    },
    "Example Archived App": {
      claudeMd: null,
      coverage: {
        eslint: false,
        prettier: false,
        lintGate: false
      }
    }
  },
  burndown: {
    dates: ["2025-11-01", "2025-11-22", "2025-12-13", "2026-01-03"],
    series: {
      P1: [9, 6, 4, 2],
      P2: [14, 12, 9, 7],
      P3: [38, 35, 31, 28],
      P4: [22, 21, 21, 19]
    },
    projectCounts: [18, 18, 18, 18]
  },
  flagAges: {
    "Example Active App|webhook-signature": "2025-12-13",
    "Example Active App|auth-rate-limiting": "2025-11-01",
    "Example Active App|source-maps-exposed": "2026-01-03"
  }
};
