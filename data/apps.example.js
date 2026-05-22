// Example shape for window.APPS — the dashboard's app catalog.
//
// In the public Watchtower repo, this is the ONLY file under data/ that ships.
// At runtime the live file at data/apps.js (gitignored) is generated and updated
// by scans/phase_c_update.py during each scheduled run.
//
// One entry per project you want on the dashboard. Required: name, category,
// description, scanned, lastUpdated, lastScanned. Everything else is optional;
// the dashboard's render code degrades gracefully when fields are missing.
//
// Categories drive the stats filter: "Other" and "Archived" entries are excluded
// from aggregate metrics, but still render in the grid.

window.APPS = [
  {
    name: "Example Active App",
    category: "Active",
    url: "https://example.com",
    description: "One-line description of what this app does and why it exists.",
    completion: 85,
    nextAction: "Whatever's on top of the backlog (rendered in the dashboard tooltip).",
    scanned: true,
    repoVisibility: "private",
    repoUrl: "https://github.com/your-org/example-active-app.git",
    lastUpdated: "2026-01-15",
    lastScanned: "2026-01-15",
    scanVersion: "v6.7",
    tech: {
      frontend: "React 18, Vite, Tailwind CSS",
      backend: "Next.js API routes",
      dataStorage: "Supabase Postgres + RLS",
      integrations: "Stripe, Resend, PostHog",
      auth: "Supabase Auth (email + OAuth)",
      testing: "Playwright",
      hosting: "Vercel"
    },
    envSecrets: ["NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "STRIPE_SECRET_KEY"],
    metrics: {
      totalLines: 12450,
      codeLines: 9800,
      dataLines: 2650,
      linesByType: { ".tsx": 5400, ".ts": 3200, ".css": 800, ".json": 400, ".md": 1200 },
      components: 32,
      pages: 14,
      apiRoutes: 9,
      filesOver500: 2,
      duplicationAreas: 0
    },
    flags: [
      { text: "Stripe webhook endpoint missing signature verification", severity: "P1", category: "webhook-signature", confidence: 1.00, owasp: "A01" },
      { text: "No rate limiting on /api/auth/login", severity: "P2", category: "auth-rate-limiting", confidence: 0.90, owasp: "A07" },
      { text: "Source maps shipped to production via vite.config.js", severity: "P3", category: "source-maps-exposed", confidence: 0.95 },
      { text: "console.log statements in production code (12 across 4 files)", severity: "P4", category: "debug-logging", confidence: 0.90 },
      { text: "X-Frame-Options header missing", status: "resolved", note: "Added in vercel.json on 2026-01-10" },
      { text: "OAuth access tokens in localStorage", status: "accepted", note: "CSP blocks XSS, token scoped to user data only" }
    ]
  },
  {
    name: "Example Commercial App",
    category: "Commercial",
    url: "https://your-paid-saas.com",
    description: "The revenue-bearing one. Watchtower treats it with extra care.",
    completion: 100,
    scanned: true,
    repoVisibility: "private",
    lastUpdated: "2026-01-15",
    lastScanned: "2026-01-15",
    scanVersion: "v6.7",
    tech: {
      frontend: "Next.js 14, React 18",
      backend: "Next.js API routes + Supabase Edge Functions",
      dataStorage: "Supabase Postgres + RLS, Stripe (subscriptions)",
      auth: "Supabase Auth + Stripe Customer Portal",
      hosting: "Vercel"
    },
    flags: []
  },
  {
    name: "Example Archived App",
    category: "Archived",
    description: "Sits in the grid for context but doesn't count toward aggregate stats.",
    scanned: false,
    lastUpdated: "2025-08-01",
    lastScanned: "2025-08-01",
    flags: []
  }
];
