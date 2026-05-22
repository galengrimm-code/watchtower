// Example shape for window.AI_TOOL_INTEL — AI tool supply chain audit.
//
// In the public Watchtower repo, this is the only AI-intel file that ships.
// At runtime the live file at data/ai-tool-intel.js (gitignored) is updated by
// Phase A of the scheduled scan. The block between AI_INTEL:AUTO:START and
// AI_INTEL:AUTO:END is replaced wholesale each run; comments outside survive.

window.AI_TOOL_INTEL = /* <!-- AI_INTEL:AUTO:START --> */ {
  scannedAt: "2026-01-15",

  // FlorianBruniaux/claude-code-ultimate-guide threat-db.yaml — community-maintained.
  // Treat as advisory and cross-check critical findings against NVD/Snyk.
  threatDb: {
    version: "2.17.0",
    updated: "2026-01-11",
    daysOld: 4,
    stale: false,
    sourceUrl: "https://github.com/FlorianBruniaux/claude-code-ultimate-guide/blob/main/examples/commands/resources/threat-db.yaml"
  },

  claudeCode: {
    version: "2.1.143",
    minimumSafe: "2.1.34",
    upToDate: true
  },

  installed: {
    skills: 42,
    pluginSkills: 8,
    plugins: 1,
    agents: 6,
    mcpServers: 3,
    hooks: 1
  },

  installedMcps: [
    {
      name: "example-mcp-server",
      version: "0.5.0",
      pinned: true,
      source: "global ~/.claude.json",
      safeListStatus: "unvetted",
      cves: 0,
      tokenInArgs: false,
      env: "EXAMPLE_TOKEN via ${} interpolation"
    }
  ],

  installedPlugins: [
    { name: "example-plugin", version: "1.0.0", safeListStatus: "user-installed" }
  ],

  installedSkills: [
    { name: "example-skill", source: "local", safeListStatus: "user-authored" }
  ],

  // Flags Phase A produces — typed identically to per-project flags so the
  // dashboard can render them in the same UI.
  flags: [
    {
      text: "MCP server example-mcp-server is unvetted (not on the curated safe list)",
      severity: "P3",
      category: "ai-mcp-unvetted",
      confidence: 0.85
    }
  ],

  topCampaigns: [
    { name: "Example Campaign", firstSeen: "2025-09", category: "supply-chain", description: "Hypothetical attack pattern targeting AI tool stacks." }
  ],

  attackTechniques: [
    { id: "T-001", name: "Example Technique", category: "credential-theft" }
  ],

  recentCves: [
    { id: "CVE-2025-99999", package: "example-package", severity: "high", patchedIn: "1.2.3" }
  ],

  topAttackTechniques: ["credential-theft", "supply-chain-compromise", "prompt-injection"],

  // Phase 10 cross-validation against NVD (NIST National Vulnerability Database).
  // Requires NVD_API_KEY in ~/.claude/.env for higher rate limits.
  crossCheck: {
    source: "NVD",
    ranAt: "2026-01-15T21:00:00Z",
    totalChecked: 12,
    confirmed: 11,
    disagreements: 1,
    nvdOnly: 0,
    errors: 0,
    apiKey: true,
    notes: "1 community-flagged CVE not present in NVD — community DB likely false positive."
  }
} /* <!-- AI_INTEL:AUTO:END --> */;
