import { defineConfig, devices } from '@playwright/test';

// Deployment smoke test (ADR-014, Scenario A of the cloud demonstration): runs the real browser
// cryptography against a running deployment (the Oracle VM, or the local rehearsal of the same
// stack) through its public edge only. Unlike tests/e2e it starts no server and never touches
// the database or storage directly, so it can run against production. Synthetic accounts only.
//
//   CM_SMOKE_APP_ORIGIN=https://app.example pnpm exec playwright test -c playwright.deployment.config.ts
//   CM_SMOKE_APP_ORIGIN=https://app.localhost:8443 CM_SMOKE_TRUST_LOCAL_CA=1 ... (rehearsal only)
const origin = process.env['CM_SMOKE_APP_ORIGIN'];
if (origin === undefined || !origin.startsWith('https://')) {
  throw new Error('Set CM_SMOKE_APP_ORIGIN to the https:// origin of the deployment');
}
// The rehearsal's certificates come from a throwaway local CA; the cloud's must be publicly trusted.
const rehearsal = process.env['CM_SMOKE_TRUST_LOCAL_CA'] === '1';

export default defineConfig({
  testDir: 'tests/deployment',
  forbidOnly: Boolean(process.env['CI']),
  retries: 0,
  workers: 1,
  reporter: 'list',
  outputDir: 'test-results/deployment',
  // A remote deployment answers more slowly than the loopback test server; the assertions are
  // the same, only the waiting time is longer.
  expect: { timeout: 15_000 },
  use: {
    baseURL: origin,
    ignoreHTTPSErrors: rehearsal,
    trace: 'off',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
