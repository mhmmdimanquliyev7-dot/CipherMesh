import { defineConfig, devices } from '@playwright/test';

// E2E tests run against the built static export and the built API (`pnpm build` first), served
// over HTTPS on one origin by tests/e2e/static-server.mjs with the generated security headers,
// like Nginx in production. The API needs the database (DATABASE_URL). Chromium, Firefox and
// WebKit, as CLAUDE.md section 10 requires. The self-signed test certificate is accepted only here.
const port = 4173;

export default defineConfig({
  testDir: 'tests/e2e',
  forbidOnly: Boolean(process.env['CI']),
  retries: 0,
  reporter: process.env['CI'] ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: { baseURL: `https://127.0.0.1:${String(port)}`, ignoreHTTPSErrors: true },
  webServer: {
    command: 'node tests/e2e/static-server.mjs',
    url: `https://127.0.0.1:${String(port)}/`,
    ignoreHTTPSErrors: true,
    env: { E2E_PORT: String(port) },
    reuseExistingServer: !process.env['CI'],
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
