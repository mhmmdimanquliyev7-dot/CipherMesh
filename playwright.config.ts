import { defineConfig, devices } from '@playwright/test';

// E2E tests run against the built static export (`pnpm build` first), served with the
// generated security headers. Chromium, Firefox and WebKit, as CLAUDE.md section 10 requires.
const port = 4173;

export default defineConfig({
  testDir: 'tests/e2e',
  forbidOnly: Boolean(process.env['CI']),
  retries: 0,
  reporter: process.env['CI'] ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: { baseURL: `http://127.0.0.1:${port}` },
  webServer: {
    command: 'node tests/e2e/static-server.mjs',
    url: `http://127.0.0.1:${port}/`,
    env: { E2E_PORT: String(port) },
    reuseExistingServer: !process.env['CI'],
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
