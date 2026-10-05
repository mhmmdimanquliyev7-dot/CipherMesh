import { expect, test, type Page } from '@playwright/test';

// ADR-011 validation (CM-T008): the static export runs under a strict CSP without
// 'unsafe-inline' or 'unsafe-eval' and produces no CSP violations in any engine.

declare global {
  interface Window {
    __cspViolations: string[];
  }
}

async function collectViolations(page: Page): Promise<string[]> {
  const fromConsole: string[] = [];
  page.on('console', (message) => {
    if (/content.security.policy/i.test(message.text())) fromConsole.push(message.text());
  });
  await page.addInitScript(() => {
    window.__cspViolations = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      window.__cspViolations.push(`${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  return fromConsole;
}

test('the shell loads under the strict CSP without violations', async ({ page }) => {
  const consoleViolations = await collectViolations(page);
  const response = await page.goto('/');
  expect(response?.status()).toBe(200);

  const csp = response?.headers()['content-security-policy'] ?? '';
  expect(csp).toContain("default-src 'none'");
  // 'wasm-unsafe-eval' (ADR-010) is the only relaxation; the quoted keywords below never appear.
  expect(csp).not.toMatch(/'unsafe-inline'|'unsafe-eval'/);

  await expect(page.getByRole('heading', { level: 1 })).toContainText('Client-side encrypted');
  await expect(page.getByText('Not yet available', { exact: false }).first()).toBeVisible();
  await page.waitForLoadState('networkidle');

  expect(await page.evaluate(() => window.__cspViolations)).toEqual([]);
  expect(consoleViolations).toEqual([]);
});

// Pages that bundle the shared zod schemas load directly, so a violation cannot hide behind
// prefetch timing: zod's eval probe once reported 'script-src eval' here (Phase 3 CI, ADR-011).
for (const path of ['/login', '/register', '/account']) {
  test(`${path} loads under the strict CSP without violations`, async ({ page }) => {
    const consoleViolations = await collectViolations(page);
    const response = await page.goto(path);
    expect(response?.status()).toBe(200);
    await page.waitForLoadState('networkidle');
    expect(await page.evaluate(() => window.__cspViolations)).toEqual([]);
    expect(consoleViolations).toEqual([]);
  });
}

test('unknown pages return 404 with the CipherMesh not-found page and the same headers', async ({ page }) => {
  const consoleViolations = await collectViolations(page);
  const response = await page.goto('/does-not-exist');
  expect(response?.status()).toBe(404);
  expect(response?.headers()['x-frame-options']).toBe('DENY');
  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible();
  await page.waitForLoadState('networkidle');
  expect(await page.evaluate(() => window.__cspViolations)).toEqual([]);
  expect(consoleViolations).toEqual([]);
});

// Security finding SF-04-01 (Phase 4): /login and /register are prerendered with their forms. If
// the client bundle has not run yet (slow network, blocked script), a native submission would be
// a GET that puts the typed values, including the account password, into the URL, and from there
// into server logs and the browser history. The client never submits forms natively, so the CSP
// says form-action 'none', and submit buttons stay disabled until the page has hydrated.
for (const path of ['/login', '/register']) {
  test(`${path}: a form submitted before the client runs sends no typed value anywhere`, async ({ page }) => {
    const canary = `canary-${String(Date.now())}-password`;
    const requests: string[] = [];
    page.on('request', (request) => requests.push(`${request.url()} ${request.postData() ?? ''}`));
    await collectViolations(page);
    // The page never hydrates: every client script is refused.
    await page.route(/\/_next\/static\/chunks\/.+\.js$/, (route) => route.abort());
    await page.goto(path);
    await page.getByLabel('Email address').fill('prehydration@example.test');
    await page.getByLabel('Account password').fill(canary);
    await expect(page.locator('form button[type="submit"]')).toBeDisabled();
    // Even a forced submission, which a disabled button cannot start, is refused by the browser.
    await page.evaluate(() => {
      document.querySelector('form')?.requestSubmit();
    });
    await expect.poll(() => page.evaluate(() => window.__cspViolations.join(' '))).toContain('form-action');
    expect(page.url()).not.toContain(canary);
    expect(requests.filter((entry) => entry.includes(canary))).toEqual([]);
  });
}
