import { expect, test, type Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';

// Browser-level authentication checks (Phase 3) in Chromium, Firefox and WebKit:
// - the session and pre-authentication cookies are HttpOnly, Secure, SameSite=Strict, __Host-;
// - no authentication secret ends up in document.cookie, localStorage, sessionStorage or IndexedDB;
// - fetch() sends the real Origin under Referrer-Policy: no-referrer (CM-T020);
// - the UI flows work end to end against the real API, including TOTP enrollment.

const identity = () => ({
  email: `e2e-${randomBytes(6).toString('hex')}@example.test`,
  password: `${randomBytes(15).toString('base64url')}!`,
  name: 'Synthetic E2E User',
});

async function register(page: Page, user: ReturnType<typeof identity>) {
  await page.goto('/register');
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Display name').fill(user.name);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByLabel('Repeat the password').fill(user.password);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByText('Your account exists')).toBeVisible();
}

async function login(page: Page, user: ReturnType<typeof identity>) {
  await page.goto('/login');
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
}

/** Everything a script in the page can read from browser storage, as one string. */
async function readableStorage(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const dump = (storage: Storage) => JSON.stringify(Object.keys(storage).map((key) => [key, storage.getItem(key)]));
    const parts = [document.cookie, dump(localStorage), dump(sessionStorage)];
    if ('databases' in indexedDB) parts.push(JSON.stringify(await indexedDB.databases()));
    return parts.join('\n');
  });
}

test('session cookies are HttpOnly, Secure, SameSite=Strict and invisible to page scripts', async ({
  page,
  context,
  browserName,
}) => {
  const user = identity();
  await register(page, user);
  const loginResponse = page.waitForResponse((r) => r.url().endsWith('/api/auth/login'));
  await login(page, user);
  const setCookie = (await (await loginResponse).headerValue('set-cookie')) ?? '';
  expect(setCookie).toMatch(
    /__Host-cm_session=[A-Za-z0-9_-]{43}; Max-Age=43200; Path=\/; Secure; HttpOnly; SameSite=Strict/,
  );
  await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible();

  const cookies = await context.cookies();
  const session = cookies.find((c) => c.name === '__Host-cm_session');
  expect(session).toMatchObject({ httpOnly: true, secure: true, path: '/' });
  // Playwright's WebKit builds for Windows and Linux report every cookie as SameSite=None; the
  // attribute the server sent is asserted on the Set-Cookie header above for all engines.
  if (browserName !== 'webkit') expect(session?.sameSite).toBe('Strict');
  expect(session?.domain).toBe('127.0.0.1');

  const storage = await readableStorage(page);
  expect(storage).not.toContain(String(session?.value));
  expect(storage).not.toContain('cm_session');
  expect(storage).not.toContain(user.password);

  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  expect((await context.cookies()).some((c) => c.name === '__Host-cm_session')).toBe(false);
});

test('fetch() sends the real Origin for state changes under Referrer-Policy: no-referrer', async ({
  page,
  baseURL,
}) => {
  const user = identity();
  const origins: (string | undefined)[] = [];
  page.on('request', (request) => {
    if (request.url().endsWith('/api/auth/register') && request.method() === 'POST') {
      void request.allHeaders().then((h) => origins.push(h['origin']));
    }
  });
  const response = await page.goto('/register');
  expect(response?.headers()['referrer-policy']).toBe('no-referrer');
  await register(page, user);
  await expect.poll(() => origins.length).toBeGreaterThan(0);
  expect(origins[0]).toBe(new URL(String(baseURL)).origin);
});

test('MFA enrollment and login keep the secret and recovery codes out of storage', async ({ page, context }) => {
  const user = identity();
  await register(page, user);
  await login(page, user);
  await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible();

  // Enrollment needs a recent step-up; the server says so first.
  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  await expect(page.getByText('Confirm your identity to continue')).toBeVisible();
  await page.getByLabel('Account password').first().fill(user.password);
  await page.getByRole('button', { name: 'Confirm' }).click();
  await expect(page.getByText('None in this session')).toHaveCount(0);
  await expect(page.getByText('Confirm your identity to continue')).toHaveCount(0);
  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();

  await expect(page.getByRole('img', { name: 'QR code for the authenticator app' })).toBeVisible();
  const secret = (await page.locator('p.font-mono').innerText()).trim();
  const totp = (offset = 0) =>
    TOTP.generate({ secret: Secret.fromBase32(secret), digits: 6, period: 30, timestamp: Date.now() + offset });
  await page.getByLabel('Code from the app').fill(totp());
  await page.getByRole('button', { name: 'Turn on' }).click();

  await expect(page.getByRole('heading', { name: 'Recovery codes' })).toBeVisible();
  const codes = await page.locator('ul.font-mono li').allInnerTexts();
  expect(codes).toHaveLength(10);
  const storage = await readableStorage(page);
  for (const value of [secret, ...codes]) expect(storage).not.toContain(value);
  await page.getByRole('button', { name: 'I have stored them' }).click();
  await expect(page.getByText(String(codes[0]))).toHaveCount(0);

  // A new login now needs the second factor; only a pre-authentication cookie exists before it.
  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  await page.waitForLoadState('networkidle');
  await login(page, user);
  await expect(page.getByLabel('Authentication code')).toBeVisible();
  const before = (await context.cookies()).map((c) => c.name);
  expect(before).toContain('__Host-cm_preauth');
  expect(before).not.toContain('__Host-cm_session');
  await page.getByRole('button', { name: 'Use a recovery code' }).click();
  await page.getByLabel('Recovery code').fill(String(codes[0]));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible();
  const after = await context.cookies();
  expect(after.find((c) => c.name === '__Host-cm_session')).toMatchObject({ httpOnly: true, secure: true });
  expect(after.some((c) => c.name === '__Host-cm_preauth')).toBe(false);
});

test('negative control: the storage check detects a token that page scripts could read', async ({
  page,
  context,
  baseURL,
}) => {
  // Simulates the defect the checks above guard against, without changing the application:
  // a session-like cookie set without HttpOnly becomes visible to document.cookie.
  await page.goto('/');
  await context.addCookies([
    { name: 'exposed_session', value: 'canary-exposed-token', url: String(baseURL), httpOnly: false, secure: true },
  ]);
  expect(await readableStorage(page)).toContain('canary-exposed-token');
});
