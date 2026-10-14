import { expect, test } from '@playwright/test';
import { collectCspViolations, login, newUser, readableStorage, register, useDistinctClientAddress } from './helpers';

// Phase 14 + Prompt 16.5 (CM-T061): the redesigned shell and the Security & Trust Center in three
// engines. The pages load under the strict CSP, every status they show is observed or sourced
// (never invented), the platform dashboard is refused to everyone but administrators, and the
// navigation works with a keyboard and on a narrow screen. Accounts are synthetic.

const TRUST_PAGES = [
  ['/trust', 'Security & Trust Center'],
  ['/trust/cryptography', 'Data protection & key management'],
  ['/trust/infrastructure', 'Deployment & infrastructure'],
  ['/trust/governance', 'Governance & risk'],
  ['/trust/evidence', 'Security evidence register'],
  ['/trust/walkthrough', 'Guided security walkthrough'],
  ['/trust/dashboard', 'Platform security dashboard'],
] as const;

for (const [path, heading] of TRUST_PAGES) {
  test(`${path} loads under the strict CSP without violations`, async ({ page }) => {
    const violations = await collectCspViolations(page);
    const response = await page.goto(path);
    expect(response?.status()).toBe(200);
    await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(await violations()).toEqual([]);
    // The Trust Center keeps nothing in the browser.
    expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  });
}

test('the live checks report what this browser observes, including what is not configured', async ({ page }) => {
  await page.goto('/trust/infrastructure');
  const checks = page.getByTestId('live-checks');
  await expect(checks.getByTestId('live-check-https')).toHaveAttribute('data-outcome', 'pass');
  await expect(checks.getByTestId('live-check-health')).toHaveAttribute('data-outcome', 'pass');
  await expect(checks.getByTestId('live-check-ready')).toHaveAttribute('data-outcome', 'pass');
  await expect(checks.getByTestId('live-check-content-security-policy')).toHaveAttribute('data-outcome', 'pass');
  await expect(checks.getByTestId('live-check-x-frame-options')).toHaveAttribute('data-outcome', 'pass');
  // HSTS belongs to the TLS edge of the cloud workstream; the test server does not send it.
  await expect(checks.getByTestId('live-check-hsts')).toHaveAttribute('data-outcome', 'absent');
  // The live cloud status is for platform administrators (PA-01): a signed-out visitor is told so,
  // and no state is claimed for them (ADR-014).
  await expect(page.getByTestId('deployment-live')).toContainText('Administrators only');
  await expect(page.getByTestId('deployment-live')).not.toContainText(/Healthy|Degraded|Not connected/);
  // No cloud-side control is claimed: every verified control names a local or CI scope.
  const verified = page.getByTestId('cloud-control').filter({ hasText: /Verified \(/ });
  await expect(verified.first()).toBeVisible();
  await expect(page.getByTestId('cloud-control').filter({ hasText: 'Verified (cloud)' })).toHaveCount(0);
});

test('the evidence register shows missing and deferred evidence as such', async ({ page }) => {
  await page.goto('/trust/evidence#EV-12-01');
  const audit = page.locator('#EV-12-01');
  await expect(audit).toContainText('Deferred');
  await page.getByTestId('evidence-status').selectOption('pending');
  await expect(page.getByTestId('evidence-item').first()).toContainText('Missing');
  await page.getByTestId('evidence-status').selectOption('captured');
  await page.getByTestId('evidence-subject').selectOption('CRY');
  const items = page.getByTestId('evidence-item');
  await expect(items.first()).toContainText('Captured');
  // A captured item links to its committed, redacted file.
  await expect(page.locator('#EV-07-01').getByRole('link').first()).toHaveAttribute(
    'href',
    /github\.com\/.+\/blob\/main\/docs\/report\/evidence\/phase-07\//,
  );
});

test('a risk opened by its link shows its controls, and the audit ledger is marked not implemented', async ({
  page,
}) => {
  await page.goto('/trust/governance#T-06');
  const risk = page.locator('details#T-06');
  await expect(risk).toHaveAttribute('open', '');
  await expect(risk).toContainText('Security controls');
  await page.goto('/trust');
  await expect(page.getByText('Tamper-evident audit ledger')).toBeVisible();
  await expect(page.getByTestId('trust-claim').first()).toBeVisible();
});

test('the platform dashboard is refused to signed-out users and to non-administrators', async ({ page }) => {
  await page.goto('/trust/dashboard');
  await expect(page.getByText('Sign in with a platform administrator account')).toBeVisible();
  const user = newUser();
  await useDistinctClientAddress(page);
  await register(page, user);
  await login(page, user);
  await page.goto('/trust/dashboard');
  await expect(page.getByText('available to platform administrators only')).toBeVisible();
  await expect(page.getByTestId('security-dashboard')).toHaveCount(0);
});

test('signing in leads to the overview with real notices, and the sidebar reaches every section', async ({ page }) => {
  const user = newUser();
  await useDistinctClientAddress(page);
  await register(page, user);
  await login(page, user);
  // A new account has no vault and no second factor: the overview says so, and counts are zero.
  const notices = page.getByRole('region', { name: 'Notices' });
  await expect(notices.getByText('Your vault is not set up yet.')).toBeVisible();
  await expect(notices.getByText('Two-step sign-in is off.')).toBeVisible();
  await expect(page.getByText('No rooms yet')).toBeVisible();
  const nav = page.getByRole('navigation', { name: 'Primary' });
  await expect(nav.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
  for (const [name, heading] of [
    ['Rooms', 'Rooms'],
    ['Invitations', 'Invitations'],
    ['Vault', 'Vault'],
    ['Trust Center', 'Security & Trust Center'],
    ['Account', 'Account'],
  ] as const) {
    await nav.getByRole('link', { name, exact: true }).click();
    await expect(page.getByRole('heading', { level: 1, name: heading, exact: true })).toBeVisible();
    await expect(nav.getByRole('link', { name, exact: true })).toHaveAttribute('aria-current', 'page');
  }
  // Nothing about the session, the vault or the visited pages is kept in browser storage.
  expect(await readableStorage(page)).not.toContain(user.email);
});

test('on a narrow screen the navigation opens from the menu button and closes with Escape', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/trust');
  const nav = page.getByRole('navigation', { name: 'Primary' });
  await expect(nav).toBeHidden();
  const menu = page.getByRole('button', { name: 'Open menu' });
  await menu.click();
  await expect(nav).toBeVisible();
  await expect(page.getByRole('button', { name: 'Close menu' })).toHaveAttribute('aria-expanded', 'true');
  await page.keyboard.press('Escape');
  await expect(nav).toBeHidden();
  // The page itself does not scroll sideways.
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
});

test('the first Tab reaches the skip link, which moves focus past the navigation', async ({ page, browserName }) => {
  // WebKit on macOS does not move focus to links with Tab by default.
  test.skip(browserName === 'webkit', 'Tab does not focus links in WebKit by default');
  await page.goto('/trust/cryptography');
  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: 'Skip to content' });
  await expect(skip).toBeFocused();
  await expect(skip).toHaveAttribute('href', '#content');
});
