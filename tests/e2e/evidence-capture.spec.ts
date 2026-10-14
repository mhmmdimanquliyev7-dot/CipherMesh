import { expect, test, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { login, newUser, register, useDistinctClientAddress, type TestUser } from './helpers';
import {
  acceptThroughUi,
  createRoomThroughUi,
  enrollMfa,
  inviteThroughUi,
  signedInWithVault,
  totp,
  verifiedSafetyCode,
} from './room-helpers';

// Phase 14 + Prompt 16.5 evidence (EV-14-01 to EV-14-18): screenshots of the running application
// for the report, taken through the real UI with synthetic accounts and disposable content. Run
// on demand only: CM_CAPTURE_EVIDENCE=1 pnpm exec playwright test evidence-capture --project chromium
// The platform administrator is granted through the server-side CLI, as an operator would. No
// screenshot shows a password, passphrase, TOTP secret, recovery code or key; the Room Safety Code
// section is never captured.

const root = fileURLToPath(new URL('../../', import.meta.url));
const out = join(root, 'docs', 'report', 'evidence', 'phase-14');

test.skip(process.env['CM_CAPTURE_EVIDENCE'] !== '1', 'Evidence capture runs on demand (CM_CAPTURE_EVIDENCE=1)');
test.use({ viewport: { width: 1440, height: 900 } });

const shot = (page: Page, name: string, fullPage = true) =>
  page.screenshot({ path: join(out, name), fullPage, animations: 'disabled' });

function grantPlatformAdmin(email: string): void {
  const result = spawnSync(
    process.execPath,
    ['--env-file-if-exists=.env', '--import', 'tsx', 'apps/api/src/cli/platform-admin.ts', 'grant', email],
    { cwd: root, encoding: 'utf8' },
  );
  expect(result.status, result.stderr).toBe(0);
}

async function signInWithCode(page: Page, user: TestUser, secret: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Authentication code').fill(await totp(secret));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
}

test('capture the Phase 14 + Prompt 16.5 screenshots', async ({ browser, page }) => {
  test.setTimeout(15 * 60_000);
  mkdirSync(out, { recursive: true });

  // EV-14-03: the public start page.
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await shot(page, 'EV-14-03_landing.png');

  // A platform administrator (security officer), granted on the server.
  const adminContext = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const adminPage = await adminContext.newPage();
  const admin = { ...newUser(), name: 'Security Officer' };
  await useDistinctClientAddress(adminPage);
  await register(adminPage, admin);
  await login(adminPage, admin);
  const adminSecret = await enrollMfa(adminPage, admin);
  grantPlatformAdmin(admin.email);
  await signInWithCode(adminPage, admin, adminSecret);

  // The room owner and a member, each in their own browser.
  await signedInWithVault(page, 'Alice Owner');
  const memberContext = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const memberPage = await memberContext.newPage();
  const member = await signedInWithVault(memberPage, 'Bob Member');
  const roomName = 'Quarterly Planning';
  await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  await inviteThroughUi(page, member, 'Member', false);
  await acceptThroughUi(memberPage, roomName);
  await verifiedSafetyCode(memberPage);

  // EV-14-09: the vault, unlocked in this tab (in-app navigation keeps the keys in memory).
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible();
  await shot(page, 'EV-14-09_vault.png');

  // Synthetic content: a file, a note and a secret, all encrypted in the browser.

  await page.getByRole('link', { name: 'Rooms', exact: true }).click();
  await page.getByRole('list', { name: 'Your rooms' }).getByRole('link', { name: roomName }).click();
  await verifiedSafetyCode(page);
  await page.getByTestId('file-input').setInputFiles({
    name: 'synthetic-roadmap.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('Synthetic demonstration file. No real data.\n'),
  });
  await page.getByTestId('file-upload').click();
  await expect(page.getByText('The file was encrypted in your browser and uploaded.')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('file-receipt').first().locator('summary').click();

  await page.getByTestId('note-new').click();
  await page.getByTestId('note-title-input').fill('Launch checklist');
  await page
    .getByTestId('note-body-input')
    .fill('1. Review the security profile\n2. Compare the Safety Code\n3. Rotate after changes');
  await page.getByTestId('note-create').click();
  await expect(page.getByText('The note was encrypted in your browser and saved.')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('note-receipt').first().locator('summary').click();

  await page.getByTestId('secret-new').click();
  await page.getByTestId('secret-recipient').selectOption({ label: member.name });
  await page.getByTestId('secret-text-input').fill('synthetic-demo-token-0000');
  await page.getByTestId('secret-send').click();
  await expect(page.getByTestId('secret-message')).toContainText('was encrypted in your browser', { timeout: 60_000 });

  // EV-14-05 to EV-14-08: the room header and its sections (the Safety Code section is not captured).
  await page.evaluate(() => {
    window.scrollTo(0, 0);
  });
  // Clipped above the Room Safety Code card: the code itself is never recorded (INV-18).
  const safety = await page.getByRole('heading', { name: 'Room Safety Code' }).boundingBox();
  expect(safety).not.toBeNull();
  await page.screenshot({
    path: join(out, 'EV-14-05_room.png'),
    animations: 'disabled',
    clip: { x: 0, y: 0, width: 1440, height: Math.floor((safety?.y ?? 600) - 40) },
  });
  await page.locator('#files').screenshot({ path: join(out, 'EV-14-06_files-receipt.png') });
  await page.locator('#notes').screenshot({ path: join(out, 'EV-14-07_notes-receipt.png') });
  await page.locator('#secrets').screenshot({ path: join(out, 'EV-14-08_secrets.png') });

  // EV-14-10: removal locks the room; the owner rotates the key in the browser.
  const row = page.getByRole('list', { name: 'Members' }).getByRole('listitem').filter({ hasText: member.name });
  await row.getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByText(`${member.name} was removed.`)).toBeVisible({ timeout: 60_000 });
  await page.getByRole('button', { name: /Rotate the room key/ }).click();
  await expect(page.getByTestId('rekey-review')).toBeVisible({ timeout: 60_000 });
  await page.locator('#key-rotation').screenshot({ path: join(out, 'EV-14-10a_rekey-review.png') });
  await page.getByRole('button', { name: 'Create and share the new key' }).click();
  await expect(page.getByTestId('rekey-done')).toContainText('Key version 2 is now current', { timeout: 90_000 });
  await page.locator('#key-rotation').screenshot({ path: join(out, 'EV-14-10b_rekey-done.png') });

  // EV-14-04: the owner's workspace overview.
  await page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: 'Overview' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await expect(page.getByText('Quarterly Planning').first()).toBeVisible();
  await shot(page, 'EV-14-04_overview.png');

  // EV-14-11 to EV-14-17: the Security & Trust Center, as any visitor sees it.
  const visitor = await browser.newPage({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  for (const [path, name] of [
    ['/trust', 'EV-14-11_trust-summary.png'],
    ['/trust/cryptography', 'EV-14-12_data-protection.png'],
    ['/trust/infrastructure', 'EV-14-13_infrastructure.png'],
    ['/trust/governance#T-06', 'EV-14-14_governance-risk.png'],
    ['/trust/evidence', 'EV-14-16_evidence-register.png'],
    ['/trust/walkthrough', 'EV-14-17_walkthrough.png'],
  ] as const) {
    await visitor.goto(path);
    await expect(visitor.getByRole('heading', { level: 1 })).toBeVisible();
    if (path === '/trust/infrastructure') {
      await expect(visitor.getByTestId('live-check-ready')).toHaveAttribute('data-outcome', 'pass');
    }
    await shot(visitor, name);
  }
  await visitor.goto('/trust/governance#controls');
  await visitor.locator('#control-8\\.3 summary').click();
  await visitor.locator('#control-8\\.3').screenshot({ path: join(out, 'EV-14-15_control-evidence.png') });

  // EV-14-01 and EV-14-02: the platform security dashboard after this scenario, with definitions.
  await adminPage.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: 'Trust Center' }).click();
  await adminPage.getByRole('link', { name: 'Security dashboard', exact: true }).click();
  await expect(adminPage.getByTestId('security-dashboard')).toBeVisible();
  await shot(adminPage, 'EV-14-01_security-dashboard.png');
  await adminPage.getByTestId('metric-SD-07').screenshot({ path: join(out, 'EV-14-02_metric-definition.png') });

  // EV-14-18: the overview on a phone-sized screen.
  await page.setViewportSize({ width: 390, height: 844 });
  await shot(page, 'EV-14-18_mobile-overview.png');

  await adminContext.close();
  await memberContext.close();
});
