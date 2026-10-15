import { expect, test, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { login, newUser, newVaultPassphrase, register, type TestUser } from '../e2e/helpers';
import {
  confirmAccount,
  createRoomThroughUi,
  enrollMfa,
  PASSPHRASE_FIELD,
  totp,
  verifiedSafetyCode,
} from '../e2e/room-helpers';
import { authSlots } from './pace';

// Screenshots of the running deployment for the university report (local Docker demonstration or,
// later, the cloud VM). Runs on demand: CM_DEMO_EVIDENCE_DIR names the output directory. Synthetic
// accounts only; no password, passphrase, authenticator secret or recovery code is ever on screen.
// The platform administrator is granted with the server-side CLI (cm-platform-admin), as an
// operator would; there is no API for it.

const out = process.env['CM_DEMO_EVIDENCE_DIR'];
const root = fileURLToPath(new URL('../../', import.meta.url));
test.skip(out === undefined || out === '', 'screenshots on demand (CM_DEMO_EVIDENCE_DIR)');
test.use({ viewport: { width: 1440, height: 900 } });

// caret: 'initial' keeps Playwright from injecting a style element, which the page's CSP refuses.
// The Room Safety Code is never stored (INV-18), not even in a screenshot: it is masked.
const shot = (page: Page, name: string) =>
  page.screenshot({
    path: join(out ?? '', name),
    fullPage: true,
    animations: 'disabled',
    caret: 'initial',
    mask: [page.getByTestId('safety-code-words')],
  });

async function signInWithCode(page: Page, user: TestUser, secret: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Authentication code').fill(await totp(secret));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
}

test('capture the deployment demonstration screenshots', async ({ page, browser }) => {
  test.setTimeout(10 * 60_000);
  mkdirSync(out ?? '', { recursive: true });

  // A member with a vault, a room, a file and a note.
  const alice = { ...newUser(), name: 'Alice (synthetic)' };
  await authSlots(1);
  await register(page, alice);
  await authSlots(1);
  await login(page, alice);
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await authSlots(1);
  await confirmAccount(page, alice);
  const passphrase = newVaultPassphrase();
  await page.getByLabel(PASSPHRASE_FIELD).fill(passphrase);
  await page.getByLabel('Repeat the Vault Passphrase').fill(passphrase);
  await page.getByLabel('I understand that CipherMesh cannot recover a lost Vault Passphrase.').check();
  await page.getByRole('button', { name: 'Create vault' }).click();
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 120_000 });
  await shot(page, '01_vault-unlocked.png');

  await createRoomThroughUi(page, 'Demonstration room');
  await verifiedSafetyCode(page);
  await page.getByTestId('file-input').setInputFiles({
    name: 'synthetic-report.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('Synthetic demonstration file. No real data.\n'),
  });
  await page.getByTestId('file-upload').click();
  await expect(page.getByText('The file was encrypted in your browser and uploaded.')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('note-new').click();
  await page.getByTestId('note-title-input').fill('Synthetic note');
  await page.getByTestId('note-body-input').fill('This text is encrypted in the browser before it is stored.');
  await page.getByTestId('note-create').click();
  await expect(page.getByText('The note was encrypted in your browser and saved.')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('file-receipt').first().locator('summary').click();
  await page.getByTestId('note-receipt').first().locator('summary').click();
  await shot(page, '02_room-encrypted-file-and-note-receipts.png');

  // A platform administrator with MFA, granted on the server.
  const context = await browser.newContext({
    ignoreHTTPSErrors: test.info().project.use.ignoreHTTPSErrors ?? false,
    viewport: { width: 1440, height: 900 },
  });
  const admin = await context.newPage();
  const officer = { ...newUser(), name: 'Security Officer (synthetic)' };
  await authSlots(1);
  await register(admin, officer);
  await authSlots(1);
  await login(admin, officer);
  await authSlots(3);
  const secret = await enrollMfa(admin, officer);
  const granted = spawnSync(process.execPath, ['scripts/demo.mjs', 'admin', officer.email], {
    cwd: root,
    encoding: 'utf8',
  });
  expect(granted.status, granted.stderr).toBe(0);
  await authSlots(2);
  await signInWithCode(admin, officer, secret);

  await admin.goto('/trust/infrastructure');
  await expect(admin.getByTestId('deployment-live')).not.toContainText('Checking', { timeout: 30_000 });
  await shot(admin, '03_trust-infrastructure-live-status.png');

  await admin.goto('/trust/dashboard');
  await expect(admin.getByTestId('security-dashboard')).toBeVisible({ timeout: 30_000 });
  await shot(admin, '04_security-dashboard-measured-platform.png');

  await admin.goto('/trust/governance');
  await shot(admin, '05_trust-governance-risks-and-controls.png');
  await context.close();
});
