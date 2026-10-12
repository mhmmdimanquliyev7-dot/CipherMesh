import { expect, test, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  acceptThroughUi,
  createRoomThroughUi,
  enrollMfa,
  inviteThroughUi,
  loginWithMfa,
  openRoomThroughUi,
  signedInWithVault,
  totp,
  unlockVault,
  verifiedSafetyCode,
} from './room-helpers';

// Phase 10 (CM-T046 to CM-T048) in the browser: the room page explains the rules the API enforces
// for the room's profile and policy version, the OWNER upgrades and downgrades the profile (the
// downgrade asks for a fresh identity confirmation), and a member without MFA is refused by the
// server as soon as the room is CONFIDENTIAL. The page only reflects the API's decisions; the
// policy matrix (tests/policy) proves the enforcement. Every value is synthetic.

// Evidence screenshots go to test-results/evidence (copied into docs/report/evidence/phase-10).
const EVIDENCE = resolve('test-results', 'evidence');
async function screenshot(page: Page, name: string): Promise<void> {
  mkdirSync(EVIDENCE, { recursive: true });
  await page.screenshot({ path: join(EVIDENCE, name), fullPage: true });
}

test('the OWNER changes the profile; members without MFA are refused once it is CONFIDENTIAL', async ({
  page,
  browser,
  browserName,
}) => {
  test.skip(browserName !== 'chromium', 'One engine suffices for the policy flow; the API decides every request');
  test.setTimeout(360_000);
  const owner = await signedInWithVault(page, 'Policy Owner');
  const ownerSecret = await enrollMfa(page, owner);
  await loginWithMfa(page, owner, ownerSecret);
  await unlockVault(page, owner.passphrase);
  const roomName = 'Policy room';
  await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);

  const current = page.getByTestId('profile-current');
  const rules = page.getByRole('list', { name: 'Enforced rules' });
  await expect(current).toContainText('Standard');
  await expect(current).toContainText('policy version 1');
  await expect(rules).toContainText('A password sign-in is enough; two-step sign-in is not required.');

  // A member who never turned on two-step sign-in joins while the room is STANDARD.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await context.newPage();
  const member = await signedInWithVault(other, 'Policy Member');
  await openRoomThroughUi(page, roomName);
  await inviteThroughUi(page, member, 'Member', false);
  await acceptThroughUi(other, roomName);
  await expect(other.getByTestId('profile-current')).toContainText('Standard');
  // Only the OWNER is offered the change (UX; the API refuses everyone else, AZ-03).
  await expect(other.getByRole('form', { name: 'Change profile' })).toHaveCount(0);

  // Upgrade: takes effect at once, explained before it is confirmed.
  await openRoomThroughUi(page, roomName);
  const form = page.getByRole('form', { name: 'Change profile' });
  await form.getByLabel('Change the profile to').selectOption('CONFIDENTIAL');
  await expect(form).toContainText('Existing expiry dates are shortened to the new maximum');
  await expect(form.getByRole('button', { name: 'Change profile' })).toBeDisabled();
  await form.getByLabel(/I understand what changes when this room becomes Confidential/).check();
  await form.getByRole('button', { name: 'Change profile' }).click();
  await expect(page.getByText('The room is now Confidential.')).toBeVisible({ timeout: 30_000 });
  await expect(current).toContainText('Confidential');
  await expect(rules).toContainText('Members need a session verified with an authentication code');
  await expect(rules).toContainText('Files and notes must expire within 90 days.');
  await screenshot(page, 'EV-10-04-profile-upgraded.png');

  // The member's next request to the room is refused by the server (PC-01). The room still appears
  // in their list (SS-06 lists memberships, decision D-10-07); opening it shows the refusal.
  await other.getByRole('link', { name: 'Rooms', exact: true }).click();
  await other.getByRole('list', { name: 'Your rooms' }).getByRole('link', { name: roomName }).click();
  await expect(
    other.getByText('This security profile needs a session verified with an authentication code'),
  ).toBeVisible();
  await expect(other.getByTestId('profile-current')).toHaveCount(0);
  await screenshot(other, 'EV-10-02-mfa-required.png');

  // Downgrade: a warning, then a fresh identity confirmation (within 5 minutes) before the API
  // accepts it.
  await form.getByLabel('Change the profile to').selectOption('STANDARD');
  await expect(form).toContainText('Existing expiry dates are not extended');
  await form.getByLabel(/I understand what changes when this room becomes Standard \(a weaker profile\)/).check();
  await form.getByRole('button', { name: 'Change profile' }).click();
  await expect(page.getByRole('heading', { name: 'Confirm your account' })).toBeVisible();
  await expect(page.getByText('Lowering the security profile needs an identity confirmation')).toBeVisible();
  await page.getByLabel('Account password').fill(owner.password);
  await page.getByLabel('Authentication code').fill(await totp(ownerSecret));
  await page.getByRole('button', { name: 'Confirm account' }).click();
  await expect(page.getByText('The room is now Standard.')).toBeVisible({ timeout: 30_000 });
  await expect(current).toContainText('Standard');
  await screenshot(page, 'EV-10-03-profile-downgraded.png');

  // The member is admitted again under STANDARD.
  await openRoomThroughUi(other, roomName);
  await expect(other.getByTestId('profile-current')).toContainText('Standard');
  await context.close();
});
