import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import pg from 'pg';
import { loadLocalEnv } from '../../scripts/storage/lib.mjs';
import { captureRequests, newVaultPassphrase, readableStorage } from './helpers';
import {
  acceptThroughUi,
  createRoomThroughUi,
  inviteThroughUi,
  openRoomThroughUi,
  PASSPHRASE_FIELD,
  signedInWithVault,
  verifiedSafetyCode,
} from './room-helpers';

// Phase 11 in the browser (CM-T050 to CM-T053) in Chromium, Firefox and WebKit, against the built
// static export under the production CSP and the real API:
// - A: removing a member locks the room; an admin rotates the key in the browser; the remaining
//   members verify the new version, see a new Safety Code, and the room accepts content again;
// - B: an interrupted rotation (cancelled) leaves the room locked; a new rotation recovers it;
// - C: a member resets their vault; the room shows that they need keys; an admin re-shares after
//   comparing the fingerprint, and the member verifies the room key with the new identity.
// Every account, room and passphrase is synthetic. Key material never leaves the browsers.

loadLocalEnv();

async function withDatabase<T>(fn: (db: pg.Client) => Promise<T>): Promise<T> {
  const db = new pg.Client({ connectionString: process.env['DATABASE_URL'] });
  await db.connect();
  try {
    return await fn(db);
  } finally {
    await db.end();
  }
}

async function keyState(roomId: string): Promise<{ key_state: string; current_key_version: number }> {
  return withDatabase(async (db) => {
    const { rows } = await db.query<{ key_state: string; current_key_version: number }>(
      'SELECT key_state::text, current_key_version FROM rooms WHERE id = $1',
      [roomId],
    );
    const row = rows[0];
    if (row === undefined) throw new Error('room not found');
    return row;
  });
}

/** A second person in their own browser context. */
async function secondPerson(browser: Browser, name: string) {
  const context: BrowserContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const user = await signedInWithVault(page, name);
  return { context, page, user };
}

async function removeThroughUi(page: Page, name: string, password: string): Promise<void> {
  const row = page.getByRole('list', { name: 'Members' }).getByRole('listitem').filter({ hasText: name });
  await row.getByRole('button', { name: 'Remove' }).click();
  await confirmIfAsked(page, password);
  await expect(page.getByText(`${name} was removed.`)).toBeVisible({ timeout: 60_000 });
}

/** Answers the step-up form if the server asked for one (a recent one may still be fresh). */
async function confirmIfAsked(page: Page, password: string): Promise<void> {
  const confirm = page.getByRole('heading', { name: 'Confirm your account' });
  if (await confirm.isVisible().catch(() => false)) {
    await page.getByLabel('Account password').first().fill(password);
    await page.getByRole('button', { name: 'Confirm account' }).click();
  }
}

/** Starts a rotation and returns the review list's names. */
async function startRotation(page: Page): Promise<string[]> {
  await page.getByRole('button', { name: /Rotate the room key/ }).click();
  const review = page.getByTestId('rekey-review');
  await expect(review).toBeVisible({ timeout: 60_000 });
  return (await review.getByTestId('rekey-recipient-name').allInnerTexts()).map((t) => t.trim());
}

async function finishRotation(page: Page, version: number): Promise<void> {
  await page.getByRole('button', { name: 'Create and share the new key' }).click();
  await expect(page.getByTestId('rekey-done')).toContainText(`Key version ${String(version)} is now current`, {
    timeout: 90_000,
  });
  await expect(page.getByTestId('room-key-status')).toContainText(`Room key version ${String(version)} verified`, {
    timeout: 60_000,
  });
}

test('A: a removal locks the room; a rotation in the browser gives the remaining members a new verified key', async ({
  page,
  browser,
}) => {
  test.setTimeout(420_000);
  const owner = await signedInWithVault(page, 'Rotation Owner');
  const captured = captureRequests(page);
  const roomId = await createRoomThroughUi(page, 'Rotation room');
  const before = await verifiedSafetyCode(page);
  const member = await secondPerson(browser, 'Staying Member');
  const leaving = await secondPerson(browser, 'Removed Member');
  for (const who of [member, leaving]) {
    await openRoomThroughUi(page, 'Rotation room');
    await inviteThroughUi(page, who.user, 'Member', false);
    await acceptThroughUi(who.page, 'Rotation room');
    await verifiedSafetyCode(who.page);
  }

  await openRoomThroughUi(page, 'Rotation room');
  await removeThroughUi(page, 'Removed Member', owner.password);
  await expect(page.getByTestId('rekey-state')).toContainText('Locked until the room key is rotated');
  expect(await keyState(roomId)).toEqual({ key_state: 'REKEY_REQUIRED', current_key_version: 1 });
  // Content writes are refused while locked (the API decides; the page says why).
  await expect(page.getByText('The room key must be rotated.').first()).toBeVisible();

  const names = await startRotation(page);
  expect(names.sort()).toEqual(['Rotation Owner', 'Staying Member']);
  expect(await keyState(roomId)).toMatchObject({ key_state: 'REKEYING' });
  await finishRotation(page, 2);
  expect(await keyState(roomId)).toEqual({ key_state: 'ACTIVE', current_key_version: 2 });
  const after = await verifiedSafetyCode(page);
  expect(after).not.toBe(before);

  // The remaining member verifies version 2 on their own device and sees the same new code.
  await openRoomThroughUi(member.page, 'Rotation room');
  await expect(member.page.getByTestId('room-key-status')).toContainText('Room key version 2 verified', {
    timeout: 60_000,
  });
  expect(await verifiedSafetyCode(member.page)).toBe(after);
  // The removed member sees nothing of the room any more.
  await leaving.page.goto(`/rooms/room?id=${roomId}`);
  await expect(leaving.page.getByText('This room does not exist, or you are not a member of it.')).toBeVisible();

  // No key material, passphrase or Safety Code left the owner's browser or entered its storage.
  const sent = captured.map((c) => `${c.url} ${c.body}`).join('\n');
  for (const value of [after, owner.passphrase]) {
    expect(sent.includes(value)).toBe(false);
    expect(await readableStorage(page)).not.toContain(value);
  }
  await member.context.close();
  await leaving.context.close();
});

test('B: a cancelled rotation leaves the room locked; a new rotation recovers it', async ({ page, browser }) => {
  test.setTimeout(420_000);
  const owner = await signedInWithVault(page, 'Recovery Owner');
  const roomId = await createRoomThroughUi(page, 'Recovery room');
  await verifiedSafetyCode(page);
  const leaving = await secondPerson(browser, 'Departing Member');
  await openRoomThroughUi(page, 'Recovery room');
  await inviteThroughUi(page, leaving.user, 'Member', false);
  await acceptThroughUi(leaving.page, 'Recovery room');
  // The member leaves on their own (AZ-11).
  await leaving.page.getByLabel('I want to leave this room.').check();
  await leaving.page.getByRole('button', { name: 'Leave room' }).click();
  await expect(leaving.page).toHaveURL(/\/rooms$/);

  await openRoomThroughUi(page, 'Recovery room');
  await expect(page.getByTestId('rekey-state')).toContainText('a member left');
  await startRotation(page);
  // The rotation is interrupted: cancelled before anything was made.
  await page.getByTestId('rekey-review').getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByTestId('rekey-state')).toContainText('Locked until the room key is rotated', {
    timeout: 60_000,
  });
  expect(await keyState(roomId)).toEqual({ key_state: 'REKEY_REQUIRED', current_key_version: 1 });
  // Locking the vault in the middle of a review drops it; nothing partial exists.
  await startRotation(page);
  await page.getByRole('button', { name: 'Lock now' }).first().click();
  await expect(page.getByTestId('rekey-review')).toHaveCount(0);
  expect(await keyState(roomId)).toMatchObject({ current_key_version: 1 });
  // Recovery: unlock and rotate again; the open operation of this owner is superseded.
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await page.getByLabel(PASSPHRASE_FIELD).fill(owner.passphrase);
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 90_000 });
  await openRoomThroughUi(page, 'Recovery room');
  await startRotation(page);
  await finishRotation(page, 2);
  expect(await keyState(roomId)).toEqual({ key_state: 'ACTIVE', current_key_version: 2 });
  await leaving.context.close();
});

test('C: after a vault reset the admin re-shares the room keys and the member verifies them with the new identity', async ({
  page,
  browser,
}) => {
  test.setTimeout(420_000);
  await signedInWithVault(page, 'Sharing Owner');
  await createRoomThroughUi(page, 'Reset room');
  const code = await verifiedSafetyCode(page);
  const member = await secondPerson(browser, 'Resetting Member');
  await openRoomThroughUi(page, 'Reset room');
  await inviteThroughUi(page, member.user, 'Member', false);
  await acceptThroughUi(member.page, 'Reset room');
  expect(await verifiedSafetyCode(member.page)).toBe(code);

  // The member replaces their identity (strict step-up, new passphrase).
  await member.page.getByRole('link', { name: 'Vault', exact: true }).click();
  await member.page.getByRole('button', { name: 'Replace my identity' }).click();
  await confirmIfAsked(member.page, member.user.password);
  const fresh = newVaultPassphrase();
  // The passphrase-change form uses the same labels; the reset form comes last on the page.
  await member.page.getByLabel('New Vault Passphrase (not your account password)').last().fill(fresh);
  await member.page.getByLabel('Repeat the new Vault Passphrase').last().fill(fresh);
  await member.page
    .getByLabel('I understand that my current identity and what was encrypted only for it cannot be restored.')
    .check();
  await member.page.getByRole('button', { name: 'Replace identity' }).click();
  await expect(member.page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 90_000 });
  const newFingerprint = (await member.page.getByTestId('own-fingerprint').innerText()).trim();
  // The old key cannot be substituted: the member holds no room key for the new identity yet.
  await openRoomThroughUi(member.page, 'Reset room');
  await expect(member.page.getByText('There is no room key for your current identity')).toBeVisible({
    timeout: 60_000,
  });

  // The owner sees who needs keys, compares the new fingerprint and re-shares.
  await openRoomThroughUi(page, 'Reset room');
  const reshare = page.getByTestId('reshare');
  await expect(reshare).toContainText('Resetting Member', { timeout: 60_000 });
  await reshare.getByRole('button', { name: 'Share keys again' }).click();
  const shown = (await page.getByTestId('reshare-fingerprint').innerText()).trim();
  expect(shown.replace(/\s+/g, '')).toBe(newFingerprint.replace(/\s+/g, ''));
  await reshare.getByLabel('I compared this fingerprint with them over a channel I trust.').check();
  await reshare.getByRole('button', { name: 'Share the room keys' }).click();
  await expect(page.getByText('Resetting Member received 1 key version(s).')).toBeVisible({ timeout: 60_000 });

  // The member verifies the room key through the new grant and sees the same Safety Code.
  await openRoomThroughUi(member.page, 'Reset room');
  expect(await verifiedSafetyCode(member.page)).toBe(code);
  await expect(
    member.page.getByText('You hold this key through a membership grant signed by an owner or admin.'),
  ).toBeVisible();
  await member.context.close();
});
