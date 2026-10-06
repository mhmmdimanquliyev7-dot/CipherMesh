import { expect, test, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import {
  collectCspViolations,
  login,
  newUser,
  newVaultPassphrase,
  readableStorage,
  register,
  useDistinctClientAddress,
  type TestUser,
} from './helpers';

// Rooms in the browser (Phase 5, CM-T030, CM-T031) in Chromium, Firefox and WebKit, against the
// built static export under the production CSP and the real API:
// - the room page works as a static page with the room ID in the query string, including a reload
//   and a direct visit (ADR-011);
// - the room-name warning is shown, deletion and ownership transfer ask for a step-up;
// - the controls follow the user's role, and the API's answers are what the page shows.
// Room creation needs a vault (SS-04), so each test creates one through the UI first. The second
// member of a room joins through a database fixture, because invitations arrive in Phase 6.

const PASSPHRASE_FIELD = 'Vault Passphrase (not your account password)';

async function confirmAccount(page: Page, user: TestUser): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Confirm your account' })).toBeVisible();
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Confirm account' }).click();
}

/** Registers, signs in and creates a vault through the UI. */
async function signedInWithVault(page: Page): Promise<TestUser> {
  const user = newUser();
  await useDistinctClientAddress(page);
  await register(page, user);
  await login(page, user);
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await confirmAccount(page, user);
  const passphrase = newVaultPassphrase();
  await page.getByLabel(PASSPHRASE_FIELD).fill(passphrase);
  await page.getByLabel('Repeat the Vault Passphrase').fill(passphrase);
  await page.getByLabel('I understand that CipherMesh cannot recover a lost Vault Passphrase.').check();
  await page.getByRole('button', { name: 'Create vault' }).click();
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 60_000 });
  return user;
}

/** Creates a room on the Rooms page; returns its ID from the room page's URL. */
async function createRoomThroughUi(page: Page, name: string): Promise<string> {
  await page.getByRole('link', { name: 'Rooms', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Rooms', exact: true })).toBeVisible();
  await expect(page.getByText('Room names are not encrypted')).toBeVisible();
  await page.getByLabel('Room name').fill(name);
  await page.getByLabel('Security profile').selectOption('STANDARD');
  await page.getByRole('button', { name: 'Create room' }).click();
  await expect(page).toHaveURL(/\/rooms\/room\?id=[0-9a-f-]{36}$/);
  await expect(page.getByRole('heading', { name })).toBeVisible();
  return new URL(page.url()).searchParams.get('id') ?? '';
}

test('create, open after a reload, rename and delete a room, without CSP violations', async ({ page }) => {
  test.setTimeout(180_000);
  const violations = await collectCspViolations(page);
  const user = await signedInWithVault(page);
  const roomId = await createRoomThroughUi(page, 'E2E room');
  await expect(page.getByText('Your role: Owner')).toBeVisible();
  await expect(page.getByTestId(/^member-/)).toHaveCount(1);

  // ADR-011: the static room page loads directly and after a reload, with the ID in the query.
  await page.reload();
  await expect(page.getByRole('heading', { name: 'E2E room' })).toBeVisible();

  await page.getByLabel('New room name').fill('E2E renamed');
  await page.getByRole('button', { name: 'Rename' }).click();
  await expect(page.getByRole('heading', { name: 'E2E renamed' })).toBeVisible();

  // A fresh sign-in has no step-up: deleting must ask for the account password first.
  await login(page, user);
  await page.goto(`/rooms/room?id=${roomId}`);
  await page.getByLabel('I understand that this room will be deleted for every member.').check();
  await page.getByRole('button', { name: 'Delete room' }).click();
  await confirmAccount(page, user);
  await expect(page).toHaveURL(/\/rooms$/);
  await expect(page.getByRole('list', { name: 'Your rooms' })).toHaveCount(0);
  await expect(page.getByText('You are not a member of any room yet.')).toBeVisible();

  await page.goto(`/rooms/room?id=${roomId}`);
  await expect(page.getByText('This room does not exist, or you are not a member of it.')).toBeVisible();
  await page.goto('/rooms/room?id=not-a-room');
  await expect(page.getByText('This room does not exist, or you are not a member of it.')).toBeVisible();
  await page.goto(`/rooms/room?id=${randomUUID()}`);
  await expect(page.getByText('This room does not exist, or you are not a member of it.')).toBeVisible();

  expect(await violations()).toEqual([]);
  expect(await readableStorage(page)).not.toContain(user.password);
});

test('an owner promotes a member, transfers ownership, and the new owner removes the former one', async ({
  page,
  browser,
}) => {
  test.setTimeout(240_000);
  await signedInWithVault(page);
  const roomId = await createRoomThroughUi(page, 'Team room');

  const otherContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await otherContext.newPage();
  const second = { ...newUser(), name: 'Second Member' };
  await useDistinctClientAddress(other);
  await register(other, second);
  await login(other, second);
  const secondId = await other.evaluate(async () => {
    const response = await fetch('/api/auth/session', { credentials: 'same-origin' });
    return ((await response.json()) as { user: { id: string } }).user.id;
  });
  // Invitations arrive in Phase 6; until then a second member joins through a fixture.
  const db = new pg.Client({ connectionString: process.env['DATABASE_URL'] });
  await db.connect();
  try {
    await db.query(
      "INSERT INTO room_members (room_id, user_id, role, first_key_version) VALUES ($1, $2, 'MEMBER', 1)",
      [roomId, secondId],
    );
  } finally {
    await db.end();
  }

  await page.reload();
  const row = page.getByTestId(`member-${secondId}`);
  await expect(row).toContainText('Second Member');
  await expect(row).toContainText('Member');
  await row.getByRole('button', { name: 'Make admin' }).click();
  await expect(row).toContainText('Admin');
  // The vault setup's step-up is still fresh, so the transfer needs no new confirmation.
  await row.getByRole('button', { name: 'Transfer ownership' }).click();
  await expect(page.getByText('Second Member is now the owner. You are an admin of this room.')).toBeVisible();
  await expect(page.getByText('Your role: Admin')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Delete room' })).toHaveCount(0);

  // The new owner sees the room with the OWNER role and removes the former owner.
  await other.goto(`/rooms/room?id=${roomId}`);
  await expect(other.getByText('Your role: Owner')).toBeVisible();
  const former = other.getByTestId(/^member-/).filter({ hasNotText: '(you)' });
  await expect(former).toContainText('Admin');
  await former.getByRole('button', { name: 'Remove' }).click();
  await expect(other.getByText('was removed.', { exact: false })).toBeVisible();
  await expect(other.getByText('Until an owner or admin completes a key rotation').first()).toBeVisible();
  await otherContext.close();

  // The removed former owner no longer reaches the room.
  await page.goto(`/rooms/room?id=${roomId}`);
  await expect(page.getByText('This room does not exist, or you are not a member of it.')).toBeVisible();
});
