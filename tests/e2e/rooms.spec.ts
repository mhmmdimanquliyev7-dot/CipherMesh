import { expect, test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { collectCspViolations, login, readableStorage } from './helpers';
import {
  acceptThroughUi,
  confirmAccount,
  createRoomThroughUi,
  inviteThroughUi,
  openRoomThroughUi,
  signedInWithVault,
  verifiedSafetyCode,
} from './room-helpers';

// Rooms in the browser (Phase 5, CM-T030, CM-T031; Phase 6) in Chromium, Firefox and WebKit,
// against the built static export under the production CSP and the real API:
// - the room page works as a static page with the room ID in the query string, including a reload
//   and a direct visit (ADR-011);
// - the room-name warning is shown, deletion and ownership transfer ask for a step-up;
// - the controls follow the user's role, and the API's answers are what the page shows.
// Room creation needs an unlocked vault: the room key is created in the browser (CM-T033). Since
// Phase 6 the second member joins through a real invitation with an envelope, and granting ADMIN
// or ownership is signed with the owner's identity key (ADR-015 section 4).

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

test('an invited member is promoted, receives ownership, and the new owner removes the former one', async ({
  page,
  browser,
}) => {
  test.setTimeout(300_000);
  await signedInWithVault(page, 'First Owner');
  const roomId = await createRoomThroughUi(page, 'Team room');
  await verifiedSafetyCode(page);

  const otherContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await otherContext.newPage();
  const second = await signedInWithVault(other, 'Second Member');
  const secondId = await other.evaluate(async () => {
    const response = await fetch('/api/auth/session', { credentials: 'same-origin' });
    return ((await response.json()) as { user: { id: string } }).user.id;
  });
  await openRoomThroughUi(page, 'Team room');
  await inviteThroughUi(page, second, 'Member', false);
  await acceptThroughUi(other, 'Team room');
  await verifiedSafetyCode(other);

  // Reopened inside the app: a page reload would start without the unlocked vault (memory only).
  await openRoomThroughUi(page, 'Team room');
  const row = page.getByTestId(`member-${secondId}`);
  await expect(row).toContainText('Second Member');
  await expect(row).toContainText('Member');
  // Granting ADMIN is signed in this browser with the owner's identity key.
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
  await expect(other.getByText('Until an owner or admin completes the key rotation').first()).toBeVisible();
  await otherContext.close();

  // The removed former owner no longer reaches the room.
  await page.goto(`/rooms/room?id=${roomId}`);
  await expect(page.getByText('This room does not exist, or you are not a member of it.')).toBeVisible();
});
