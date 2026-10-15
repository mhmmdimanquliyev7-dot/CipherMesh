import { expect, test, type BrowserContext, type Page, type Request } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { collectCspViolations, login, newUser, newVaultPassphrase, register, type TestUser } from '../e2e/helpers';
import {
  acceptThroughUi,
  confirmAccount,
  createRoomThroughUi,
  inviteThroughUi,
  openRoomThroughUi,
  PASSPHRASE_FIELD,
  verifiedSafetyCode,
} from '../e2e/room-helpers';
import { authSlots } from './pace';

// Deployment collaboration test (local Docker demonstration and CI, ADR-014): two synthetic people,
// each in their own browser context, through the production edge only. Invitation and acceptance
// with matching Safety Codes; a burn-after-reading secret revealed once and refused afterwards;
// removal of the member, which locks the room; key rotation to version 2 in the owner's browser;
// the removed member loses the room; new content under the new key. No database access, no test
// headers: everything goes through Nginx, the API and storage as a user would.

interface Person extends TestUser {
  readonly passphrase: string;
}

async function personWithVault(page: Page, name: string): Promise<Person> {
  const user = { ...newUser(), name };
  await authSlots(1);
  await register(page, user);
  await authSlots(1);
  await login(page, user);
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await authSlots(1);
  await confirmAccount(page, user);
  const passphrase = newVaultPassphrase();
  await page.getByLabel(PASSPHRASE_FIELD).fill(passphrase);
  await page.getByLabel('Repeat the Vault Passphrase').fill(passphrase);
  await page.getByLabel('I understand that CipherMesh cannot recover a lost Vault Passphrase.').check();
  await page.getByRole('button', { name: 'Create vault' }).click();
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 120_000 });
  return { ...user, passphrase };
}

function bodies(page: Page): string[] {
  const captured: string[] = [];
  page.on('request', (request: Request) => {
    captured.push(`${request.url()} ${request.postData() ?? ''}`);
  });
  return captured;
}

async function confirmIfAsked(page: Page, password: string): Promise<void> {
  const confirm = page.getByRole('heading', { name: 'Confirm your account' });
  if (await confirm.isVisible().catch(() => false)) {
    await page.getByLabel('Account password').first().fill(password);
    await page.getByRole('button', { name: 'Confirm account' }).click();
  }
}

test('deployment: invitation, burn secret, removal and key rotation between two people', async ({
  page,
  browser,
  browserName,
}) => {
  test.setTimeout(420_000);
  const ownerViolations = await collectCspViolations(page);
  const ownerRequests = bodies(page);
  const roomName = `Collaboration ${browserName} ${randomBytes(3).toString('hex')}`;

  // Owner: vault and room (key version 1 made in this browser).
  const owner = await personWithVault(page, `Demo Owner ${browserName}`);
  await createRoomThroughUi(page, roomName);
  const codeV1 = await verifiedSafetyCode(page);

  // Member in a separate context: own vault, invited, accepts, verifies the same room key.
  const context: BrowserContext = await browser.newContext({
    ignoreHTTPSErrors: test.info().project.use.ignoreHTTPSErrors ?? false,
  });
  const other = await context.newPage();
  const memberViolations = await collectCspViolations(other);
  const memberRequests = bodies(other);
  const member = await personWithVault(other, `Demo Member ${browserName}`);
  await openRoomThroughUi(page, roomName);
  await inviteThroughUi(page, member, 'Member', false);
  await acceptThroughUi(other, roomName);
  expect(await verifiedSafetyCode(other), 'both browsers hold the same room key').toBe(codeV1);

  // Burn-after-reading secret, encrypted in the owner's browser for the member only.
  const canary = `deployment-canary-secret-${randomBytes(8).toString('hex')}`;
  await openRoomThroughUi(page, roomName);
  const announce = page.waitForRequest((r) => /\/api\/rooms\/[^/]+\/secrets$/.test(r.url()) && r.method() === 'POST');
  await page.getByTestId('secret-new').click();
  await page.getByTestId('secret-recipient').selectOption({ label: member.name });
  await page.getByTestId('secret-text-input').fill(canary);
  await page.getByTestId('secret-send').click();
  await expect(page.getByText(`was encrypted in your browser for ${member.name} and sent`)).toBeVisible({
    timeout: 60_000,
  });
  const sent = JSON.parse((await announce).postData() ?? '{}') as { secretId?: string };
  const roomId = new URL(page.url()).searchParams.get('id') ?? '';

  await openRoomThroughUi(other, roomName);
  const row = other.getByTestId('secret-row').first();
  await expect(row).toContainText('Waiting to be revealed', { timeout: 60_000 });
  await row.getByTestId('secret-reveal').click();
  await expect(row.getByTestId('secret-reveal-warning')).toContainText('cannot be recovered');
  await row.getByTestId('secret-reveal-confirm').click();
  await expect(row.getByTestId('secret-view-text')).toHaveText(canary, { timeout: 60_000 });
  await expect(row.getByTestId('secret-status')).toContainText('Revealed and destroyed');
  const again = await other.evaluate(
    async ([room, id]) => {
      const response = await fetch(`/api/rooms/${room}/secrets/${id}/reveal`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-ciphermesh-request': '1' },
        body: '{}',
      });
      return { status: response.status, text: await response.text() };
    },
    [roomId, sent.secretId ?? ''] as const,
  );
  expect(again.status, 'a burned secret cannot be revealed twice').toBe(409);
  expect(again.text).toContain('SECRET_UNAVAILABLE');

  // Removal locks the room; the owner rotates the key in the browser.
  await openRoomThroughUi(page, roomName);
  const memberRow = page.getByRole('list', { name: 'Members' }).getByRole('listitem').filter({ hasText: member.name });
  await authSlots(1);
  await memberRow.getByRole('button', { name: 'Remove' }).click();
  await confirmIfAsked(page, owner.password);
  await expect(page.getByText(`${member.name} was removed.`)).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId('rekey-state')).toContainText('Locked until the room key is rotated');
  await page.getByRole('button', { name: /Rotate the room key/ }).click();
  const review = page.getByTestId('rekey-review');
  await expect(review).toBeVisible({ timeout: 60_000 });
  expect((await review.getByTestId('rekey-recipient-name').allInnerTexts()).map((t) => t.trim())).toEqual([owner.name]);
  await page.getByRole('button', { name: 'Create and share the new key' }).click();
  await expect(page.getByTestId('rekey-done')).toContainText('Key version 2 is now current', { timeout: 90_000 });
  await expect(page.getByTestId('room-key-status')).toContainText('Room key version 2 verified', { timeout: 60_000 });
  const codeV2 = await verifiedSafetyCode(page);
  expect(codeV2).not.toBe(codeV1);

  // The removed member no longer sees the room.
  await other.goto(`/rooms/room?id=${roomId}`);
  await expect(other.getByText('This room does not exist, or you are not a member of it.')).toBeVisible();

  // New content is written under version 2.
  const noteCanary = `deployment-canary-note-v2-${randomBytes(8).toString('hex')}`;
  await page.getByTestId('note-new').click();
  await page.getByTestId('note-title-input').fill('After rotation');
  await page.getByTestId('note-body-input').fill(noteCanary);
  await page.getByTestId('note-create').click();
  await expect(page.getByText('The note was encrypted in your browser and saved.')).toBeVisible({ timeout: 60_000 });

  for (const value of [canary, noteCanary, codeV1, codeV2, owner.passphrase, member.passphrase]) {
    for (const request of [...ownerRequests, ...memberRequests]) {
      expect(request.includes(value), 'a secret value left a browser').toBe(false);
    }
  }
  expect(await ownerViolations()).toEqual([]);
  expect(await memberViolations()).toEqual([]);
  await context.close();
});
