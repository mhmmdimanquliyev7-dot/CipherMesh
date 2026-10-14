import { expect, test, type Page, type Request } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { collectCspViolations, login, newUser, newVaultPassphrase, register } from '../e2e/helpers';
import { confirmAccount, createRoomThroughUi, PASSPHRASE_FIELD } from '../e2e/room-helpers';

// Deployment smoke test (ADR-014, Scenario A): through the deployment's public edge only, one
// synthetic user registers, creates a vault, a room, an encrypted note and an encrypted file, and
// reads both back. Every request leaving the browser is checked: the plaintext note and file never
// leave it, storage receives no cookie, and the page runs under its CSP without violations.
// Synthetic data only; the account stays on the deployment as a demonstration artifact.
//
// With CM_SMOKE_RECORD_ACCOUNTS=<directory> the synthetic account, its Vault Passphrase and the
// expected note and file are written there (rehearsal and CI only, never against the live cloud),
// so restore-verify.spec.ts can sign in again after a backup restore and decrypt both.

const OUT = join('test-results', 'deployment');

interface Captured {
  readonly url: string;
  readonly body: Buffer;
  readonly headers: Promise<Record<string, string>>;
}

function captureAll(page: Page): Captured[] {
  const captured: Captured[] = [];
  page.on('request', (request: Request) => {
    captured.push({
      url: request.url(),
      body: request.postDataBuffer() ?? Buffer.alloc(0),
      headers: request.allHeaders().catch(() => ({})),
    });
  });
  return captured;
}

test('deployment: vault, room, encrypted note and file round trip; no plaintext leaves the browser', async ({
  page,
  browserName,
}) => {
  test.setTimeout(300_000);
  const violations = await collectCspViolations(page);
  const requests = captureAll(page);
  const noteSecret = `deployment-canary-note-${randomBytes(8).toString('hex')}`;
  const fileSecret = `deployment-canary-file-${randomBytes(8).toString('hex')}`;
  const fileContent = Buffer.concat([Buffer.from(`${fileSecret}\n`), randomBytes(48 * 1024)]);
  mkdirSync(OUT, { recursive: true });
  const upload = join(OUT, `${randomBytes(4).toString('hex')}-synthetic.bin`);
  writeFileSync(upload, fileContent);

  // Account and vault through the real UI.
  const user = { ...newUser(), name: `Cloud smoke ${browserName}` };
  await register(page, user);
  await login(page, user);
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await confirmAccount(page, user);
  const passphrase = newVaultPassphrase();
  await page.getByLabel(PASSPHRASE_FIELD).fill(passphrase);
  await page.getByLabel('Repeat the Vault Passphrase').fill(passphrase);
  await page.getByLabel('I understand that CipherMesh cannot recover a lost Vault Passphrase.').check();
  await page.getByRole('button', { name: 'Create vault' }).click();
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 120_000 });

  // A room: key version 1 is generated in this browser and wrapped to the owner's public key.
  const roomName = `Cloud smoke room ${browserName} ${randomBytes(3).toString('hex')}`;
  await createRoomThroughUi(page, roomName);

  // An encrypted note.
  await page.getByTestId('note-new').click();
  await page.getByTestId('note-title-input').fill('Cloud smoke note');
  await page.getByTestId('note-body-input').fill(noteSecret);
  await page.getByTestId('note-create').click();
  await expect(page.getByText('The note was encrypted in your browser and saved.')).toBeVisible({ timeout: 60_000 });
  const note = page.getByTestId('note-row').filter({ hasText: 'Cloud smoke note' });
  if ((await note.getByTestId('note-view').count()) === 0) await note.getByTestId('note-open').click();
  await expect(note.getByTestId('note-view')).toContainText(noteSecret);

  // An encrypted file: uploaded to storage with a presigned URL, downloaded and decrypted again.
  await page.getByTestId('file-input').setInputFiles(upload);
  await page.getByTestId('file-upload').click();
  await expect(page.getByText('The file was encrypted in your browser and uploaded.')).toBeVisible({ timeout: 90_000 });
  const row = page.getByTestId('file-row').first();
  await expect(row).toBeVisible({ timeout: 60_000 });
  const pending = page.waitForEvent('download');
  await row.getByRole('button', { name: /^Download/ }).click();
  const downloaded = readFileSync(await (await pending).path());
  expect(downloaded.equals(fileContent), 'downloaded file equals the original').toBe(true);
  const record = process.env['CM_SMOKE_RECORD_ACCOUNTS'];
  if (record !== undefined && record !== '') {
    mkdirSync(record, { recursive: true });
    writeFileSync(
      join(record, `${browserName}.json`),
      JSON.stringify({ ...user, passphrase, roomName, noteSecret, file: fileContent.toString('base64') }),
      { mode: 0o600 },
    );
  }

  // Encryption receipts are shown for the stored items.
  await expect(page.getByTestId('file-receipt').first()).toBeVisible();
  await expect(page.getByTestId('note-receipt').first()).toBeVisible();

  // Nothing secret left the browser: neither canary appears in any request body, to the API or to
  // storage, and the storage host never received a cookie or a Referer (SF-07-01).
  const app = new URL(page.url()).origin;
  let storageRequests = 0;
  for (const request of requests) {
    expect(request.body.includes(noteSecret), `note plaintext in ${new URL(request.url).pathname}`).toBe(false);
    expect(request.body.includes(fileSecret), `file plaintext in ${new URL(request.url).pathname}`).toBe(false);
    if (new URL(request.url).origin !== app && !request.url.startsWith('data:') && !request.url.startsWith('blob:')) {
      storageRequests += 1;
      const headers = await request.headers;
      expect(headers['cookie'], 'cookie sent to storage').toBeUndefined();
      expect(headers['referer'], 'Referer sent to storage').toBeUndefined();
    }
  }
  expect(storageRequests, 'the file went to the separate storage origin').toBeGreaterThanOrEqual(2);
  expect(await violations()).toEqual([]);

  // Evidence screenshot last: Playwright hides the caret by injecting a style element, which the
  // page's CSP blocks (and WebKit reports) unless the caret is left as it is.
  await page.screenshot({ path: join(OUT, `cloud-smoke-room-${browserName}.png`), fullPage: true, caret: 'initial' });
});
