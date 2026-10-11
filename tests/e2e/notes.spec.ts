import { expect, firefox, test, webkit, type Browser, type Page, type Request, type Route } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { loadLocalEnv } from '../../scripts/storage/lib.mjs';
import { collectCspViolations, readableStorage } from './helpers';
import {
  acceptThroughUi,
  createRoomThroughUi,
  inviteThroughUi,
  openRoomThroughUi,
  signedInWithVault,
  unlockVault,
  verifiedSafetyCode,
} from './room-helpers';

// Phase 8 in the browser (CM-T042) in Chromium, Firefox and WebKit, against the built static export
// under the production CSP and the real API:
// - a note is encrypted in the browser; only ciphertext and the wrapped NEK reach the API, and
//   neither requests nor browser storage carry its title or body;
// - it is read again after a reload and vault unlock, edited into a new revision, and decrypted by
//   another member; a VIEWER gets no edit or delete controls; deletion asks for confirmation;
// - concurrent edits end in a clear conflict, never in lost text;
// - XSS payloads in a note render as text (EV-08-02);
// - ciphertext substituted by a malicious server is refused, and a rolled-back revision is flagged;
// - locking the vault removes note text at once; notes cross engines.
// Every title and body is synthetic. Evidence goes to test-results/evidence.

loadLocalEnv();
const EVIDENCE = join('test-results', 'evidence');

async function screenshot(page: Page, name: string): Promise<void> {
  mkdirSync(EVIDENCE, { recursive: true });
  await page.screenshot({ path: join(EVIDENCE, name), fullPage: true });
}

const noteRow = (page: Page, title: string) => page.getByTestId('note-row').filter({ hasText: title });

async function createNoteThroughUi(page: Page, title: string, body: string): Promise<void> {
  await page.getByTestId('note-new').click();
  await page.getByTestId('note-title-input').fill(title);
  await page.getByTestId('note-body-input').fill(body);
  await page.getByTestId('note-create').click();
  await expect(page.getByText('The note was encrypted in your browser and saved.')).toBeVisible({ timeout: 60_000 });
}

/** Opens the note's view (if closed) and returns its row. */
async function openNoteThroughUi(page: Page, title: string) {
  const row = noteRow(page, title);
  await expect(row).toBeVisible({ timeout: 60_000 });
  if ((await row.getByTestId('note-view').count()) === 0) await row.getByTestId('note-open').click();
  await expect(row.getByTestId('note-view')).toBeVisible();
  return row;
}

async function editThroughUi(page: Page, title: string, body: string) {
  const row = await openNoteThroughUi(page, title);
  await row.getByTestId('note-edit').click();
  await row.getByTestId('note-body-input').fill(body);
  await expect(row.getByTestId('note-unsaved')).toBeVisible();
  await row.getByTestId('note-save').click();
  return row;
}

/** Every request with its body, for leak checks. */
function captureAll(page: Page): { url: string; body: string }[] {
  const captured: { url: string; body: string }[] = [];
  page.on('request', (request: Request) => {
    captured.push({ url: request.url(), body: request.postData() ?? '' });
  });
  return captured;
}

async function withDatabase<T>(fn: (db: pg.Client) => Promise<T>): Promise<T> {
  const db = new pg.Client({ connectionString: process.env['DATABASE_URL'] });
  await db.connect();
  try {
    return await fn(db);
  } finally {
    await db.end();
  }
}

test('a note is encrypted in the browser, survives a reload, gets a new revision and is read by another member', async ({
  page,
  browser,
  browserName,
}) => {
  test.setTimeout(300_000);
  const violations = await collectCspViolations(page);
  const captured = captureAll(page);
  const owner = await signedInWithVault(page, 'Note Owner');
  const roomName = 'Note room';
  const roomId = await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  await expect(page.getByTestId('notes-empty')).toBeVisible();

  const titleCanary = `canary-title-${randomBytes(5).toString('hex')}`;
  const bodyCanary = `CANARY-BODY-${randomBytes(6).toString('hex')}`;
  const announce = page.waitForRequest((r) => r.url().endsWith(`/api/rooms/${roomId}/notes`) && r.method() === 'POST');
  await createNoteThroughUi(page, titleCanary, `${bodyCanary}\nSecond line of a synthetic note.`);
  // The API receives ciphertext and the wrapped NEK only (DF-12): no title, body or key.
  const body = JSON.parse((await announce).postData() ?? '{}') as Record<string, unknown>;
  expect(Object.keys(body).sort()).toEqual(
    ['ciphertext', 'contentIv', 'expiresAt', 'keyVersion', 'nekIv', 'noteId', 'suite', 'wrappedNek'].sort(),
  );
  const row = await openNoteThroughUi(page, titleCanary);
  await expect(row.getByTestId('note-view-body')).toHaveText(`${bodyCanary}\nSecond line of a synthetic note.`);

  // EV-08-01: what the database holds next to what the member sees.
  const stored = await withDatabase(
    async (db) =>
      (
        await db.query<{ ciphertext: Buffer; revision: number }>(
          'SELECT ciphertext, revision FROM encrypted_notes WHERE room_id = $1',
          [roomId],
        )
      ).rows,
  );
  expect(stored).toHaveLength(1);
  expect(stored[0]?.ciphertext.includes(Buffer.from(bodyCanary))).toBe(false);
  expect(stored[0]?.ciphertext.includes(Buffer.from(titleCanary))).toBe(false);
  if (browserName === 'chromium') {
    mkdirSync(EVIDENCE, { recursive: true });
    writeFileSync(
      join(EVIDENCE, 'EV-08-01-note-row.txt'),
      `revision ${String(stored[0]?.revision)}, ciphertext ${String(stored[0]?.ciphertext.length)} bytes, first 64 bytes:\n${stored[0]?.ciphertext.subarray(0, 64).toString('hex') ?? ''}\n`,
    );
    await screenshot(page, 'EV-08-01-rendered-note.png');
  }

  // A full reload starts without an unlocked vault: nothing decrypted survives it.
  await page.reload();
  await unlockVault(page, owner.passphrase);
  await openRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  await editThroughUi(page, titleCanary, `${bodyCanary} edited`);
  await expect(page.getByText('Saved as revision 2.')).toBeVisible({ timeout: 60_000 });

  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await context.newPage();
  const otherCaptured = captureAll(other);
  const viewer = await signedInWithVault(other, 'Note Viewer');
  await inviteThroughUi(page, viewer, 'Viewer', false);
  await acceptThroughUi(other, roomName);
  await verifiedSafetyCode(other);
  const seen = await openNoteThroughUi(other, titleCanary);
  await expect(seen.getByTestId('note-view-body')).toHaveText(`${bodyCanary} edited`);
  await expect(seen).toContainText('revision 2');
  // A VIEWER is offered neither creation, editing nor deletion (AZ-19, AZ-21, AZ-22; the API decides).
  await expect(other.getByTestId('note-new')).toHaveCount(0);
  await expect(seen.getByTestId('note-edit')).toHaveCount(0);
  await expect(seen.getByTestId('note-delete')).toHaveCount(0);

  // Deletion asks first; then the note is gone for every member.
  const ownerRow = noteRow(page, titleCanary);
  await ownerRow.getByTestId('note-delete').click();
  await expect(ownerRow.getByText('Delete for every member?')).toBeVisible();
  await ownerRow.getByTestId('note-delete-confirm').click();
  await expect(page.getByText('The note was deleted for every member.')).toBeVisible();
  await openRoomThroughUi(other, roomName);
  await expect(other.getByTestId('notes-empty')).toBeVisible({ timeout: 60_000 });

  for (const [who, requests] of [
    [page, captured],
    [other, otherCaptured],
  ] as const) {
    for (const request of requests) {
      for (const canary of [titleCanary, bodyCanary]) {
        expect(request.url.includes(canary)).toBe(false);
        expect(request.body.includes(canary), `request to ${new URL(request.url).pathname}`).toBe(false);
      }
    }
    const kept = await readableStorage(who);
    expect(kept).not.toContain(titleCanary);
    expect(kept).not.toContain(bodyCanary);
  }
  expect(await violations()).toEqual([]);
  await context.close();
});

test('XSS payloads in a note render as text and run nothing (EV-08-02)', async ({ page, browserName }) => {
  test.setTimeout(240_000);
  const violations = await collectCspViolations(page);
  let dialogs = 0;
  page.on('dialog', (dialog) => {
    dialogs += 1;
    void dialog.dismiss();
  });
  await signedInWithVault(page, 'XSS Owner');
  await createRoomThroughUi(page, 'XSS note room');
  await verifiedSafetyCode(page);
  const title = '<img src=x onerror="window.__cmPwned=1;alert(1)">';
  const body = [
    '<script>window.__cmPwned=1;alert(1)</script>',
    '<svg onload="window.__cmPwned=1"></svg><iframe src="javascript:alert(1)"></iframe>',
    '[click](javascript:alert(1)) **bold** <a href="javascript:alert(1)">link</a>',
    '"><style>body{display:none}</style>{{constructor.constructor("alert(1)")()}}',
  ].join('\n');
  await createNoteThroughUi(page, title, body);
  const row = await openNoteThroughUi(page, title);
  await expect(row.getByTestId('note-view-title')).toHaveText(title);
  await expect(row.getByTestId('note-view-body')).toHaveText(body);
  await expect(row.getByTestId('note-view').locator('img, script, svg, iframe, a, style')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __cmPwned?: number }).__cmPwned)).toBeUndefined();
  expect(dialogs).toBe(0);
  expect(page.frames()).toHaveLength(1);
  if (browserName === 'chromium') await screenshot(page, 'EV-08-02-xss-as-text.png');
  expect(await violations()).toEqual([]);
});

test('two members save the same revision: one wins, the other sees a conflict and keeps the text', async ({
  page,
  browser,
}) => {
  test.setTimeout(300_000);
  await signedInWithVault(page, 'Conflict Owner');
  const roomName = 'Conflict room';
  await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  await createNoteThroughUi(page, 'Shared plan', 'base');
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await context.newPage();
  const admin = await signedInWithVault(other, 'Conflict Admin');
  await inviteThroughUi(page, admin, 'Admin', false);
  await acceptThroughUi(other, roomName);
  await verifiedSafetyCode(other);

  const ownerRow = await openNoteThroughUi(page, 'Shared plan');
  await ownerRow.getByTestId('note-edit').click();
  await ownerRow.getByTestId('note-body-input').fill('owner version');
  await editThroughUi(other, 'Shared plan', 'admin version');
  await expect(other.getByText('Saved as revision 2.')).toBeVisible({ timeout: 60_000 });

  await ownerRow.getByTestId('note-save').click();
  await expect(ownerRow.getByTestId('note-conflict')).toBeVisible({ timeout: 60_000 });
  await expect(ownerRow.getByTestId('note-body-input')).toHaveValue('owner version');
  await ownerRow.getByRole('button', { name: 'Load the latest version' }).click();
  await expect(ownerRow.getByTestId('note-view-body')).toHaveText('admin version');
  await expect(ownerRow.getByTestId('note-body-input')).toHaveValue('owner version');
  await ownerRow.getByTestId('note-save').click();
  await expect(page.getByText('Saved as revision 3.')).toBeVisible({ timeout: 60_000 });
  await context.close();
});

test('a malicious server cannot substitute note ciphertext or roll a note back unnoticed', async ({ page }) => {
  test.setTimeout(240_000);
  await signedInWithVault(page, 'Server Attack Owner');
  const roomName = 'Server attack room';
  const roomId = await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  await createNoteThroughUi(page, 'Note A', 'alpha');
  await createNoteThroughUi(page, 'Note B', 'bravo');

  // Capture the list at revision 1, then save revision 2 of note A.
  const listUrl = `**/api/rooms/${roomId}/notes`;
  let revision1 = '';
  await page.route(listUrl, async (route: Route) => {
    const response = await route.fetch();
    revision1 = await response.text();
    await route.fulfill({ response });
  });
  await openRoomThroughUi(page, roomName);
  await expect(noteRow(page, 'Note A')).toBeVisible({ timeout: 60_000 });
  await page.unroute(listUrl);
  await editThroughUi(page, 'Note A', 'alpha two');
  await expect(page.getByText('Saved as revision 2.')).toBeVisible({ timeout: 60_000 });

  // 1. Substitution: note A served with note B's ciphertext and wrapped NEK (revision 2 claimed).
  const original = JSON.parse(revision1) as { notes: Record<string, unknown>[] };
  // Newest first: note B, then note A.
  const [b, a] = original.notes;
  await page.route(listUrl, (route: Route) =>
    route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        ...original,
        notes: [
          {
            ...a,
            wrappedNek: b?.['wrappedNek'],
            nekIv: b?.['nekIv'],
            ciphertext: b?.['ciphertext'],
            contentIv: b?.['contentIv'],
            revision: 3,
          },
        ],
      }),
    }),
  );
  await openRoomThroughUi(page, roomName);
  await expect(page.getByTestId('note-title')).toHaveText(['Damaged note (integrity check failed)'], {
    timeout: 60_000,
  });
  await page.getByTestId('note-open').click();
  await expect(page.getByText('This note failed its integrity check')).toBeVisible();
  await expect(page.getByTestId('note-view-body')).toHaveCount(0);
  await page.unroute(listUrl);

  // 2. Rollback: the server serves revision 1 again after this tab saw revision 2 (T-32).
  await page.route(listUrl, (route: Route) => route.fulfill({ contentType: 'application/json', body: revision1 }));
  await openRoomThroughUi(page, roomName);
  await expect(noteRow(page, 'Note A').getByText('returned an older version of this note')).toBeVisible({
    timeout: 60_000,
  });
  await page.unroute(listUrl);
});

test('locking the vault removes note text at once; unlocking restores it', async ({ page }) => {
  test.setTimeout(240_000);
  const user = await signedInWithVault(page, 'Note Lock Owner');
  const roomName = 'Note lock room';
  await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  await createNoteThroughUi(page, 'Locked title', 'locked body');
  await expect(page.getByTestId('note-view-body')).toHaveText('locked body');
  await page.getByRole('button', { name: 'Lock now' }).click();
  await expect(page.getByTestId('note-title').filter({ hasText: 'Locked title' })).toHaveCount(0);
  await expect(page.getByTestId('note-title').first()).toHaveText('Encrypted note');
  await expect(page.getByTestId('note-view-body')).toHaveCount(0);
  await expect(page.getByTestId('notes-locked')).toBeVisible();
  await unlockVault(page, user.passphrase);
  await openRoomThroughUi(page, roomName);
  await expect(noteRow(page, 'Locked title')).toBeVisible({ timeout: 60_000 });
});

test("a non-member cannot open another room's notes", async ({ page, browser }) => {
  test.setTimeout(240_000);
  await signedInWithVault(page, 'Private Owner');
  const roomId = await createRoomThroughUi(page, 'Private note room');
  await verifiedSafetyCode(page);
  await createNoteThroughUi(page, 'Private title', 'private body');
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const outsider = await context.newPage();
  await signedInWithVault(outsider, 'Outsider');
  const answer = await outsider.evaluate(async (id: string) => {
    const response = await fetch(`/api/rooms/${id}/notes`, { credentials: 'same-origin' });
    return { status: response.status, text: await response.text() };
  }, roomId);
  expect(answer.status).toBe(404);
  expect(answer.text).not.toContain('Private');
  await outsider.goto(`/rooms/room?id=${roomId}`);
  await expect(outsider.getByText('This room does not exist, or you are not a member of it.')).toBeVisible({
    timeout: 60_000,
  });
  await expect(outsider.getByTestId('notes-card')).toHaveCount(0);
  await context.close();
});

test('notes encrypted in one engine decrypt in the others', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'Runs once from Chromium and drives Firefox and WebKit itself');
  test.setTimeout(600_000);
  await signedInWithVault(page, 'Chromium Note Owner');
  const roomName = 'Cross-engine notes';
  await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  await createNoteThroughUi(page, 'From Chromium', 'Written in Chromium ✓ 日本語');
  for (const engine of [firefox, webkit]) {
    const other: Browser = await engine.launch();
    try {
      const context = await other.newContext({ ignoreHTTPSErrors: true, baseURL: new URL(page.url()).origin });
      const member = await context.newPage();
      const account = await signedInWithVault(member, `${engine.name()} Note Member`);
      await openRoomThroughUi(page, roomName);
      await inviteThroughUi(page, account, 'Member', false);
      await acceptThroughUi(member, roomName);
      await verifiedSafetyCode(member);
      const row = await openNoteThroughUi(member, 'From Chromium');
      await expect(row.getByTestId('note-view-body')).toHaveText('Written in Chromium ✓ 日本語');
      const title = `From ${engine.name()}`;
      await createNoteThroughUi(member, title, `Written in ${engine.name()}`);
      await openRoomThroughUi(page, roomName);
      const back = await openNoteThroughUi(page, title);
      await expect(back.getByTestId('note-view-body')).toHaveText(`Written in ${engine.name()}`);
    } finally {
      await other.close();
    }
  }
});
