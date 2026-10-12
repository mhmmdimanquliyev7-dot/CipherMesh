import { expect, firefox, test, webkit, type Browser, type Page, type Request, type Route } from '@playwright/test';
import { randomBytes, randomUUID } from 'node:crypto';
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

// Phase 9 in the browser (CM-T043, CM-T044) in Chromium, Firefox and WebKit, against the built
// static export under the production CSP and the real API:
// - a secret is encrypted in the sender's browser for one member; only ciphertext and the wrapped
//   SEK reach the API, and neither requests nor browser storage carry its text;
// - loading the page never reveals it; the recipient reveals it with an explicit, warned click,
//   the server destroys it in that transaction, and it cannot be revealed again, not after a
//   reload either;
// - two tabs revealing at once produce one winner; the loser sees a clear message;
// - expired and revoked secrets cannot be revealed; another room's member gets 404;
// - locking the vault removes revealed text and the reveal control;
// - ciphertext changed by a malicious server is refused and shows no text; XSS renders as text;
// - secrets cross engines.
// Every text is synthetic. Evidence goes to test-results/evidence.

loadLocalEnv();
const EVIDENCE = join('test-results', 'evidence');

async function screenshot(page: Page, name: string): Promise<void> {
  mkdirSync(EVIDENCE, { recursive: true });
  await page.screenshot({ path: join(EVIDENCE, name), fullPage: true });
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

const secretRows = (roomId: string) =>
  withDatabase(
    async (db) =>
      (
        await db.query<{
          id: string;
          status: string;
          payload_ciphertext: Buffer | null;
          wrapped_sek: Buffer | null;
        }>('SELECT id, status::text AS status, payload_ciphertext, wrapped_sek FROM secrets WHERE room_id = $1', [
          roomId,
        ])
      ).rows,
  );

/** A room with `owner` (this page) and one member (a new context); both have verified the room key. */
async function roomWithMember(page: Page, browser: Browser, roomName: string, memberName: string) {
  const owner = await signedInWithVault(page, `${memberName} Sender`);
  const roomId = await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await context.newPage();
  const member = await signedInWithVault(other, memberName);
  await inviteThroughUi(page, member, 'Member', false);
  await acceptThroughUi(other, roomName);
  await verifiedSafetyCode(other);
  await openRoomThroughUi(page, roomName);
  return { owner, member, roomId, other, context };
}

async function sendThroughUi(page: Page, recipientName: string, text: string, burn = true): Promise<void> {
  await page.getByTestId('secret-new').click();
  await page.getByTestId('secret-recipient').selectOption({ label: recipientName });
  await page.getByTestId('secret-text-input').fill(text);
  if (!burn) await page.getByTestId('secret-burn').uncheck();
  await page.getByTestId('secret-send').click();
  await expect(page.getByText(`was encrypted in your browser for ${recipientName} and sent`)).toBeVisible({
    timeout: 60_000,
  });
}

async function revealThroughUi(page: Page) {
  const row = page.getByTestId('secret-row').first();
  await row.getByTestId('secret-reveal').click();
  await expect(row.getByTestId('secret-reveal-warning')).toContainText('cannot be recovered');
  await row.getByTestId('secret-reveal-confirm').click();
  return row;
}

/** A reveal request from page script, as an attacker or a second tab would send it. */
function revealFromPage(page: Page, roomId: string, secretId: string): Promise<{ status: number; text: string }> {
  return page.evaluate(
    async ([room, id]) => {
      const response = await fetch(`/api/rooms/${room}/secrets/${id}/reveal`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-ciphermesh-request': '1' },
        body: '{}',
      });
      return { status: response.status, text: await response.text() };
    },
    [roomId, secretId] as const,
  );
}

test('a secret is encrypted for one member, revealed once on an explicit click, and gone afterwards', async ({
  page,
  browser,
  browserName,
}) => {
  test.setTimeout(300_000);
  const violations = await collectCspViolations(page);
  const captured = captureAll(page);
  const { member, roomId, other, context } = await roomWithMember(page, browser, 'Secret room', 'Secret Member');
  const otherViolations = await collectCspViolations(other);
  const otherCaptured = captureAll(other);
  await expect(page.getByTestId('secrets-empty')).toBeVisible();

  const canary = `CANARY-SECRET-${randomBytes(6).toString('hex')}`;
  const text = `${canary}\nline two of a synthetic secret`;
  const announce = page.waitForRequest(
    (r) => r.url().endsWith(`/api/rooms/${roomId}/secrets`) && r.method() === 'POST',
  );
  await sendThroughUi(page, member.name, text);
  // The API receives identifiers, the wrapped SEK and the payload ciphertext only (DF-09).
  const body = JSON.parse((await announce).postData() ?? '{}') as Record<string, unknown>;
  expect(Object.keys(body).sort()).toEqual(
    [
      'burnAfterReading',
      'ciphertext',
      'expiresAt',
      'payloadIv',
      'recipientKeyId',
      'recipientUserId',
      'secretId',
      'suite',
      'wrappedSek',
    ].sort(),
  );
  const [stored] = await secretRows(roomId);
  expect(stored?.status).toBe('ACTIVE');
  expect(stored?.payload_ciphertext?.includes(Buffer.from(canary))).toBe(false);
  if (browserName === 'chromium') {
    mkdirSync(EVIDENCE, { recursive: true });
    writeFileSync(
      join(EVIDENCE, 'EV-09-04-secret-row.txt'),
      `status ${String(stored?.status)}, wrapped SEK ${String(stored?.wrapped_sek?.length)} bytes, payload ${String(stored?.payload_ciphertext?.length)} bytes, first 32 payload bytes:\n${stored?.payload_ciphertext?.subarray(0, 32).toString('hex') ?? ''}\n`,
    );
  }

  // Loading the room never reveals anything: the secret is still ACTIVE with its material.
  await openRoomThroughUi(other, 'Secret room');
  const row = other.getByTestId('secret-row').first();
  await expect(row).toContainText('Waiting to be revealed', { timeout: 60_000 });
  await expect(other.getByTestId('secret-view')).toHaveCount(0);
  expect((await secretRows(roomId))[0]?.status).toBe('ACTIVE');
  // The sender cannot reveal what was sent to someone else.
  await expect(page.getByTestId('secret-reveal')).toHaveCount(0);

  await row.getByTestId('secret-reveal').click();
  await expect(row.getByTestId('secret-reveal-warning')).toContainText('cannot be recovered');
  if (browserName === 'chromium') await screenshot(other, 'EV-09-03-reveal-warning.png');
  await row.getByTestId('secret-reveal-confirm').click();
  await expect(row.getByTestId('secret-view-text')).toHaveText(text, { timeout: 60_000 });
  await expect(row.getByTestId('secret-status')).toContainText('Revealed and destroyed');
  if (browserName === 'chromium') await screenshot(other, 'EV-09-01-revealed-once.png');
  const [burned] = await secretRows(roomId);
  expect(burned).toMatchObject({ status: 'REVEALED', payload_ciphertext: null, wrapped_sek: null });
  await expect(row.getByTestId('secret-reveal')).toHaveCount(0);
  const again = await revealFromPage(other, roomId, burned?.id ?? randomUUID());
  expect(again.status).toBe(409);
  expect(again.text).toContain('SECRET_UNAVAILABLE');

  // Hiding removes the text; a reload starts without a vault and the secret cannot come back.
  await row.getByTestId('secret-hide').click();
  await expect(other.getByTestId('secret-view')).toHaveCount(0);
  await other.reload();
  await unlockVault(other, member.passphrase);
  await openRoomThroughUi(other, 'Secret room');
  await expect(other.getByTestId('secret-row').first()).toContainText('Revealed and destroyed', { timeout: 60_000 });
  await expect(other.getByTestId('secret-reveal')).toHaveCount(0);
  await expect(other.getByText(canary)).toHaveCount(0);

  for (const [who, requests] of [
    [page, captured],
    [other, otherCaptured],
  ] as const) {
    for (const request of requests) {
      expect(request.url.includes(canary)).toBe(false);
      expect(request.body.includes(canary), `request to ${new URL(request.url).pathname}`).toBe(false);
    }
    expect(await readableStorage(who)).not.toContain(canary);
  }
  expect(await violations()).toEqual([]);
  expect(await otherViolations()).toEqual([]);
  await context.close();
});

test('two tabs reveal at once: exactly one gets the secret, the other a clear refusal', async ({ page, browser }) => {
  test.setTimeout(300_000);
  const { member, roomId, other, context } = await roomWithMember(page, browser, 'Race room', 'Race Member');
  await sendThroughUi(page, member.name, 'race me');
  const [secret] = await secretRows(roomId);
  // Two simultaneous requests from the recipient's session.
  const results = await Promise.all([
    revealFromPage(other, roomId, secret?.id ?? ''),
    revealFromPage(other, roomId, secret?.id ?? ''),
  ]);
  expect(results.map((r) => r.status).sort()).toEqual([200, 409]);

  // A second tab that still shows the next secret as waiting gets an understandable message.
  await sendThroughUi(page, member.name, 'second race');
  const tab = await context.newPage();
  await tab.goto(other.url());
  await unlockVault(tab, member.passphrase);
  await openRoomThroughUi(tab, 'Race room');
  await expect(tab.getByTestId('secret-row').first()).toContainText('Waiting to be revealed', { timeout: 60_000 });
  await openRoomThroughUi(other, 'Race room');
  const first = await revealThroughUi(other);
  await expect(first.getByTestId('secret-view-text')).toHaveText('second race', { timeout: 60_000 });
  await revealThroughUi(tab);
  await expect(tab.getByTestId('secret-message')).toContainText('can no longer be revealed', { timeout: 60_000 });
  await expect(tab.getByTestId('secret-view')).toHaveCount(0);
  await expect(tab.getByTestId('secret-row').first()).toContainText('Revealed and destroyed');
  await context.close();
});

test('expired and revoked secrets cannot be revealed; another room’s member gets 404', async ({ page, browser }) => {
  test.setTimeout(300_000);
  const { member, roomId, other, context } = await roomWithMember(page, browser, 'Ended room', 'Ended Member');
  await sendThroughUi(page, member.name, 'to be revoked');
  // Revocation by the sender, with confirmation.
  const sent = page.getByTestId('secret-row').first();
  await sent.getByTestId('secret-revoke').click();
  await sent.getByTestId('secret-revoke-confirm').click();
  await expect(page.getByText('The secret was revoked.')).toBeVisible({ timeout: 60_000 });
  const [revoked] = await secretRows(roomId);
  expect(revoked).toMatchObject({ status: 'REVOKED', payload_ciphertext: null, wrapped_sek: null });

  // An expired secret (written as the database would hold it after its expiry, before the worker).
  const expiredId = randomUUID();
  await withDatabase(async (db) => {
    const ids = await db.query<{ sender: string; recipient: string; key: string }>(
      `SELECT r.created_by_id::text AS sender, u.id::text AS recipient, k.id::text AS key
         FROM rooms r, users u JOIN user_key_pairs k ON k.user_id = u.id AND k.status = 'ACTIVE'
        WHERE r.id = $1 AND u.email = $2`,
      [roomId, member.email.toLowerCase()],
    );
    const row = ids.rows[0];
    await db.query(
      `INSERT INTO secrets (id, room_id, sender_id, recipient_user_id, recipient_key_id, burn_after_reading,
         algorithm_suite, wrapped_sek, wrap_algorithm, payload_ciphertext, payload_iv, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, true, 'CM1', $6, 'RSA-OAEP-3072-SHA256', $7, $8, now() - interval '1 minute',
         now() - interval '1 hour')`,
      [expiredId, roomId, row?.sender, row?.recipient, row?.key, randomBytes(384), randomBytes(48), randomBytes(12)],
    );
  });
  await openRoomThroughUi(other, 'Ended room');
  await expect(other.getByTestId('secret-status')).toHaveText(
    // Newest first: the revoked secret was created now, the expired one an hour ago.
    [/^Revoked/, /^Expired/],
    { timeout: 60_000 },
  );
  await expect(other.getByTestId('secret-reveal')).toHaveCount(0);
  for (const id of [expiredId, revoked?.id ?? '']) {
    const answer = await revealFromPage(other, roomId, id);
    expect(answer.status).toBe(409);
  }

  // An outsider with an account and a vault: the room does not exist for them.
  const outsiderContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const outsider = await outsiderContext.newPage();
  await signedInWithVault(outsider, 'Secret Outsider');
  await page.getByTestId('secret-new').click();
  await page.getByTestId('secret-recipient').selectOption({ label: member.name });
  await page.getByTestId('secret-text-input').fill('not for outsiders');
  await page.getByTestId('secret-send').click();
  await expect(page.getByText('was encrypted in your browser')).toBeVisible({ timeout: 60_000 });
  const active = (await secretRows(roomId)).find((s) => s.status === 'ACTIVE');
  const answer = await revealFromPage(outsider, roomId, active?.id ?? randomUUID());
  expect(answer.status).toBe(404);
  expect((await secretRows(roomId)).find((s) => s.id === active?.id)?.status).toBe('ACTIVE');
  await outsiderContext.close();
  await context.close();
});

test('locking the vault removes revealed text and the reveal control', async ({ page, browser }) => {
  test.setTimeout(300_000);
  const { member, other, context } = await roomWithMember(page, browser, 'Lock room', 'Lock Member');
  await sendThroughUi(page, member.name, 'kept until locked', false);
  await openRoomThroughUi(other, 'Lock room');
  const row = other.getByTestId('secret-row').first();
  await row.getByTestId('secret-reveal').click();
  await expect(row.getByTestId('secret-view-text')).toHaveText('kept until locked', { timeout: 60_000 });
  await other.getByRole('button', { name: 'Lock now' }).click();
  await expect(other.getByTestId('secret-view')).toHaveCount(0);
  await expect(other.getByTestId('secret-reveal')).toHaveCount(0);
  await expect(other.getByTestId('secrets-locked')).toBeVisible();
  await expect(other.getByText('kept until locked')).toHaveCount(0);
  await unlockVault(other, member.passphrase);
  await openRoomThroughUi(other, 'Lock room');
  // Not burned: it can be revealed again until it expires or is revoked.
  await other.getByTestId('secret-row').first().getByTestId('secret-reveal').click();
  await expect(other.getByTestId('secret-view-text')).toHaveText('kept until locked', { timeout: 60_000 });
  await context.close();
});

test('ciphertext changed by a malicious server is refused, and XSS in a secret renders as text', async ({
  page,
  browser,
  browserName,
}) => {
  test.setTimeout(300_000);
  const violations = await collectCspViolations(page);
  const { member, roomId, other, context } = await roomWithMember(page, browser, 'Tamper room', 'Tamper Member');
  let dialogs = 0;
  other.on('dialog', (dialog) => {
    dialogs += 1;
    void dialog.dismiss();
  });
  const payload = '<img src=x onerror="window.__cmPwned=1;alert(1)"><script>window.__cmPwned=1</script>';
  await sendThroughUi(page, member.name, payload);
  await sendThroughUi(page, member.name, 'tampered on the way');
  await openRoomThroughUi(other, 'Tamper room');
  const [newest, older] = [other.getByTestId('secret-row').nth(0), other.getByTestId('secret-row').nth(1)];

  // 1. The server flips one byte of the ciphertext in the reveal response.
  const revealUrl = `**/api/rooms/${roomId}/secrets/*/reveal`;
  await other.route(revealUrl, async (route: Route) => {
    const response = await route.fetch();
    const json = (await response.json()) as { ciphertext: { ciphertext: string } };
    const bytes = Buffer.from(json.ciphertext.ciphertext, 'base64url');
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    json.ciphertext.ciphertext = bytes.toString('base64url');
    await route.fulfill({ response, json });
  });
  await newest.getByTestId('secret-reveal').click();
  await newest.getByTestId('secret-reveal-confirm').click();
  await expect(other.getByTestId('secret-message')).toContainText('failed its integrity check', { timeout: 60_000 });
  await expect(newest.getByTestId('secret-view')).toHaveCount(0);
  await other.unroute(revealUrl);

  // 2. Markup in a secret is text.
  await older.getByTestId('secret-reveal').click();
  await older.getByTestId('secret-reveal-confirm').click();
  await expect(older.getByTestId('secret-view-text')).toHaveText(payload, { timeout: 60_000 });
  await expect(older.getByTestId('secret-view').locator('img, script')).toHaveCount(0);
  expect(await other.evaluate(() => (window as unknown as { __cmPwned?: number }).__cmPwned)).toBeUndefined();
  expect(dialogs).toBe(0);
  if (browserName === 'chromium') await screenshot(other, 'EV-09-09-tamper-and-xss.png');
  expect(await violations()).toEqual([]);
  await context.close();
});

test('secrets encrypted in one engine decrypt in the others', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'Runs once from Chromium and drives Firefox and WebKit itself');
  test.setTimeout(600_000);
  await signedInWithVault(page, 'Chromium Secret Owner');
  const roomName = 'Cross-engine secrets';
  await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  for (const engine of [firefox, webkit]) {
    const other: Browser = await engine.launch();
    try {
      const context = await other.newContext({ ignoreHTTPSErrors: true, baseURL: new URL(page.url()).origin });
      const member = await context.newPage();
      const account = await signedInWithVault(member, `${engine.name()} Secret Member`);
      await openRoomThroughUi(page, roomName);
      await inviteThroughUi(page, account, 'Member', false);
      await acceptThroughUi(member, roomName);
      await verifiedSafetyCode(member);
      await openRoomThroughUi(page, roomName);
      await sendThroughUi(page, account.name, `From Chromium ✓ 秘密 to ${engine.name()}`);
      await openRoomThroughUi(member, roomName);
      const row = await revealThroughUi(member);
      await expect(row.getByTestId('secret-view-text')).toHaveText(`From Chromium ✓ 秘密 to ${engine.name()}`, {
        timeout: 60_000,
      });
      await sendThroughUi(member, 'Chromium Secret Owner', `From ${engine.name()}`);
      await openRoomThroughUi(page, roomName);
      const back = page.getByTestId('secret-row').filter({ hasText: 'From' }).first();
      await back.getByTestId('secret-reveal').click();
      await back.getByTestId('secret-reveal-confirm').click();
      await expect(back.getByTestId('secret-view-text')).toHaveText(`From ${engine.name()}`, { timeout: 60_000 });
    } finally {
      await other.close();
    }
  }
});
