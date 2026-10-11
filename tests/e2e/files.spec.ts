import { expect, firefox, test, webkit, type Browser, type Page, type Request } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { loadLocalEnv, storageClient, storageTarget } from '../../scripts/storage/lib.mjs';
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

// Phase 7 in the browser (CM-T038 to CM-T041) in Chromium, Firefox and WebKit, against the built
// static export under the production CSP, the real API and the real object storage behind an
// HTTPS endpoint (tests/e2e/static-server.mjs):
// - a file is encrypted in the browser, uploaded with a presigned PUT and downloaded by another
//   member with identical bytes; no request and no browser storage carries its name or content;
// - a changed object is an integrity error and nothing is saved;
// - HTML and SVG are never rendered; raster images preview through a blob: URL only;
// - locking the vault removes names and downloads at once;
// - files encrypted in one engine decrypt in the others.
// Content is synthetic. Evidence screenshots go to test-results/evidence.

loadLocalEnv();
const EVIDENCE = join('test-results', 'evidence');
const UPLOADS = join('test-results', 'uploads');

async function screenshot(page: Page, name: string): Promise<void> {
  mkdirSync(EVIDENCE, { recursive: true });
  await page.screenshot({ path: join(EVIDENCE, name), fullPage: true });
}

/** A synthetic local file for the file chooser; never a real document. */
function syntheticFile(name: string, content: Buffer): string {
  mkdirSync(UPLOADS, { recursive: true });
  const path = join(UPLOADS, `${randomBytes(4).toString('hex')}-${name}`);
  writeFileSync(path, content);
  return path;
}

/** Every request with its full binary body, for leak checks across the API and storage. */
interface Captured {
  readonly method: string;
  readonly url: string;
  readonly body: Buffer;
  /** Every header the browser sent, cookies and Referer included. */
  readonly headers: Promise<Record<string, string>>;
}

function captureAll(page: Page): Captured[] {
  const captured: Captured[] = [];
  page.on('request', (request: Request) => {
    captured.push({
      method: request.method(),
      url: request.url(),
      body: request.postDataBuffer() ?? Buffer.alloc(0),
      headers: request.allHeaders().catch(() => ({})),
    });
  });
  return captured;
}

async function uploadThroughUi(page: Page, path: string): Promise<void> {
  await page.getByTestId('file-input').setInputFiles(path);
  await page.getByTestId('file-upload').click();
  await expect(page.getByText('The file was encrypted in your browser and uploaded.')).toBeVisible({ timeout: 60_000 });
}

const fileRow = (page: Page, name: string) => page.getByTestId('file-row').filter({ hasText: name });

async function downloadThroughUi(page: Page, name: string): Promise<Buffer> {
  const row = fileRow(page, name);
  await expect(row).toBeVisible({ timeout: 60_000 });
  const pending = page.waitForEvent('download');
  await row.getByRole('button', { name: /^Download/ }).click();
  const download = await pending;
  return readFileSync(await download.path());
}

/** The stored object key of the room's newest file (test inspection through the database). */
async function newestObjectKey(roomId: string): Promise<string> {
  const db = new pg.Client({ connectionString: process.env['DATABASE_URL'] });
  await db.connect();
  try {
    const { rows } = await db.query<{ object_key: string }>(
      "SELECT object_key FROM encrypted_files WHERE room_id = $1 AND status = 'AVAILABLE' ORDER BY created_at DESC LIMIT 1",
      [roomId],
    );
    return rows[0]?.object_key ?? '';
  } finally {
    await db.end();
  }
}

async function objectBytes(objectKey: string): Promise<Buffer> {
  const { endpoint, bucket } = storageTarget();
  return Buffer.from(await (await storageClient('runtime').fetch(`${endpoint}/${bucket}/${objectKey}`)).arrayBuffer());
}

async function replaceObject(objectKey: string, bytes: Buffer): Promise<void> {
  const { endpoint, bucket } = storageTarget();
  const response = await storageClient('runtime').fetch(`${endpoint}/${bucket}/${objectKey}`, {
    method: 'PUT',
    body: new Uint8Array(bytes),
  });
  expect(response.status).toBe(200);
}

test('a member uploads an encrypted file; another member downloads the identical bytes; nothing leaks', async ({
  page,
  browser,
  browserName,
}) => {
  test.setTimeout(300_000);
  const violations = await collectCspViolations(page);
  const captured = captureAll(page);
  await signedInWithVault(page, 'File Owner');
  const roomId = await createRoomThroughUi(page, 'File room');
  await verifiedSafetyCode(page);
  await expect(page.getByTestId('files-empty')).toBeVisible();

  const nameCanary = `canary-name-${randomBytes(5).toString('hex')}`;
  const contentCanary = `CANARY-CONTENT-${randomBytes(6).toString('hex')}`;
  const content = Buffer.concat([Buffer.from(`${contentCanary}\n`), randomBytes(2 * 1024 * 1024)]);
  const announce = page.waitForRequest((r) => r.url().endsWith(`/api/rooms/${roomId}/files`) && r.method() === 'POST');
  await uploadThroughUi(page, syntheticFile(`${nameCanary}.bin`, content));
  // The API receives ciphertext references and the wrapped FEK only (DF-07): no name, type or key.
  const body = JSON.parse((await announce).postData() ?? '{}') as Record<string, unknown>;
  expect(Object.keys(body).sort()).toEqual(
    [
      'ciphertextSha256',
      'ciphertextSize',
      'contentIv',
      'expiresAt',
      'fekIv',
      'fileId',
      'keyVersion',
      'manifest',
      'manifestIv',
      'suite',
      'wrappedFek',
    ].sort(),
  );
  expect(body['ciphertextSize']).toBe(content.length + 16);
  await expect(fileRow(page, nameCanary)).toBeVisible();

  // The object in storage is ciphertext of the expected size, without the canary.
  const stored = await objectBytes(await newestObjectKey(roomId));
  expect(stored.length).toBe(content.length + 16);
  expect(stored.includes(Buffer.from(contentCanary))).toBe(false);
  if (browserName === 'chromium') {
    mkdirSync(EVIDENCE, { recursive: true });
    writeFileSync(join(EVIDENCE, 'EV-07-01-original-head.txt'), content.subarray(0, 64).toString('hex'));
    writeFileSync(join(EVIDENCE, 'EV-07-01-object-head.txt'), stored.subarray(0, 64).toString('hex'));
  }

  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await context.newPage();
  const otherCaptured = captureAll(other);
  const member = await signedInWithVault(other, 'File Member');
  await openRoomThroughUi(page, 'File room');
  await inviteThroughUi(page, member, 'Viewer', false);
  await acceptThroughUi(other, 'File room');
  await verifiedSafetyCode(other);
  const downloaded = await downloadThroughUi(other, nameCanary);
  expect(downloaded.equals(content), 'downloaded bytes equal the original').toBe(true);
  if (browserName === 'chromium') await screenshot(other, 'EV-07-04-download-ok.png');

  // Neither browser sent the name or the content in any request, nor kept them in storage.
  for (const [who, requests] of [
    [page, captured],
    [other, otherCaptured],
  ] as const) {
    for (const request of requests) {
      for (const canary of [nameCanary, contentCanary]) {
        expect(request.url.includes(canary)).toBe(false);
        expect(request.body.includes(Buffer.from(canary)), `request to ${new URL(request.url).pathname}`).toBe(false);
      }
    }
    const kept = await readableStorage(who);
    expect(kept).not.toContain(nameCanary);
    expect(kept).not.toContain(contentCanary);
    // Requests to storage carry no session cookie and no Referer (the room page URL names the room).
    const toStorage = requests.filter((r) => !r.url.startsWith(new URL(page.url()).origin));
    expect(toStorage.length).toBeGreaterThan(0);
    for (const request of toStorage) {
      const sentHeaders = await request.headers;
      expect(sentHeaders['cookie'], `${request.method} ${request.url.slice(0, 40)}`).toBeUndefined();
      expect(sentHeaders['referer'], `${request.method} ${request.url.slice(0, 40)}`).toBeUndefined();
    }
  }
  expect(await violations()).toEqual([]);
  await context.close();
});

test('a changed object is an integrity error: nothing is shown or saved (EV-07-04)', async ({ page, browserName }) => {
  test.setTimeout(240_000);
  await signedInWithVault(page, 'Tamper Owner');
  const roomId = await createRoomThroughUi(page, 'Tamper room');
  await verifiedSafetyCode(page);
  const content = Buffer.from('Synthetic tamper demonstration, no real data.\n'.repeat(100));
  await uploadThroughUi(page, syntheticFile('tamper.txt', content));
  const objectKey = await newestObjectKey(roomId);
  const original = await objectBytes(objectKey);
  const changed = Buffer.from(original);
  changed[200] = (changed[200] ?? 0) ^ 0x01;
  await replaceObject(objectKey, changed);

  let downloads = 0;
  page.on('download', () => {
    downloads += 1;
  });
  await fileRow(page, 'tamper.txt').getByRole('button', { name: 'Download' }).click();
  // The page's own alert (Next.js also renders an empty route announcer with role="alert").
  await expect(page.getByText('This file failed its integrity check')).toBeVisible({ timeout: 60_000 });
  expect(downloads).toBe(0);
  if (browserName === 'chromium') await screenshot(page, 'EV-07-04-tampered.png');
  await replaceObject(objectKey, original);
  expect((await downloadThroughUi(page, 'tamper.txt')).equals(content)).toBe(true);
});

test('HTML and SVG are never rendered; raster images preview through blob: only (CM-T041)', async ({ page }) => {
  test.setTimeout(240_000);
  const violations = await collectCspViolations(page);
  await signedInWithVault(page, 'Preview Owner');
  await createRoomThroughUi(page, 'Preview room');
  await verifiedSafetyCode(page);
  const html = Buffer.from('<html><body><script>window.__cmPwned = 1; parent.__cmPwned = 1;</script>x</body></html>');
  const svg = Buffer.from(
    '<svg xmlns="http://www.w3.org/2000/svg" onload="window.__cmPwned=1"><script>window.__cmPwned=1</script></svg>',
  );
  // A 1x1 PNG.
  const png = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
    'base64',
  );
  await uploadThroughUi(page, syntheticFile('page.html', html));
  await uploadThroughUi(page, syntheticFile('drawing.svg', svg));
  await uploadThroughUi(page, syntheticFile('pixel.png', png));
  const start = page.url();

  for (const name of ['page.html', 'drawing.svg']) {
    const row = fileRow(page, name);
    await expect(row.getByRole('button', { name: 'Preview' })).toHaveCount(0);
    // Executable or active content: a warning first, then a download, never a navigation.
    await row.getByRole('button', { name: 'Download' }).click();
    await expect(row.getByText('can run code or show active content')).toBeVisible();
    const pending = page.waitForEvent('download');
    await row.getByRole('button', { name: 'Download anyway' }).click();
    const saved = readFileSync(await (await pending).path());
    expect(saved.equals(name.endsWith('.html') ? html : svg)).toBe(true);
    expect(page.url()).toBe(start);
  }
  await fileRow(page, 'pixel.png').getByRole('button', { name: 'Preview' }).click();
  const image = page.getByTestId('file-preview').getByRole('img');
  await expect(image).toBeVisible();
  expect(await image.getAttribute('src')).toMatch(/^blob:/);
  expect(await page.evaluate(() => (window as unknown as { __cmPwned?: number }).__cmPwned)).toBeUndefined();
  expect(page.frames()).toHaveLength(1);
  expect(await violations()).toEqual([]);
});

test('locking the vault removes file names and downloads at once; unlocking restores them', async ({ page }) => {
  test.setTimeout(240_000);
  const user = await signedInWithVault(page, 'Lock Owner');
  await createRoomThroughUi(page, 'Lock room');
  await verifiedSafetyCode(page);
  await uploadThroughUi(page, syntheticFile('locked-name.txt', Buffer.from('lock test')));
  await expect(fileRow(page, 'locked-name.txt')).toBeVisible();
  await page.getByRole('button', { name: 'Lock now' }).click();
  await expect(page.getByTestId('file-name').filter({ hasText: 'locked-name.txt' })).toHaveCount(0);
  await expect(page.getByTestId('file-name').first()).toHaveText('Encrypted file');
  await expect(page.getByTestId('file-row').getByRole('button', { name: 'Download' })).toHaveCount(0);
  await expect(page.getByTestId('file-input')).toHaveCount(0);
  await unlockVault(page, user.passphrase);
  await openRoomThroughUi(page, 'Lock room');
  await expect(fileRow(page, 'locked-name.txt')).toBeVisible({ timeout: 60_000 });
});

test('files encrypted in one engine decrypt in the others', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'Runs once from Chromium and drives Firefox and WebKit itself');
  test.setTimeout(600_000);
  await signedInWithVault(page, 'Chromium Owner');
  const roomName = 'Cross-engine files';
  await createRoomThroughUi(page, roomName);
  await verifiedSafetyCode(page);
  const fromChromium = randomBytes(300_000);
  await uploadThroughUi(page, syntheticFile('from-chromium.bin', fromChromium));
  for (const engine of [firefox, webkit]) {
    const other: Browser = await engine.launch();
    try {
      const context = await other.newContext({ ignoreHTTPSErrors: true, baseURL: new URL(page.url()).origin });
      const member = await context.newPage();
      const account = await signedInWithVault(member, `${engine.name()} Member`);
      await openRoomThroughUi(page, roomName);
      await inviteThroughUi(page, account, 'Member', false);
      await acceptThroughUi(member, roomName);
      await verifiedSafetyCode(member);
      expect((await downloadThroughUi(member, 'from-chromium.bin')).equals(fromChromium), engine.name()).toBe(true);
      const fromOther = randomBytes(200_000);
      const name = `from-${engine.name()}.bin`;
      await uploadThroughUi(member, syntheticFile(name, fromOther));
      await openRoomThroughUi(page, roomName);
      expect((await downloadThroughUi(page, name)).equals(fromOther), `${engine.name()} to chromium`).toBe(true);
    } finally {
      await other.close();
    }
  }
});
