import { expect, firefox, request, test, webkit, type Browser, type Page } from '@playwright/test';
import { build } from 'vite';
import { hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import pg from 'pg';
import { Secret, TOTP } from 'otpauth';
import { contextBytes } from '../../packages/crypto/src/contexts';
import { generateIdentity } from '../../packages/crypto/src/identity';
import { createInitialRoomKey, createInvitationKeys, type RoomKeyBundle } from '../../packages/crypto/src/room-keys';
import {
  invitationKeysToWire,
  roomCreationKeysToWire,
  roomKeyBundlesFromWire,
  type EnvelopeWire,
  type RoomKeyMaterialWire,
} from '../../packages/crypto/src/room-format';
import { keyVersionStatement } from '../../packages/crypto/src/room-statements';
import { wrap32 } from '../../packages/crypto/src/rsa-oaep';
import { signStatement } from '../../packages/crypto/src/signing';
import { publicIdentityFromWire, type PublicIdentityWire } from '../../packages/crypto/src/vault-format';
import { verifyPublicIdentity } from '../../packages/crypto/src/identity';
import { captureRequests, collectCspViolations, newUser, readableStorage, type TestUser } from './helpers';
import {
  acceptThroughUi,
  createRoomThroughUi,
  inviteThroughUi,
  openRoomThroughUi,
  ownFingerprint,
  signedInWithVault,
  unlockVault,
  verifiedSafetyCode,
} from './room-helpers';

// Phase 6 in the browser (CM-T033, CM-T034, CM-T036, CM-T085) in Chromium, Firefox and WebKit,
// against the built static export under the production CSP and the real API:
// - room keys are made, verified and used only in the browser and live only in memory;
// - an invited member verifies the key through the signed grant and sees the same Safety Code;
// - envelopes made in one engine open in the others (OCD-01, ADR-007);
// - the Safety Code derivation and word mapping give the known answers in every engine;
// - a split view made by an authorized owner together with the server passes every automatic
//   check, and only the Safety Codes reveal it (EV-06-06, L-22).
// Evidence screenshots go to test-results/evidence (copied into docs/report/evidence/phase-06).

const EVIDENCE = join('test-results', 'evidence');

async function screenshot(page: Page, name: string): Promise<void> {
  mkdirSync(EVIDENCE, { recursive: true });
  await page.screenshot({ path: join(EVIDENCE, name), fullPage: true });
}

/** Everything a request carries that could leak a value: URL and body. */
/**
 * The forms a leaked Safety Code would take: the six words with spaces, without separators, with
 * commas or as a JSON array. Single words are not searched: a short common word can appear in an
 * unrelated URL or in base64 data by chance (a WebKit run hit "tree"), which proves nothing.
 */
const codeForms = (code: string): string[] => {
  const words = code.split(' ');
  return [code, words.join(''), words.join(','), JSON.stringify(words)];
};

const sent = (captured: { url: string; body: string }[]): string =>
  captured.map((r) => `${r.url}\n${r.body}`).join('\n');

test('the room key is made and kept in the browser: verified after lock and unlock, never sent or stored', async ({
  page,
}) => {
  test.setTimeout(240_000);
  const violations = await collectCspViolations(page);
  const captured = captureRequests(page);
  const user = await signedInWithVault(page);
  const created = page.waitForRequest((r) => r.url().endsWith('/api/rooms') && r.method() === 'POST');
  const roomId = await createRoomThroughUi(page, 'Keyed room');
  // POST /rooms carries public values and ciphertext only: no field for key material (DF-05).
  const body = JSON.parse((await created).postData() ?? '{}') as { keys: Record<string, string> };
  expect(Object.keys(body.keys).sort()).toEqual(
    ['commitment', 'creatorKeyId', 'envelope', 'genesisSignature', 'keyVersionSignature'].sort(),
  );
  expect(body.keys['envelope']).toHaveLength(512);
  const code = await verifiedSafetyCode(page);
  expect(code.split(' ')).toHaveLength(6);

  // Locking drops the room key with the identity keys: the code disappears at once.
  await page.getByRole('button', { name: 'Lock now' }).click();
  await expect(page.getByTestId('safety-code-words')).toHaveCount(0);
  await expect(page.getByText('to open it.')).toBeVisible();
  await unlockVault(page, user.passphrase);
  await openRoomThroughUi(page, 'Keyed room');
  expect(await verifiedSafetyCode(page)).toBe(code);
  expect(new URL(page.url()).searchParams.get('id')).toBe(roomId);

  // Recording a comparison sends the key version only (AZ-30, INV-18).
  const recorded = page.waitForRequest((r) => r.url().endsWith(`/rooms/${roomId}/safety-code`));
  await page.getByRole('button', { name: 'We compared, they match' }).click();
  expect(JSON.parse((await recorded).postData() ?? '{}')).toEqual({ keyVersion: 1, result: 'MATCH' });
  await expect(page.getByText('You recorded a comparison for version 1.')).toBeVisible();

  await page.getByRole('button', { name: 'Show as numbers' }).click();
  const digits = (await page.getByTestId('safety-code-digits').innerText()).replace(/\s/g, '');
  expect(digits).toMatch(/^\d{20}$/);
  for (const value of [...codeForms(code), digits, user.passphrase]) {
    expect(sent(captured).includes(value), `request carried ${value.slice(0, 6)}`).toBe(false);
    expect(await readableStorage(page)).not.toContain(value);
    expect(page.url()).not.toContain(value);
  }
  expect(await violations()).toEqual([]);
});

test('an invited member verifies the room key through the signed grant and sees the same Safety Code', async ({
  page,
  browser,
  browserName,
}) => {
  test.setTimeout(300_000);
  await signedInWithVault(page, 'Room Owner');
  const roomId = await createRoomThroughUi(page, 'Shared room');
  const ownerCode = await verifiedSafetyCode(page);

  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const invitee = await context.newPage();
  const captured = captureRequests(invitee);
  const member = await signedInWithVault(invitee, 'Invited Member');
  await openRoomThroughUi(page, 'Shared room');
  expect(new URL(page.url()).searchParams.get('id')).toBe(roomId);
  const shown = await inviteThroughUi(page, member, 'Member', true);
  // The fingerprint the inviter compares is computed from the invitee's keys on the inviter's device.
  expect(shown.replace(/\s+/g, '')).toBe((await ownFingerprint(invitee)).replace(/\s+/g, ''));
  await expect(page.getByRole('list', { name: 'Open invitations' })).toContainText('Invited Member');

  await acceptThroughUi(invitee, 'Shared room');
  const memberCode = await verifiedSafetyCode(invitee);
  expect(memberCode).toBe(ownerCode);
  await expect(
    invitee.getByText('You hold this key through a membership grant signed by an owner or admin.'),
  ).toBeVisible();
  if (browserName === 'chromium') {
    await screenshot(page, 'EV-06-05-owner.png');
    await screenshot(invitee, 'EV-06-05-member.png');
  }
  // The invitee's browser never sent the code, and stored nothing of it.
  for (const value of codeForms(memberCode)) {
    expect(sent(captured).includes(value)).toBe(false);
    expect(await readableStorage(invitee)).not.toContain(value);
  }
  await context.close();
});

// ------------------------------------------------------------------ RESTRICTED (EV-06-02, PC-05)

async function enrollMfa(page: Page, user: TestUser): Promise<string> {
  await page.getByRole('link', { name: 'Account', exact: true }).click();
  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  // The vault setup's step-up may still be fresh; otherwise the server asks for the password first.
  const qr = page.getByRole('img', { name: 'QR code for the authenticator app' });
  const confirm = page.getByText('Confirm your identity to continue');
  await expect(qr.or(confirm)).toBeVisible();
  if (await confirm.isVisible()) {
    await page.getByLabel('Account password').first().fill(user.password);
    await page.getByRole('button', { name: 'Confirm' }).click();
    await expect(confirm).toHaveCount(0);
    await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  }
  await expect(qr).toBeVisible();
  const secret = (await page.locator('p.font-mono').innerText()).trim();
  await page.getByLabel('Code from the app').fill(await totp(secret));
  await page.getByRole('button', { name: 'Turn on' }).click();
  await page.getByRole('button', { name: 'I have stored them' }).click();
  return secret;
}
/**
 * A code for a time step this secret has not used yet: the API refuses a replayed step (CP-09), so
 * each enrollment, sign-in and step-up takes the next unused step, waiting for real time to reach
 * it when it is more than one step ahead (the accepted drift).
 */
const usedSteps = new Map<string, number>();
async function totp(secret: string): Promise<string> {
  const now = (): number => Math.floor(Date.now() / 30_000);
  const target = Math.max(now(), (usedSteps.get(secret) ?? -1) + 1);
  while (target > now() + 1) await new Promise((resolve) => setTimeout(resolve, 1000));
  usedSteps.set(secret, target);
  return TOTP.generate({ secret: Secret.fromBase32(secret), digits: 6, period: 30, timestamp: target * 30_000 });
}

/** Signs in again with the second factor, which gives the session the MFA verification of PC-01. */
async function loginWithMfa(page: Page, user: TestUser, secret: string): Promise<void> {
  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Authentication code').fill(await totp(secret));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible();
}

test('a RESTRICTED room invites only after the fingerprint was compared, with a step-up', async ({
  page,
  browser,
  browserName,
}) => {
  test.skip(browserName !== 'chromium', 'One engine suffices for the policy flow; the crypto runs in all three above');
  test.setTimeout(360_000);
  const owner = await signedInWithVault(page, 'Restricted Owner');
  const ownerSecret = await enrollMfa(page, owner);
  await loginWithMfa(page, owner, ownerSecret);
  await unlockVault(page, owner.passphrase);
  const roomName = 'Restricted room';
  const roomId = await createRoomThroughUi(page, roomName, 'RESTRICTED');
  await verifiedSafetyCode(page);

  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await context.newPage();
  const invitee = await signedInWithVault(other, 'Restricted Invitee');
  const inviteeSecret = await enrollMfa(other, invitee);
  await loginWithMfa(other, invitee, inviteeSecret);

  await openRoomThroughUi(page, roomName);
  expect(new URL(page.url()).searchParams.get('id')).toBe(roomId);
  await page.getByLabel('Email address of the person to invite').fill(invitee.email);
  await page.getByRole('button', { name: 'Look up' }).click();
  const candidate = page.getByTestId('invite-candidate');
  await expect(candidate).toContainText(
    'This RESTRICTED room requires you to compare the fingerprint before inviting.',
  );
  // Without the comparison the invitation cannot be sent (the API refuses it as well, PC-05).
  await expect(candidate.getByRole('button', { name: 'Invite' })).toBeDisabled();
  await screenshot(page, 'EV-06-02-fingerprint-required.png');
  await candidate.getByLabel(`I compared this fingerprint with ${invitee.name} over a channel I trust`).check();
  await candidate.getByRole('button', { name: 'Invite' }).click();
  // PC-03: inviting in a RESTRICTED room needs a recent step-up with the password and the code.
  await expect(page.getByRole('heading', { name: 'Confirm your account' })).toBeVisible();
  await page.getByLabel('Account password').fill(owner.password);
  await page.getByLabel('Authentication code').fill(await totp(ownerSecret));
  await page.getByRole('button', { name: 'Confirm account' }).click();
  await expect(page.getByText(`${invitee.name} was invited.`)).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole('list', { name: 'Open invitations' })).toContainText('fingerprint confirmed');
  await screenshot(page, 'EV-06-02-invited.png');

  await unlockVault(other, invitee.passphrase);
  await acceptThroughUi(other, roomName);
  await verifiedSafetyCode(other);
  await context.close();
});

// --------------------------------------------------------------- cross-engine envelopes (OCD-01)

test('envelopes made in Chromium open in Firefox and WebKit, with the same Safety Code', async ({
  page,
  browserName,
}) => {
  test.skip(browserName !== 'chromium', 'Runs once from Chromium and opens the other two engines itself');
  test.setTimeout(480_000);
  await signedInWithVault(page, 'Chromium Owner');
  const roomName = 'Cross-engine room';
  const roomId = await createRoomThroughUi(page, roomName);
  const ownerCode = await verifiedSafetyCode(page);
  for (const engine of [firefox, webkit]) {
    const other: Browser = await engine.launch();
    try {
      const context = await other.newContext({ ignoreHTTPSErrors: true, baseURL: new URL(page.url()).origin });
      const invitee = await context.newPage();
      const member = await signedInWithVault(invitee, `${engine.name()} Member`);
      await openRoomThroughUi(page, roomName);
      expect(new URL(page.url()).searchParams.get('id')).toBe(roomId);
      await inviteThroughUi(page, member, 'Viewer', false);
      await acceptThroughUi(invitee, roomName);
      expect(await verifiedSafetyCode(invitee), engine.name()).toBe(ownerCode);
    } finally {
      await other.close();
    }
  }
});

// ------------------------------------------------------------- known answers in every engine

test('the commitment and Safety Code derivations give the known answers in this engine (CP-24)', async ({ page }) => {
  // The real package source, bundled for the browser like the Phase 4 benchmark page (vite).
  const output = await build({
    configFile: false,
    logLevel: 'warn',
    build: {
      write: false,
      target: 'es2022',
      minify: false,
      lib: { entry: resolve('tests/e2e/fixtures/room-crypto-kat.ts'), formats: ['iife'], name: 'cmRoomKat' },
    },
  });
  const results = Array.isArray(output) ? output : [output];
  const first = results[0];
  const chunk = first !== undefined && 'output' in first ? first.output.find((o) => o.type === 'chunk') : undefined;
  const code = chunk?.type === 'chunk' ? chunk.code : '';
  expect(code.length).toBeGreaterThan(1000);
  await page.goto('/');
  await page.evaluate(code);
  const result = (await page.evaluate(() =>
    (globalThis as unknown as { __cmRoomKat: () => Promise<unknown> }).__cmRoomKat(),
  )) as { commitment: string; code: unknown; ones: unknown };
  const roomId = '0f3e2d1c-4b5a-4968-8776-a5b4c3d2e1f0';
  const info = Buffer.from(JSON.stringify({ ctx: 'cm.room.commitment', keyVersion: 1, roomId, v: 1 }));
  const rkm = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  // Node.js (OpenSSL) computes the commitment independently of the engine under test.
  expect(result.commitment).toBe(Buffer.from(hkdfSync('sha256', rkm, Buffer.alloc(32), info, 32)).toString('hex'));
  expect(result.code).toEqual({
    keyVersion: 1,
    words: ['knee', 'want', 'dad', 'also', 'trust', 'siege'],
    digits: '35631199793402506816',
  });
  expect(result.ones).toEqual({ keyVersion: 3, words: Array(6).fill('zoo'), digits: '73786976294838206463' });
});

// ------------------------------------------------- split view by an authorized owner (EV-06-06)

/** An owner whose keys live in this test process: it plays an OWNER colluding with the server. */
async function nodeOwner(baseURL: string) {
  const user = newUser();
  const headers = {
    origin: baseURL,
    'sec-fetch-site': 'same-origin',
    'x-ciphermesh-request': '1',
    'x-e2e-client-address': `2001:db8::${randomBytes(2).toString('hex')}:${randomBytes(2).toString('hex')}`,
  };
  const http = await request.newContext({ baseURL, ignoreHTTPSErrors: true, extraHTTPHeaders: headers });
  expect(
    (
      await http.post('/api/auth/register', {
        data: { email: user.email, password: user.password, displayName: 'Colluding Owner' },
      })
    ).status(),
  ).toBe(201);
  expect((await http.post('/api/auth/login', { data: { email: user.email, password: user.password } })).status()).toBe(
    200,
  );
  const session = (await (await http.get('/api/auth/session')).json()) as { user: { id: string } };
  const generated = await generateIdentity(session.user.id);
  const identity = generated.identity;
  const db = new pg.Client({ connectionString: process.env['DATABASE_URL'] });
  await db.connect();
  try {
    // The identity row; the wrapped private keys are filler bytes because this vault is never unlocked.
    await db.query(
      `INSERT INTO user_key_pairs (id, user_id, status, algorithm_suite, public_key_spki, signing_public_key_spki,
         public_key_fingerprint, identity_signature, encrypted_private_key, private_key_iv,
         encrypted_signing_private_key, signing_private_key_iv, vault_version, kdf_algorithm, kdf_memory_kib,
         kdf_iterations, kdf_parallelism, kdf_salt)
       VALUES ($1, $2, 'ACTIVE', 'CM1', $3, $4, $5, $6, $7, $8, $9, $10, 1, 'argon2id', 65536, 3, 1, $11)`,
      [
        identity.keyId,
        identity.userId,
        Buffer.from(identity.encryptionKeySpki),
        Buffer.from(identity.signingKeySpki),
        identity.fingerprint,
        Buffer.from(identity.bindingSignature),
        Buffer.alloc(1810, 0xa5),
        Buffer.alloc(12, 0xa5),
        Buffer.alloc(154, 0xa5),
        Buffer.alloc(12, 0xa5),
        Buffer.alloc(16, 0xa5),
      ],
    );
  } finally {
    await db.end();
  }
  const vault = {
    identity,
    encryptionPrivateKey: generated.encryptionPrivateKey,
    signingPrivateKey: generated.signingPrivateKey,
  };
  const bundles = async (roomId: string): Promise<RoomKeyBundle[]> => {
    const material = (await (await http.get(`/api/rooms/${roomId}/key-versions`)).json()) as RoomKeyMaterialWire;
    const envelopes = (await (await http.get(`/api/rooms/${roomId}/envelopes`)).json()) as {
      envelopes: EnvelopeWire[];
    };
    return roomKeyBundlesFromWire(
      roomId,
      { userId: identity.userId, keyId: identity.keyId },
      material,
      envelopes.envelopes,
    );
  };
  const lookup = async (email: string) => {
    const entry = (await (await http.post('/api/directory/lookup', { data: { email } })).json()) as {
      user: { id: string };
      identity: PublicIdentityWire;
    };
    return verifyPublicIdentity(publicIdentityFromWire(entry.identity, entry.user.id));
  };
  return { http, vault, bundles, lookup };
}

test('a split view made by an authorized owner with the server passes every check; only the Safety Codes differ', async ({
  page,
  browser,
  browserName,
  baseURL,
}) => {
  test.skip(browserName !== 'chromium', 'The harness runs once; the property does not depend on the engine');
  test.setTimeout(360_000);
  const origin = baseURL ?? '';
  const owner = await nodeOwner(origin);
  const roomId = randomUUID();
  const roomName = 'Split view room';
  const { keys } = await createInitialRoomKey(owner.vault, roomId);
  expect(
    (
      await owner.http.post('/api/rooms', {
        data: { roomId, name: roomName, securityProfile: 'STANDARD', keys: roomCreationKeysToWire(keys) },
      })
    ).status(),
  ).toBe(201);

  const alice = await signedInWithVault(page, 'Alice Member');
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const bobPage = await context.newPage();
  const bob = await signedInWithVault(bobPage, 'Bob Member');
  for (const member of [alice, bob]) {
    const invitee = await owner.lookup(member.email);
    const wire = invitationKeysToWire(
      await createInvitationKeys(owner.vault, {
        roomId,
        bundles: await owner.bundles(roomId),
        invitee,
        role: 'MEMBER',
      }),
    );
    const created = await owner.http.post(`/api/rooms/${roomId}/invitations`, {
      data: {
        inviteeUserId: invitee.userId,
        inviteeKeyId: invitee.keyId,
        role: 'MEMBER',
        confirmedFingerprint: null,
        ...wire,
      },
    });
    expect(created.status()).toBe(201);
  }
  await acceptThroughUi(page, roomName);
  await acceptThroughUi(bobPage, roomName);
  const honest = await verifiedSafetyCode(page);
  expect(await verifiedSafetyCode(bobPage)).toBe(honest);

  // The colluding owner signs a second version-1 statement for other key material and the server
  // shows it to Bob only, with an envelope for Bob. Signatures, authority and the commitment all check out.
  const bobIdentity = await owner.lookup(bob.email);
  const otherKey = new Uint8Array(randomBytes(32));
  const commitment = new Uint8Array(
    hkdfSync('sha256', otherKey, Buffer.alloc(32), contextBytes('cm.room.commitment', { roomId, keyVersion: 1 }), 32),
  );
  const self = { userId: owner.vault.identity.userId, keyId: owner.vault.identity.keyId };
  const signature = await signStatement(
    owner.vault.signingPrivateKey,
    keyVersionStatement({
      roomId,
      keyVersion: 1,
      commitment,
      previousCommitment: null,
      creatorUserId: self.userId,
      creatorKeyId: self.keyId,
      recipients: [self],
    }),
  );
  const envelope = await wrap32(
    bobIdentity.encryptionPublicKey,
    otherKey.slice(),
    contextBytes('cm.room.envelope', {
      roomId,
      keyVersion: 1,
      recipientUserId: bobIdentity.userId,
      recipientKeyId: bobIdentity.keyId,
      suite: 'CM1',
    }),
  );
  const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
  await bobPage.route(`**/api/rooms/${roomId}/key-versions`, async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as { keyVersions: { commitment: string; signature: string }[] };
    const version = body.keyVersions[0];
    if (version !== undefined) {
      version.commitment = b64(commitment);
      version.signature = b64(signature);
    }
    await route.fulfill({ response, json: body });
  });
  await bobPage.route(`**/api/rooms/${roomId}/envelopes`, async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as { envelopes: { wrappedKey: string }[] };
    const own = body.envelopes[0];
    if (own !== undefined) own.wrappedKey = b64(envelope);
    await route.fulfill({ response, json: body });
  });
  // Bob opens the room again inside the app; the room key is fetched and verified anew.
  await openRoomThroughUi(bobPage, roomName);
  const split = await verifiedSafetyCode(bobPage);
  // Both browsers report a verified key; only comparing the codes out of band reveals the split.
  expect(split).not.toBe(honest);
  await openRoomThroughUi(page, roomName);
  expect(await verifiedSafetyCode(page)).toBe(honest);
  await screenshot(page, 'EV-06-06-alice.png');
  await screenshot(bobPage, 'EV-06-06-bob.png');
  await context.close();
  await owner.http.dispose();
});
