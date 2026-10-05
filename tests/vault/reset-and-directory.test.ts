import { SESSION_COOKIE } from '@ciphermesh/shared';
import {
  computeFingerprint,
  createVault,
  publicIdentityFromWire,
  unlockVault,
  vaultRecordToWire,
  verifyPublicIdentity,
} from '@ciphermesh/crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { Browser, errorCode, signedInUser, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { fetchStoredVault, newPassphrase, runner, userWithVault, vaultUser } from '../helpers/vault';

// Vault reset after a lost passphrase (key-lifecycle section 3, session-and-csrf section 4) and
// the public-key directory (CM-T027, SS-05). Object-level rules: the owner is always the session
// user (OL-10); others see public identity data only.
let api: AuthTestApi;
let db: pg.Client;

beforeAll(async () => {
  api = await startAuthApi();
  loadDatabaseTestEnv();
  db = await testDatabase(inject('databaseName')).connect('api');
});
afterAll(async () => {
  await db.end();
  await api.close();
});

describe('vault reset (POST /api/vault/reset)', () => {
  it('replaces the identity, retires the old one without its private keys, and ends the other sessions', async () => {
    const user = await userWithVault(api);
    const old = await fetchStoredVault(user);
    // A second device of the same user.
    const otherDevice = new Browser(api);
    expect((await otherDevice.login(user.identity)).status).toBe(200);
    const oldToken = user.browser.session;

    const fresh = await createVault({
      userId: user.userId,
      passphrase: newPassphrase(),
      account: user.account,
      runner,
    });
    const response = await user.browser.request('POST', '/vault/reset', {
      supersedesKeyId: old.identity.keyId,
      vault: vaultRecordToWire(fresh.record),
    });
    expect(response.status).toBe(201);
    expect(response.body['fingerprint']).toBe(fresh.record.identity.fingerprint);
    expect(response.body['otherSessionsRevoked']).toBe(1);

    // The current session was rotated: the old token is dead, the new one works.
    expect(user.browser.session).not.toBe(oldToken);
    const stale = new Browser(api);
    stale.cookies.set(SESSION_COOKIE, String(oldToken));
    expect((await stale.request('GET', '/vault')).status).toBe(401);
    expect((await otherDevice.request('GET', '/vault')).status).toBe(401);

    const { rows } = await db.query<{ id: string; status: string; enc: Uint8Array | null; sig: Uint8Array | null }>(
      `SELECT id, status, encrypted_private_key AS enc, encrypted_signing_private_key AS sig
         FROM user_key_pairs WHERE user_id = $1 ORDER BY created_at, status`,
      [user.userId],
    );
    const retired = rows.find((r) => r.id === old.identity.keyId);
    expect(retired).toMatchObject({ status: 'SUPERSEDED', enc: null, sig: null });
    expect(rows.find((r) => r.id === fresh.record.identity.keyId)?.status).toBe('ACTIVE');

    const now = await fetchStoredVault(user);
    expect(now.identity.fingerprint).toBe(fresh.record.identity.fingerprint);
    await expect(fresh.complete(now)).resolves.toBeDefined();
    expect(api.events.some((e) => e.name === 'VAULT_RESET' && e.actorUserId === user.userId)).toBe(true);
  });

  it('requires the strict step-up window (5 minutes) and names the current identity', async () => {
    const user = await userWithVault(api);
    const old = await fetchStoredVault(user);
    const fresh = await createVault({
      userId: user.userId,
      passphrase: newPassphrase(),
      account: user.account,
      runner,
    });
    const body = { supersedesKeyId: old.identity.keyId, vault: vaultRecordToWire(fresh.record) };
    api.clock.advance(6 * 60_000);
    expect(errorCode(await user.browser.request('POST', '/vault/reset', body))).toBe('STEP_UP_REQUIRED');
    expect((await user.browser.request('POST', '/auth/step-up', { password: user.identity.password })).status).toBe(
      200,
    );
    const wrongTarget = await user.browser.request('POST', '/vault/reset', {
      ...body,
      supersedesKeyId: fresh.record.identity.keyId,
    });
    expect(wrongTarget.status).toBe(409);
    expect(errorCode(wrongTarget)).toBe('VAULT_CONFLICT');
    // Nothing changed: the old identity is still the active one and still opens.
    const still = await fetchStoredVault(user);
    expect(still.identity.keyId).toBe(old.identity.keyId);
    await expect(
      unlockVault({ record: still, userId: user.userId, passphrase: user.passphrase, runner }),
    ).resolves.toBeDefined();
  });
});

describe('public-key directory (POST /api/directory/lookup)', () => {
  it('returns only public identity data that the browser can verify and fingerprint itself', async () => {
    const target = await userWithVault(api);
    const searcher = await userWithVault(api);
    const response = await searcher.browser.request('POST', '/directory/lookup', {
      email: target.identity.email.toUpperCase(),
    });
    expect(response.status).toBe(200);
    const body = response.body as { user: Record<string, unknown>; identity: Record<string, unknown> };
    expect(Object.keys(body.user).sort()).toEqual(['accountCreatedAt', 'displayName', 'emailVerified', 'id']);
    expect(body.user['emailVerified']).toBe(false);
    expect(Object.keys(body.identity).sort()).toEqual(
      [
        'bindingSignature',
        'createdAt',
        'encryptionPublicKey',
        'fingerprint',
        'keyId',
        'signingPublicKey',
        'suite',
      ].sort(),
    );
    const text = JSON.stringify(response.body);
    for (const forbidden of ['ciphertext', 'salt', 'kdf', 'iv', 'passwordHash', 'email', 'wrapped']) {
      expect(text).not.toContain(`"${forbidden}"`);
    }
    // The searcher verifies the identity and computes the fingerprint locally (CP-17).
    const identity = publicIdentityFromWire(
      body.identity as unknown as Parameters<typeof publicIdentityFromWire>[0],
      String(body.user['id']),
    );
    const verified = await verifyPublicIdentity(identity);
    expect(await computeFingerprint(verified.encryptionKeySpki, verified.signingKeySpki)).toBe(
      target.setup.record.identity.fingerprint,
    );
  });

  it('requires an own vault, and answers 404 alike for unknown, vault-less and disabled accounts', async () => {
    const noVault = await signedInUser(api);
    const target = await userWithVault(api);
    const lookup = await noVault.browser.request('POST', '/directory/lookup', { email: target.identity.email });
    expect(lookup.status).toBe(403);
    expect(errorCode(lookup)).toBe('VAULT_SETUP_REQUIRED');

    const searcher = await userWithVault(api);
    const vaultless = await signedInUser(api);
    const disabled = await userWithVault(api);
    await db.query(`UPDATE users SET status = 'DISABLED' WHERE id = $1`, [disabled.userId]);
    for (const email of ['nobody-here@example.test', vaultless.identity.email, disabled.identity.email]) {
      const response = await searcher.browser.request('POST', '/directory/lookup', { email });
      expect(response.status).toBe(404);
      expect(errorCode(response)).toBe('NOT_FOUND');
    }
  });

  it('is rate-limited per user and records the throttling', async () => {
    const searcher = await userWithVault(api);
    const statuses: number[] = [];
    for (let i = 0; i < 21; i++) {
      statuses.push(
        (await searcher.browser.request('POST', '/directory/lookup', { email: `x${String(i)}@example.test` })).status,
      );
    }
    expect(statuses.slice(0, 20).every((s) => s === 404)).toBe(true);
    expect(statuses[20]).toBe(429);
    expect(api.events.some((e) => e.name === 'DIRECTORY_LOOKUP_THROTTLED' && e.actorUserId === searcher.userId)).toBe(
      true,
    );
  });
});

describe('object-level authorization (BOLA/IDOR, OL-10)', () => {
  it("no request field, query or header can select another user's vault", async () => {
    const victim = await userWithVault(api);
    const attacker = await vaultUser(api);
    // The routes take no identifiers: a query parameter is rejected, headers and bodies are ignored.
    const withQuery = await attacker.browser.request('GET', `/vault?userId=${victim.userId}`);
    expect(withQuery.status).toBe(400);
    for (const headers of [{ 'x-user-id': victim.userId }, { 'x-forwarded-user': victim.userId }]) {
      const response = await attacker.browser.request('GET', '/vault', undefined, headers);
      expect(response.status).toBe(404);
      expect(JSON.stringify(response.body)).not.toContain(victim.setup.record.identity.fingerprint);
    }
    const victimKeyId = victim.setup.record.identity.keyId;
    const rewrapOfVictim = await attacker.browser.request('POST', '/vault/rewrap', {
      keyId: victimKeyId,
      previousKdfSalt: 'A'.repeat(22),
      kdf: {
        algorithm: 'argon2id',
        version: 19,
        memoryKiB: 65536,
        iterations: 3,
        parallelism: 1,
        salt: 'B'.repeat(21) + 'A',
      },
      wrappedEncryptionKey: { iv: 'A'.repeat(16), ciphertext: 'A'.repeat(2412) },
      wrappedSigningKey: { iv: 'A'.repeat(16), ciphertext: 'A'.repeat(206) },
      signature: 'A'.repeat(86),
    });
    expect(rewrapOfVictim.status).toBe(404);
    const resetOfVictim = await attacker.browser.request('POST', '/vault/reset', {
      supersedesKeyId: victimKeyId,
      vault: vaultRecordToWire(
        (await createVault({ userId: attacker.userId, passphrase: newPassphrase(), account: attacker.account, runner }))
          .record,
      ),
    });
    expect(resetOfVictim.status).toBe(409);
    // The victim's vault is untouched.
    const record = await fetchStoredVault(victim);
    expect(record.identity.keyId).toBe(victimKeyId);
    await expect(
      unlockVault({ record, userId: victim.userId, passphrase: victim.passphrase, runner }),
    ).resolves.toBeDefined();
  });
});
