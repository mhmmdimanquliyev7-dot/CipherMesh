import { unlockVault, verifyPublicIdentity, vaultRecordFromWire, type VaultWire } from '@ciphermesh/crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { errorCode, signedInUser, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import {
  fetchStoredVault,
  newPassphrase,
  prepareVault,
  runner,
  setupBody,
  userWithVault,
  vaultUser,
} from '../helpers/vault';

// CM-T025 vault setup and the owner's vault record (DF-03, DF-04, OL-10), against the real API,
// real Argon2id parameters and PostgreSQL as the least-privilege API role.
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

// The rsaEncryption and id-ecPublicKey OIDs appear in every PKCS#8 private key of the two types.
const PKCS8_MARKERS = ['2a864886f70d010101', '2a8648ce3d0201'];

describe('vault setup (POST /api/vault)', () => {
  it('requires a session and a recent step-up', async () => {
    const { identity, browser } = await signedInUser(api);
    const session = await browser.request('GET', '/auth/session');
    const userId = (session.body['user'] as { id: string }).id;
    const setup = await prepareVault(
      { identity, browser, userId, account: { email: identity.email, displayName: identity.displayName } },
      newPassphrase(),
    );
    expect(errorCode(await browser.request('POST', '/vault', setupBody(setup)))).toBe('STEP_UP_REQUIRED');
    browser.cookies.clear();
    expect((await browser.request('POST', '/vault', setupBody(setup))).status).toBe(401);
  });

  it('stores only public keys, ciphertext and non-secret KDF metadata (database row inspected)', async () => {
    const user = await userWithVault(api);
    const { rows } = await db.query<Record<string, unknown>>(
      `SELECT status, algorithm_suite, vault_version, public_key_spki, signing_public_key_spki,
              public_key_fingerprint, identity_signature, encrypted_private_key, private_key_iv,
              encrypted_signing_private_key, signing_private_key_iv, kdf_algorithm, kdf_memory_kib,
              kdf_iterations, kdf_parallelism, kdf_salt
         FROM user_key_pairs WHERE user_id = $1`,
      [user.userId],
    );
    expect(rows).toHaveLength(1);
    const row = rows[0] ?? {};
    expect(row).toMatchObject({
      status: 'ACTIVE',
      algorithm_suite: 'CM1',
      vault_version: 1,
      kdf_algorithm: 'argon2id',
      kdf_memory_kib: 65536,
      kdf_iterations: 3,
      kdf_parallelism: 1,
      public_key_fingerprint: user.setup.record.identity.fingerprint,
    });
    const hex = (value: unknown): string => Buffer.from(value as Uint8Array).toString('hex');
    for (const column of ['encrypted_private_key', 'encrypted_signing_private_key']) {
      for (const marker of PKCS8_MARKERS) expect(hex(row[column])).not.toContain(marker);
    }
    expect((row['encrypted_private_key'] as Uint8Array).length).toBeGreaterThan(1700);
    expect((row['encrypted_signing_private_key'] as Uint8Array).length).toBe(154);
    // Nothing in the row is the passphrase or derived from it in a recoverable way.
    const everything = JSON.stringify(Object.values(row).map((v) => (v instanceof Uint8Array ? hex(v) : v)));
    expect(everything).not.toContain(Buffer.from(user.passphrase).toString('hex'));
    expect(everything).not.toContain(user.passphrase);
  });

  it('returns the record to its owner, and only the passphrase opens it, in the browser', async () => {
    const user = await userWithVault(api);
    const record = await fetchStoredVault(user);
    expect(record.identity.fingerprint).toBe(user.setup.record.identity.fingerprint);
    await expect(user.setup.complete(record)).resolves.toBeDefined();
    await expect(
      unlockVault({ record, userId: user.userId, passphrase: user.passphrase, runner }),
    ).resolves.toBeDefined();
    await expect(
      unlockVault({ record, userId: user.userId, passphrase: `${user.passphrase}x`, runner }),
    ).rejects.toMatchObject({ code: 'VAULT_UNLOCK_FAILED' });
  });

  it("a user without a vault gets 404 VAULT_NOT_FOUND, never someone else's record", async () => {
    await userWithVault(api);
    const { browser } = await signedInUser(api);
    const response = await browser.request('GET', '/vault');
    expect(response.status).toBe(404);
    expect(errorCode(response)).toBe('VAULT_NOT_FOUND');
  });

  it('refuses a second vault for the same account', async () => {
    const user = await userWithVault(api);
    const second = await prepareVault(user, newPassphrase());
    const response = await user.browser.request('POST', '/vault', setupBody(second));
    expect(response.status).toBe(409);
    expect(errorCode(response)).toBe('VAULT_ALREADY_EXISTS');
  });

  it('rejects any field that could carry a secret (strict schemas, INV-01)', async () => {
    const user = await vaultUser(api);
    const body = setupBody(await prepareVault(user, newPassphrase()));
    const smuggled: Record<string, unknown>[] = [
      { ...body, vaultPassphrase: 'x'.repeat(20) },
      { ...body, privateKey: 'AAAA' },
      { ...body, identity: { ...body.identity, privateKeyPkcs8: 'AAAA' } },
      { ...body, kdf: { ...body.kdf, key: 'AAAA' } },
      { ...body, userId: user.userId },
    ];
    for (const payload of smuggled) {
      const response = await user.browser.request('POST', '/vault', payload);
      expect(response.status).toBe(400);
      expect(errorCode(response)).toBe('VALIDATION_FAILED');
    }
  });

  it('rejects an identity that fails verification, with the same checks the browsers run', async () => {
    const user = await vaultUser(api);
    const body = setupBody(await prepareVault(user, newPassphrase()));
    const lastChar = (s: string): string => (s.endsWith('A') ? 'B' : 'A');
    const flipSignature = `${body.identity.bindingSignature.slice(0, 20)}${lastChar(body.identity.bindingSignature.slice(20, 21))}${body.identity.bindingSignature.slice(21)}`;
    const otherFingerprint = `${body.identity.fingerprint.slice(0, 63)}${body.identity.fingerprint.endsWith('0') ? '1' : '0'}`;
    for (const identity of [
      { ...body.identity, bindingSignature: flipSignature },
      { ...body.identity, fingerprint: otherFingerprint },
    ]) {
      const response = await user.browser.request('POST', '/vault', { ...body, identity });
      expect(response.status).toBe(400);
      expect(errorCode(response)).toBe('IDENTITY_REJECTED');
    }
    // Another account's genuine identity is bound to that account's user ID (ADR-015 section 2).
    const other = await vaultUser(api);
    const foreign = setupBody(await prepareVault(other, newPassphrase()));
    const response = await user.browser.request('POST', '/vault', foreign);
    expect(errorCode(response)).toBe('IDENTITY_REJECTED');
  });

  it('rejects KDF parameters below the floor or above the ceiling, and non-canonical encodings', async () => {
    const user = await vaultUser(api);
    const body = setupBody(await prepareVault(user, newPassphrase()));
    for (const kdf of [
      { ...body.kdf, memoryKiB: 19455 },
      { ...body.kdf, iterations: 1 },
      { ...body.kdf, memoryKiB: 262145 },
      { ...body.kdf, algorithm: 'pbkdf2' },
      { ...body.kdf, version: 16 },
    ]) {
      expect((await user.browser.request('POST', '/vault', { ...body, kdf })).status).toBe(400);
    }
    // A salt with non-zero unused bits in its last character passes the shape check but not the
    // strict decoding: each value has exactly one accepted encoding.
    const salt = body.kdf.salt;
    const nonCanonical = `${salt.slice(0, -1)}${salt.endsWith('B') ? 'C' : 'B'}`;
    const response = await user.browser.request('POST', '/vault', {
      ...body,
      kdf: { ...body.kdf, salt: nonCanonical },
    });
    expect(errorCode(response)).toBe('INVALID_VAULT_FORMAT');
  });

  it('the uploaded public identity verifies in the browser exactly as on the server', async () => {
    const user = await userWithVault(api);
    const response = await user.browser.request('GET', '/vault');
    const record = vaultRecordFromWire(response.body['vault'] as VaultWire, user.userId);
    await expect(verifyPublicIdentity(record.identity)).resolves.toBeDefined();
  });
});
