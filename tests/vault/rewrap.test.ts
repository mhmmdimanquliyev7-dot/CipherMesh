import {
  changeVaultPassphrase,
  rewrapToWire,
  unlockVault,
  upgradeVaultProtection,
  type VaultRewrapWire,
} from '@ciphermesh/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { fetchStoredVault, newPassphrase, runner, userWithVault, vaultUser } from '../helpers/vault';

// CM-T028 Vault Passphrase change and the signed re-wrap of ADR-015 section 3: same identity, new
// salt and ciphertexts, accepted only with a valid signature by the identity's signing key, only
// against the current salt, never weaker.
let api: AuthTestApi;

beforeAll(async () => {
  api = await startAuthApi();
});
afterAll(() => api.close());

async function changedPassphrase(user: Awaited<ReturnType<typeof userWithVault>>, next = newPassphrase()) {
  const record = await fetchStoredVault(user);
  const rewrap = await changeVaultPassphrase({
    record,
    userId: user.userId,
    currentPassphrase: user.passphrase,
    newPassphrase: next,
    account: user.account,
    runner,
  });
  return { record, rewrap, next, body: rewrapToWire(rewrap.request) };
}

describe('vault passphrase change (POST /api/vault/rewrap)', () => {
  it('keeps the identity, replaces salt and ciphertexts; only the new passphrase opens the vault', async () => {
    const user = await userWithVault(api);
    const { record: before, body, next, rewrap } = await changedPassphrase(user);
    expect(JSON.stringify(body)).not.toContain(next);
    expect(JSON.stringify(body)).not.toContain(user.passphrase);
    const response = await user.browser.request('POST', '/vault/rewrap', body);
    expect(response.status).toBe(200);
    expect(typeof response.body['rewrappedAt']).toBe('string');

    const after = await fetchStoredVault(user);
    expect(after.identity.keyId).toBe(before.identity.keyId);
    expect(after.identity.fingerprint).toBe(before.identity.fingerprint);
    expect(Buffer.from(after.identity.encryptionKeySpki).equals(Buffer.from(before.identity.encryptionKeySpki))).toBe(
      true,
    );
    expect(Buffer.from(after.kdf.salt).equals(Buffer.from(before.kdf.salt))).toBe(false);
    expect(
      Buffer.from(after.wrappedEncryptionKey.ciphertext).equals(Buffer.from(before.wrappedEncryptionKey.ciphertext)),
    ).toBe(false);
    await expect(rewrap.complete(after)).resolves.toBeDefined();
    await expect(unlockVault({ record: after, userId: user.userId, passphrase: next, runner })).resolves.toBeDefined();
    await expect(
      unlockVault({ record: after, userId: user.userId, passphrase: user.passphrase, runner }),
    ).rejects.toMatchObject({ code: 'VAULT_UNLOCK_FAILED' });
  });

  it('requires a recent step-up', async () => {
    const user = await userWithVault(api);
    const { body } = await changedPassphrase(user);
    api.clock.advance(16 * 60_000);
    expect(errorCode(await user.browser.request('POST', '/vault/rewrap', body))).toBe('STEP_UP_REQUIRED');
  });

  it('refuses a request that was modified after signing, or signed by another identity', async () => {
    const user = await userWithVault(api);
    const { body } = await changedPassphrase(user);
    const flip = (s: string): string => `${s.slice(0, 30)}${s.charAt(30) === 'A' ? 'B' : 'A'}${s.slice(31)}`;
    const tampered: VaultRewrapWire[] = [
      {
        ...body,
        wrappedEncryptionKey: { ...body.wrappedEncryptionKey, ciphertext: flip(body.wrappedEncryptionKey.ciphertext) },
      },
      { ...body, kdf: { ...body.kdf, iterations: body.kdf.iterations + 1 } },
      { ...body, signature: flip(body.signature) },
    ];
    for (const request of tampered) {
      const response = await user.browser.request('POST', '/vault/rewrap', request);
      expect(response.status).toBe(403);
      expect(errorCode(response)).toBe('VAULT_SIGNATURE_INVALID');
    }
    // A signature made by another user's identity over this user's change does not count either.
    const other = await userWithVault(api);
    const foreign = await changedPassphrase(other);
    const mixed = { ...body, signature: foreign.body.signature };
    expect(errorCode(await user.browser.request('POST', '/vault/rewrap', mixed))).toBe('VAULT_SIGNATURE_INVALID');
    // Nothing changed: the original passphrase still opens the stored vault.
    const record = await fetchStoredVault(user);
    await expect(
      unlockVault({ record, userId: user.userId, passphrase: user.passphrase, runner }),
    ).resolves.toBeDefined();
  });

  it('a replayed or stale request is refused, so an old change can never be applied again', async () => {
    const user = await userWithVault(api);
    const first = await changedPassphrase(user);
    expect((await user.browser.request('POST', '/vault/rewrap', first.body)).status).toBe(200);
    // Replaying the same signed request: its previous salt is no longer current.
    const replay = await user.browser.request('POST', '/vault/rewrap', first.body);
    expect(replay.status).toBe(409);
    expect(errorCode(replay)).toBe('VAULT_CONFLICT');
    // A request for another key ID is a conflict as well.
    const other = await user.browser.request('POST', '/vault/rewrap', {
      ...first.body,
      keyId: '1d6b4f0e-2c3a-4b5d-8e9f-0a1b2c3d4e5f',
    });
    expect(errorCode(other)).toBe('VAULT_CONFLICT');
  });

  it('refuses weaker parameters and a reused salt before checking the signature', async () => {
    const user = await userWithVault(api);
    const { body, record } = await changedPassphrase(user);
    const weaker = { ...body, kdf: { ...body.kdf, memoryKiB: 32768 } };
    const downgrade = await user.browser.request('POST', '/vault/rewrap', weaker);
    expect(downgrade.status).toBe(400);
    expect(errorCode(downgrade)).toBe('INVALID_VAULT_FORMAT');
    expect(downgrade.body['error']).toMatchObject({ issues: [{ path: 'kdf', code: 'kdf_downgrade' }] });
    const sameSalt = { ...body, kdf: { ...body.kdf, salt: Buffer.from(record.kdf.salt).toString('base64url') } };
    const reused = await user.browser.request('POST', '/vault/rewrap', sameSalt);
    expect(reused.body['error']).toMatchObject({ issues: [{ path: 'kdf', code: 'salt_reused' }] });
  });

  it('upgrades the parameters of a vault with the same passphrase (ADR-010)', async () => {
    const user = await userWithVault(api);
    const record = await fetchStoredVault(user);
    const upgrade = await upgradeVaultProtection({ record, userId: user.userId, passphrase: user.passphrase, runner });
    const response = await user.browser.request('POST', '/vault/rewrap', rewrapToWire(upgrade.request));
    expect(response.status).toBe(200);
    const after = await fetchStoredVault(user);
    await expect(
      unlockVault({ record: after, userId: user.userId, passphrase: user.passphrase, runner }),
    ).resolves.toBeDefined();
  });

  it('a user without a vault gets 404', async () => {
    const owner = await userWithVault(api);
    const { body } = await changedPassphrase(owner);
    const { browser } = await vaultUser(api);
    expect(errorCode(await browser.request('POST', '/vault/rewrap', body))).toBe('VAULT_NOT_FOUND');
  });
});
