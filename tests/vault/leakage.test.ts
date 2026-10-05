import { changeVaultPassphrase, createVault, rewrapToWire, vaultRecordToWire } from '@ciphermesh/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startAuthApi, type AuthTestApi } from '../helpers/auth';
import { fetchStoredVault, newPassphrase, runner, userWithVault } from '../helpers/vault';

// INV-10 for the vault: after every vault flow, neither the API log nor the security events
// contain a passphrase, a wrapped private key, an IV or a salt. (The server never receives a
// passphrase at all; this proves the client-side values also never travel into any log line.)
let api: AuthTestApi;

beforeAll(async () => {
  api = await startAuthApi();
});
afterAll(() => api.close());

describe('vault flows leave no secret or ciphertext in logs and events', () => {
  it('setup, passphrase change, reset and lookup', async () => {
    const user = await userWithVault(api);
    const canaries = new Set<string>([user.passphrase]);
    const stored = await fetchStoredVault(user);
    const wire = vaultRecordToWire(stored);
    for (const value of [
      wire.wrappedEncryptionKey.ciphertext,
      wire.wrappedSigningKey.ciphertext,
      wire.wrappedEncryptionKey.iv,
      wire.kdf.salt,
    ]) {
      canaries.add(value);
    }

    const next = newPassphrase();
    canaries.add(next);
    const rewrap = await changeVaultPassphrase({
      record: stored,
      userId: user.userId,
      currentPassphrase: user.passphrase,
      newPassphrase: next,
      account: user.account,
      runner,
    });
    const rewrapBody = rewrapToWire(rewrap.request);
    canaries.add(rewrapBody.wrappedEncryptionKey.ciphertext);
    canaries.add(rewrapBody.signature);
    expect((await user.browser.request('POST', '/vault/rewrap', rewrapBody)).status).toBe(200);

    const resetPassphrase = newPassphrase();
    canaries.add(resetPassphrase);
    const fresh = await createVault({
      userId: user.userId,
      passphrase: resetPassphrase,
      account: user.account,
      runner,
    });
    expect((await user.browser.request('POST', '/auth/step-up', { password: user.identity.password })).status).toBe(
      200,
    );
    const resetBody = { supersedesKeyId: stored.identity.keyId, vault: vaultRecordToWire(fresh.record) };
    canaries.add(resetBody.vault.wrappedSigningKey.ciphertext);
    expect((await user.browser.request('POST', '/vault/reset', resetBody)).status).toBe(201);

    const other = await userWithVault(api);
    canaries.add(other.passphrase);
    expect((await user.browser.request('POST', '/directory/lookup', { email: other.identity.email })).status).toBe(200);

    const log = api.logText();
    const events = JSON.stringify(api.events);
    expect(log.length).toBeGreaterThan(0);
    for (const canary of canaries) {
      expect(log).not.toContain(canary);
      expect(events).not.toContain(canary);
    }
    // The catalogued events were recorded, with identifiers and counts only.
    for (const name of ['VAULT_CREATED', 'VAULT_REWRAPPED', 'VAULT_RESET']) {
      expect(api.events.some((e) => e.name === name && e.actorUserId === user.userId)).toBe(true);
    }
  });
});
