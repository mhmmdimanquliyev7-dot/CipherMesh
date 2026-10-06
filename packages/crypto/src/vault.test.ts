import { beforeAll, describe, expect, it } from 'vitest';
import { wrapPrivateKey } from './aead';
import { contextBytes } from './contexts';
import { toHex } from './encoding';
import { CryptoError, CryptoErrorCode, isCryptoError } from './errors';
import { deriveWrappingKey } from './hkdf';
import { generateIdentity, verifyPublicIdentity, type VerifiedIdentity } from './identity';
import { deriveVaultRootKey } from './kdf/derive';
import { createInProcessRunner, type KdfRunner } from './kdf/runner';
import { SUITE, VAULT_KDF, VAULT_VERSION } from './params';
import { verifyStatement } from './signing';
import type { Bytes, Key } from './types';
import { changeVaultPassphrase, createVault, unlockVault, upgradeVaultProtection } from './vault';
import {
  privateKeyContext,
  rewrapFromWire,
  rewrapStatement,
  rewrapToWire,
  vaultRecordFromWire,
  vaultRecordToWire,
  type VaultRecord,
  type VaultWire,
} from './vault-format';
import { subtle } from './webcrypto';

// The Vault (DF-03, DF-04, CM-T025 to CM-T028) with real Argon2id at the production target
// parameters (CP-04) running in-process. Nothing is weakened for speed.

const USER = '4b0c0b7e-6a5c-4d0e-9f3a-2b1c8d7e6f5a';
const OTHER_USER = '1d6b4f0e-2c3a-4b5d-8e9f-0a1b2c3d4e5f';
const account = { email: 'vault.tester@example.test', displayName: 'Vault Tester' };
const PASSPHRASE = 'tall green lamps hum softly at noon';
const NEW_PASSPHRASE = 'seven orange kites drift over quiet harbours';
const runner = createInProcessRunner();

/** What the API stores and returns: the record after a JSON round trip. */
const roundTrip = (record: VaultRecord, userId = USER): VaultRecord =>
  vaultRecordFromWire(JSON.parse(JSON.stringify(vaultRecordToWire(record))) as VaultWire, userId);

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught), String(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
}

function flip(bytes: Bytes, index: number): Bytes {
  const copy = new Uint8Array(bytes);
  copy[index] = (copy[index] ?? 0) ^ 1;
  return copy;
}

// PKCS#8 of an RSA key always contains the rsaEncryption OID, and of an EC key the id-ecPublicKey
// OID. Finding either in a wrapped key would mean the private key was stored in plaintext.
const RSA_OID = '2a864886f70d010101';
const EC_OID = '2a8648ce3d0201';

/** A runner that counts calls, to prove that some failures happen before any derivation. */
function countingRunner(): KdfRunner & { calls: number } {
  const counter = {
    calls: 0,
    run: (request: Parameters<KdfRunner['run']>[0]) => {
      counter.calls++;
      return runner.run(request);
    },
  };
  return counter;
}

let stored: VaultRecord;

beforeAll(async () => {
  const setup = await createVault({ userId: USER, passphrase: PASSPHRASE, account, runner });
  stored = roundTrip(setup.record);
}, 60_000);

describe('vault setup (DF-03, CM-T025)', () => {
  it('uploads only public keys, ciphertext and non-secret KDF metadata', async () => {
    const setup = await createVault({ userId: USER, passphrase: PASSPHRASE, account, runner });
    const { record } = setup;
    const wireText = JSON.stringify(vaultRecordToWire(record));
    expect(wireText).not.toContain(PASSPHRASE);
    expect(Object.keys(vaultRecordToWire(record)).sort()).toEqual(
      ['identity', 'kdf', 'vaultVersion', 'wrappedEncryptionKey', 'wrappedSigningKey'].sort(),
    );
    expect(record.vaultVersion).toBe(VAULT_VERSION);
    expect(record.identity.suite).toBe(SUITE);
    expect(record.kdf).toMatchObject({ algorithm: 'argon2id', version: 19, ...VAULT_KDF.target });
    expect(record.kdf.salt).toHaveLength(16);
    for (const wrapped of [record.wrappedEncryptionKey, record.wrappedSigningKey]) {
      expect(wrapped.iv).toHaveLength(12);
      expect(toHex(wrapped.ciphertext)).not.toContain(RSA_OID);
      expect(toHex(wrapped.ciphertext)).not.toContain(EC_OID);
    }
    expect(toHex(record.wrappedEncryptionKey.iv)).not.toBe(toHex(record.wrappedSigningKey.iv));
    // The public identity passes the same verification the API runs.
    await expect(verifyPublicIdentity(record.identity)).resolves.toBeDefined();
  });

  it('completes into non-extractable private keys with only their own usages', async () => {
    const setup = await createVault({ userId: USER, passphrase: PASSPHRASE, account, runner });
    const unlocked = await setup.complete(roundTrip(setup.record));
    expect(unlocked.encryptionPrivateKey.extractable).toBe(false);
    expect(unlocked.signingPrivateKey.extractable).toBe(false);
    expect([...unlocked.encryptionPrivateKey.usages].sort()).toEqual(['decrypt', 'unwrapKey']);
    expect([...unlocked.signingPrivateKey.usages]).toEqual(['sign']);
    await expect(subtle().exportKey('pkcs8', unlocked.encryptionPrivateKey)).rejects.toThrow();
    await expect(subtle().exportKey('jwk', unlocked.signingPrivateKey)).rejects.toThrow();
    // A CryptoKey serializes to nothing: no private key material can leak through JSON state.
    expect(JSON.stringify(unlocked.encryptionPrivateKey)).toBe('{}');
    expect(JSON.stringify(unlocked.signingPrivateKey)).toBe('{}');
  });

  it('completion refuses a record the server changed to another identity', async () => {
    const setup = await createVault({ userId: USER, passphrase: PASSPHRASE, account, runner });
    await expectCode(setup.complete(stored), CryptoErrorCode.IDENTITY_INVALID);
  });

  it('refuses a passphrase that fails the policy, before any derivation', async () => {
    const counting = countingRunner();
    await expectCode(
      createVault({ userId: USER, passphrase: 'too short', account, runner: counting }),
      CryptoErrorCode.PASSPHRASE_REJECTED,
    );
    expect(counting.calls).toBe(0);
  });

  it('two vaults never share a salt, an IV, a key ID or a fingerprint', async () => {
    const a = await createVault({ userId: USER, passphrase: PASSPHRASE, account, runner });
    const b = await createVault({ userId: USER, passphrase: PASSPHRASE, account, runner });
    expect(toHex(a.record.kdf.salt)).not.toBe(toHex(b.record.kdf.salt));
    expect(a.record.identity.keyId).not.toBe(b.record.identity.keyId);
    expect(a.record.identity.fingerprint).not.toBe(b.record.identity.fingerprint);
    const ivs = [a, b].flatMap((s) => [s.record.wrappedEncryptionKey.iv, s.record.wrappedSigningKey.iv]).map(toHex);
    expect(new Set(ivs).size).toBe(4);
  });
}, 120_000);

describe('vault unlock (DF-04, CM-T026)', () => {
  it('unlocks with the right passphrase, typed in any Unicode normalization form (CD-15)', async () => {
    const unlocked = await unlockVault({ record: stored, userId: USER, passphrase: PASSPHRASE, runner });
    expect(unlocked.identity.fingerprint).toBe(stored.identity.fingerprint);
    expect(unlocked.encryptionPrivateKey.extractable).toBe(false);

    const composed = 'café crème brûlée at midnight';
    const setup = await createVault({ userId: USER, passphrase: composed.normalize('NFC'), account, runner });
    const record = roundTrip(setup.record);
    await expect(
      unlockVault({ record, userId: USER, passphrase: composed.normalize('NFD'), runner }),
    ).resolves.toBeDefined();
  });

  it('a wrong passphrase gives the generic VAULT_UNLOCK_FAILED', async () => {
    await expectCode(
      unlockVault({ record: stored, userId: USER, passphrase: `${PASSPHRASE}!`, runner }),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
    await expectCode(
      unlockVault({ record: stored, userId: USER, passphrase: 'short', runner }),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
  });

  it('any modified byte of a wrapped key, its IV or its tag gives the same generic failure', async () => {
    const enc = stored.wrappedEncryptionKey;
    const sig = stored.wrappedSigningKey;
    const tampered: VaultRecord[] = [
      { ...stored, wrappedEncryptionKey: { ...enc, ciphertext: flip(enc.ciphertext, 0) } },
      { ...stored, wrappedEncryptionKey: { ...enc, ciphertext: flip(enc.ciphertext, enc.ciphertext.length - 1) } },
      { ...stored, wrappedEncryptionKey: { ...enc, iv: flip(enc.iv, 3) } },
      { ...stored, wrappedSigningKey: { ...sig, ciphertext: flip(sig.ciphertext, 40) } },
      { ...stored, wrappedSigningKey: { ...sig, iv: flip(sig.iv, 0) } },
    ];
    for (const record of tampered) {
      await expectCode(
        unlockVault({ record, userId: USER, passphrase: PASSPHRASE, runner }),
        CryptoErrorCode.VAULT_UNLOCK_FAILED,
      );
    }
  });

  it('swapping the two wrapped keys fails: each key is bound to its purpose (AAD and HKDF info)', async () => {
    // Sizes differ, so the swap is rejected structurally; swap the IVs instead, which keeps sizes.
    const swappedIvs: VaultRecord = {
      ...stored,
      wrappedEncryptionKey: { ...stored.wrappedEncryptionKey, iv: stored.wrappedSigningKey.iv },
      wrappedSigningKey: { ...stored.wrappedSigningKey, iv: stored.wrappedEncryptionKey.iv },
    };
    await expectCode(
      unlockVault({ record: swappedIvs, userId: USER, passphrase: PASSPHRASE, runner }),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
  });

  it('a changed salt or changed parameters derive another key and fail', async () => {
    const otherSalt: VaultRecord = { ...stored, kdf: { ...stored.kdf, salt: flip(stored.kdf.salt, 0) } };
    const otherPasses: VaultRecord = { ...stored, kdf: { ...stored.kdf, iterations: stored.kdf.iterations + 1 } };
    for (const record of [otherSalt, otherPasses]) {
      await expectCode(
        unlockVault({ record, userId: USER, passphrase: PASSPHRASE, runner }),
        CryptoErrorCode.VAULT_UNLOCK_FAILED,
      );
    }
  });

  it('a server that substitutes another valid public identity cannot get the vault opened', async () => {
    // The attacker's identity is valid on its own, but the fingerprint in the AAD no longer matches.
    const attacker = await generateIdentity(USER);
    const substituted: VaultRecord = { ...stored, identity: attacker.identity };
    await expectCode(
      unlockVault({ record: substituted, userId: USER, passphrase: PASSPHRASE, runner }),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
  });

  it("an invalid public identity or another user's record is refused before any derivation", async () => {
    const counting = countingRunner();
    const badBinding: VaultRecord = {
      ...stored,
      identity: { ...stored.identity, bindingSignature: flip(stored.identity.bindingSignature, 7) },
    };
    await expectCode(
      unlockVault({ record: badBinding, userId: USER, passphrase: PASSPHRASE, runner: counting }),
      CryptoErrorCode.IDENTITY_INVALID,
    );
    const otherUsers = roundTrip(stored, OTHER_USER);
    await expectCode(
      unlockVault({ record: otherUsers, userId: USER, passphrase: PASSPHRASE, runner: counting }),
      CryptoErrorCode.INVALID_VAULT_FORMAT,
    );
    expect(counting.calls).toBe(0);
  });

  it('refuses a second derivation while one is running', async () => {
    // Both calls verify the record with WebCrypto before their derivation starts, and those steps
    // finish in no guaranteed order, so either call can be the one that derives first. The runner
    // therefore holds whichever derivation starts first until it is released: the other call must
    // be refused while it is held, with no timing assumption (this test failed intermittently when
    // it assumed that the first call always wins the race).
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const held: KdfRunner = {
      run: async (request) => {
        await gate;
        return runner.run(request);
      },
    };
    const calls = [
      unlockVault({ record: stored, userId: USER, passphrase: PASSPHRASE, runner: held }),
      unlockVault({ record: stored, userId: USER, passphrase: PASSPHRASE, runner: held }),
    ];
    // Neither call can finish before the release, so the first outcome is the refusal.
    const refusal = await Promise.race(
      calls.map((call) =>
        call.then(
          () => 'opened' as const,
          (error: unknown) => error,
        ),
      ),
    );
    expect(isCryptoError(refusal), String(refusal)).toBe(true);
    expect((refusal as { code: string }).code).toBe(CryptoErrorCode.KDF_BUSY);
    release();
    const outcomes = await Promise.allSettled(calls);
    expect(outcomes.filter((o) => o.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.filter((o) => o.status === 'rejected')).toHaveLength(1);
  });
}, 120_000);

describe('vault format (version 1): structural refusals before derivation', () => {
  const wire = (): VaultWire => JSON.parse(JSON.stringify(vaultRecordToWire(stored))) as VaultWire;
  const refused = (mutate: (w: VaultWire) => VaultWire, code: string): void => {
    let caught: unknown;
    try {
      vaultRecordFromWire(mutate(wire()), USER);
    } catch (error) {
      caught = error;
    }
    expect(isCryptoError(caught), JSON.stringify(mutate(wire()).kdf)).toBe(true);
    expect((caught as { code: string }).code).toBe(code);
  };

  it('refuses unknown versions and suites (no downgrade) and foreign KDFs', () => {
    refused((w) => ({ ...w, vaultVersion: 2 }), CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
    refused((w) => ({ ...w, vaultVersion: 0 }), CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
    refused((w) => ({ ...w, identity: { ...w.identity, suite: 'CM0' } }), CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
    refused((w) => ({ ...w, kdf: { ...w.kdf, algorithm: 'pbkdf2' } }), CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
    refused((w) => ({ ...w, kdf: { ...w.kdf, version: 16 } }), CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
  });

  it('refuses parameters below the floor or above the ceiling', () => {
    refused((w) => ({ ...w, kdf: { ...w.kdf, memoryKiB: 19455 } }), CryptoErrorCode.KDF_PARAMETERS_OUT_OF_RANGE);
    refused((w) => ({ ...w, kdf: { ...w.kdf, iterations: 1 } }), CryptoErrorCode.KDF_PARAMETERS_OUT_OF_RANGE);
    refused((w) => ({ ...w, kdf: { ...w.kdf, memoryKiB: 4_194_304 } }), CryptoErrorCode.KDF_PARAMETERS_OUT_OF_RANGE);
  });

  it('refuses malformed sizes and encodings', () => {
    refused((w) => ({ ...w, kdf: { ...w.kdf, salt: w.kdf.salt.slice(0, 20) } }), CryptoErrorCode.INVALID_VAULT_FORMAT);
    refused(
      (w) => ({ ...w, wrappedSigningKey: { ...w.wrappedSigningKey, iv: 'AAAA' } }),
      CryptoErrorCode.INVALID_VAULT_FORMAT,
    );
    refused(
      (w) => ({ ...w, wrappedEncryptionKey: { ...w.wrappedEncryptionKey, ciphertext: 'AAAA' } }),
      CryptoErrorCode.INVALID_VAULT_FORMAT,
    );
    refused(
      (w) => ({ ...w, identity: { ...w.identity, encryptionPublicKey: `${w.identity.encryptionPublicKey}=` } }),
      CryptoErrorCode.INVALID_VAULT_FORMAT,
    );
  });
});

describe('passphrase change and signed re-wrap (CM-T028, ADR-015 section 3)', () => {
  it('keeps the identity, replaces salt and ciphertext, and only the new passphrase opens the result', async () => {
    const rewrap = await changeVaultPassphrase({
      record: stored,
      userId: USER,
      currentPassphrase: PASSPHRASE,
      newPassphrase: NEW_PASSPHRASE,
      account,
      runner,
    });
    const { request } = rewrap;
    expect(request.keyId).toBe(stored.identity.keyId);
    expect(toHex(request.previousKdfSalt)).toBe(toHex(stored.kdf.salt));
    expect(toHex(request.kdf.salt)).not.toBe(toHex(stored.kdf.salt));
    expect(toHex(request.wrappedEncryptionKey.ciphertext)).not.toBe(toHex(stored.wrappedEncryptionKey.ciphertext));
    expect(toHex(request.wrappedSigningKey.iv)).not.toBe(toHex(stored.wrappedSigningKey.iv));
    expect(JSON.stringify(rewrapToWire(request))).not.toContain(NEW_PASSPHRASE);

    // What the server stores: the same public identity with the new KDF section and ciphertexts.
    const updated = roundTrip({ ...stored, ...request, identity: stored.identity });
    const reopened = await rewrap.complete(updated);
    expect(reopened.identity.fingerprint).toBe(stored.identity.fingerprint);
    await expect(
      unlockVault({ record: updated, userId: USER, passphrase: NEW_PASSPHRASE, runner }),
    ).resolves.toBeDefined();
    await expectCode(
      unlockVault({ record: updated, userId: USER, passphrase: PASSPHRASE, runner }),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
  });

  it('the signature covers every field, and the server can verify it with the stored public key', async () => {
    const { request } = await changeVaultPassphrase({
      record: stored,
      userId: USER,
      currentPassphrase: PASSPHRASE,
      newPassphrase: NEW_PASSPHRASE,
      account,
      runner,
    });
    const decoded = rewrapFromWire(
      JSON.parse(JSON.stringify(rewrapToWire(request))) as ReturnType<typeof rewrapToWire>,
    );
    const identity = await verifyPublicIdentity(stored.identity);
    const statement = (fields: typeof decoded) =>
      rewrapStatement({ userId: USER, keyId: stored.identity.keyId, ...fields });
    expect(await verifyStatement(identity.signingPublicKey, statement(decoded), decoded.signature)).toBe(true);
    const variants: (typeof decoded)[] = [
      { ...decoded, previousKdfSalt: flip(decoded.previousKdfSalt, 0) },
      { ...decoded, kdf: { ...decoded.kdf, iterations: decoded.kdf.iterations + 1 } },
      { ...decoded, kdf: { ...decoded.kdf, salt: flip(decoded.kdf.salt, 1) } },
      {
        ...decoded,
        wrappedEncryptionKey: {
          ...decoded.wrappedEncryptionKey,
          ciphertext: flip(decoded.wrappedEncryptionKey.ciphertext, 9),
        },
      },
      { ...decoded, wrappedSigningKey: { ...decoded.wrappedSigningKey, iv: flip(decoded.wrappedSigningKey.iv, 2) } },
    ];
    for (const variant of variants) {
      expect(await verifyStatement(identity.signingPublicKey, statement(variant), decoded.signature)).toBe(false);
    }
    // Another user's statement with the same fields does not verify either.
    expect(
      await verifyStatement(
        identity.signingPublicKey,
        rewrapStatement({ userId: OTHER_USER, keyId: stored.identity.keyId, ...decoded }),
        decoded.signature,
      ),
    ).toBe(false);
  });

  it('a wrong current passphrase produces no request', async () => {
    await expectCode(
      changeVaultPassphrase({
        record: stored,
        userId: USER,
        currentPassphrase: 'not the right passphrase at all',
        newPassphrase: NEW_PASSPHRASE,
        account,
        runner,
      }),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
  });

  it('a new passphrase that fails the policy is refused before any derivation', async () => {
    const counting = countingRunner();
    await expectCode(
      changeVaultPassphrase({
        record: stored,
        userId: USER,
        currentPassphrase: PASSPHRASE,
        newPassphrase: 'short',
        account,
        runner: counting,
      }),
      CryptoErrorCode.PASSPHRASE_REJECTED,
    );
    expect(counting.calls).toBe(0);
  });
}, 120_000);

describe('parameter upgrade (ADR-010)', () => {
  it('re-wraps a floor-parameter vault under the target with the same passphrase', async () => {
    // Fixture: a vault written with the floor parameters, built from the same primitives.
    const { identity, encryptionPrivateKey, signingPrivateKey } = await generateIdentity(USER);
    const salt = new Uint8Array(16).fill(9);
    const root = await deriveVaultRootKey(runner, PASSPHRASE, salt, VAULT_KDF.floor);
    const wrappingKey = (purpose: 'encryption' | 'signing') =>
      deriveWrappingKey(root, contextBytes('cm.vault.pk-wrap', { userId: USER, keyId: identity.keyId, purpose }));
    const old: VaultRecord = {
      vaultVersion: VAULT_VERSION,
      identity,
      kdf: { algorithm: 'argon2id', version: 19, ...VAULT_KDF.floor, salt },
      wrappedEncryptionKey: await wrapPrivateKey(
        encryptionPrivateKey,
        await wrappingKey('encryption'),
        privateKeyContext(identity, 'encryption'),
      ),
      wrappedSigningKey: await wrapPrivateKey(
        signingPrivateKey,
        await wrappingKey('signing'),
        privateKeyContext(identity, 'signing'),
      ),
    };
    const oldStored = roundTrip(old);
    await expect(
      unlockVault({ record: oldStored, userId: USER, passphrase: PASSPHRASE, runner }),
    ).resolves.toBeDefined();

    const upgrade = await upgradeVaultProtection({ record: oldStored, userId: USER, passphrase: PASSPHRASE, runner });
    expect(upgrade.request.kdf).toMatchObject(VAULT_KDF.target);
    const upgraded = roundTrip({ ...oldStored, ...upgrade.request, identity: oldStored.identity });
    await expect(upgrade.complete(upgraded)).resolves.toBeDefined();
    await expect(
      unlockVault({ record: upgraded, userId: USER, passphrase: PASSPHRASE, runner }),
    ).resolves.toBeDefined();
  });
}, 120_000);

describe('defence in depth inside unlock and re-wrap', () => {
  /** A vault for `identity` whose wrapped keys hold `keys`, built from the same primitives. */
  async function craft(
    identity: VerifiedIdentity,
    keys: { readonly encryptionPrivateKey: Key; readonly signingPrivateKey: Key },
  ): Promise<VaultRecord> {
    const salt = new Uint8Array(16).fill(11);
    const root = await deriveVaultRootKey(runner, PASSPHRASE, salt, VAULT_KDF.floor);
    const wrappingKey = (purpose: 'encryption' | 'signing') =>
      deriveWrappingKey(root, contextBytes('cm.vault.pk-wrap', { userId: USER, keyId: identity.keyId, purpose }));
    return roundTrip({
      vaultVersion: VAULT_VERSION,
      identity,
      kdf: { algorithm: 'argon2id', version: 19, ...VAULT_KDF.floor, salt },
      wrappedEncryptionKey: await wrapPrivateKey(
        keys.encryptionPrivateKey,
        await wrappingKey('encryption'),
        privateKeyContext(identity, 'encryption'),
      ),
      wrappedSigningKey: await wrapPrivateKey(
        keys.signingPrivateKey,
        await wrappingKey('signing'),
        privateKeyContext(identity, 'signing'),
      ),
    });
  }

  it('the pair checks refuse private keys of another identity even when every AAD matches', async () => {
    const real = await generateIdentity(USER);
    const foreign = await generateIdentity(USER);
    const unlock = (record: VaultRecord) => unlockVault({ record, userId: USER, passphrase: PASSPHRASE, runner });
    // Control: the crafted record with the identity's own keys opens.
    await expect(unlock(await craft(real.identity, real))).resolves.toBeDefined();
    // Foreign encryption key: the RSA-OAEP round trip fails.
    await expectCode(
      unlock(await craft(real.identity, { ...real, encryptionPrivateKey: foreign.encryptionPrivateKey })),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
    // Foreign signing key: the RSA check passes, the signature check does not.
    await expectCode(
      unlock(await craft(real.identity, { ...real, signingPrivateKey: foreign.signingPrivateKey })),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
  });

  it('an in-memory record with another format version or out-of-range parameters is refused without deriving', async () => {
    const counting = countingRunner();
    const future = { ...stored, vaultVersion: 2 } as unknown as VaultRecord;
    await expectCode(
      unlockVault({ record: future, userId: USER, passphrase: PASSPHRASE, runner: counting }),
      CryptoErrorCode.UNSUPPORTED_VAULT_VERSION,
    );
    const tiny: VaultRecord = { ...stored, kdf: { ...stored.kdf, memoryKiB: 64 } };
    await expectCode(
      unlockVault({ record: tiny, userId: USER, passphrase: PASSPHRASE, runner: counting }),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
    expect(counting.calls).toBe(0);
  });

  it('environment failures pass through unchanged, so a broken browser is not reported as a wrong passphrase', async () => {
    const failing = (error: Error): KdfRunner => ({ run: () => Promise.reject(error) });
    for (const code of [CryptoErrorCode.KDF_FAILED, CryptoErrorCode.UNAVAILABLE]) {
      const runner = failing(new CryptoError(code));
      await expectCode(unlockVault({ record: stored, userId: USER, passphrase: PASSPHRASE, runner }), code);
      await expectCode(
        changeVaultPassphrase({
          record: stored,
          userId: USER,
          currentPassphrase: PASSPHRASE,
          newPassphrase: NEW_PASSPHRASE,
          account,
          runner,
        }),
        code,
      );
    }
    // Anything else stays the generic failure.
    await expectCode(
      changeVaultPassphrase({
        record: stored,
        userId: USER,
        currentPassphrase: PASSPHRASE,
        newPassphrase: NEW_PASSPHRASE,
        account,
        runner: failing(new Error('unexpected')),
      }),
      CryptoErrorCode.VAULT_UNLOCK_FAILED,
    );
  });

  it('completing a re-wrap refuses a stored record of another identity', async () => {
    const change = await changeVaultPassphrase({
      record: stored,
      userId: USER,
      currentPassphrase: PASSPHRASE,
      newPassphrase: NEW_PASSPHRASE,
      account,
      runner,
    });
    const other = roundTrip((await createVault({ userId: USER, passphrase: NEW_PASSPHRASE, account, runner })).record);
    await expectCode(change.complete(other), CryptoErrorCode.IDENTITY_INVALID);
  });
}, 120_000);
