import { unwrapPrivateKey, wrapPrivateKey, type UnwrapTarget } from './aead';
import { contextBytes } from './contexts';
import { bytesEqual, toBase64Url, utf8Encode, wipe } from './encoding';
import { CryptoError, CryptoErrorCode, isCryptoError } from './errors';
import { deriveWrappingKey } from './hkdf';
import { generateIdentity, verifyPublicIdentity, type VerifiedIdentity } from './identity';
import { deriveVaultRootKey } from './kdf/derive';
import type { KdfRunner } from './kdf/runner';
import { ECDSA, RSA_OAEP, SUITE, VAULT_KDF, VAULT_VERSION, type Argon2idParameters } from './params';
import { checkVaultPassphrase, normalizeVaultPassphrase } from './passphrase';
import { randomBytes } from './random';
import { unwrap32, wrap32 } from './rsa-oaep';
import { signStatement, verifyStatement } from './signing';
import type { Key } from './types';
import { privateKeyContext, rewrapStatement, type KeyPurpose, type VaultKdf, type VaultRecord } from './vault-format';

/**
 * The Vault (cryptographic-architecture section 5, ADR-015, docs/crypto/vault.md).
 *
 *   VRK  = Argon2id(NFKC(Vault Passphrase), salt, params)          in a Web Worker, never stored
 *   PKWK_purpose = HKDF-SHA-256(VRK, info = cm.vault.pk-wrap {userId, keyId, purpose})
 *   wrapped_purpose = AES-256-GCM-wrap(PKCS#8 private key, PKWK_purpose, fresh IV,
 *                     AAD = cm.vault.private-key {userId, keyId, purpose, fingerprint, suite, vaultVersion})
 *
 * One wrapping key per private key, each used for exactly one encryption per vault write, so an
 * IV can never repeat under the same key. The private keys are wrapped and unwrapped inside
 * WebCrypto: their PKCS#8 bytes never appear in JavaScript. After unlock they are
 * non-extractable and live only in memory; nothing unlocked is ever written to browser storage
 * (INV-01). The Vault Passphrase, VRK and the wrapping keys never leave the browser.
 */
export interface UnlockedVault {
  readonly identity: VerifiedIdentity;
  /** RSA-OAEP private key: non-extractable, usages decrypt and unwrapKey. */
  readonly encryptionPrivateKey: Key;
  /** ECDSA private key: non-extractable, usage sign. */
  readonly signingPrivateKey: Key;
}

interface WrappingKeys {
  readonly encryption: Key;
  readonly signing: Key;
}

const UNWRAP_TARGETS: Readonly<Record<KeyPurpose, UnwrapTarget>> = {
  encryption: { algorithm: { name: RSA_OAEP.name, hash: RSA_OAEP.hash }, usages: ['decrypt', 'unwrapKey'] },
  signing: { algorithm: { name: ECDSA.name, namedCurve: ECDSA.namedCurve }, usages: ['sign'] },
};

/**
 * The library documents a minimum of 8 password bytes but does not enforce it (LIB-03 review), so
 * shorter input is refused here, before any derivation. No valid passphrase is that short: the
 * CP-06 minimum is 16 code points.
 */
const MIN_PASSPHRASE_BYTES = 8;

const unlockFailed = (): CryptoError => new CryptoError(CryptoErrorCode.VAULT_UNLOCK_FAILED);

/** Errors that say nothing about the passphrase and are worth showing as they are. */
const isEnvironmentError = (error: unknown): boolean =>
  isCryptoError(error, CryptoErrorCode.UNAVAILABLE) ||
  isCryptoError(error, CryptoErrorCode.KDF_BUSY) ||
  isCryptoError(error, CryptoErrorCode.KDF_FAILED);

async function deriveWrappingKeys(
  runner: KdfRunner,
  normalizedPassphrase: string,
  kdf: VaultKdf,
  userId: string,
  keyId: string,
): Promise<WrappingKeys> {
  return wrappingKeysFromRoot(await deriveVaultRootKey(runner, normalizedPassphrase, kdf.salt, kdf), userId, keyId);
}

async function wrappingKeysFromRoot(vaultRootKey: Key, userId: string, keyId: string): Promise<WrappingKeys> {
  const [encryption, signing] = await Promise.all([
    deriveWrappingKey(vaultRootKey, contextBytes('cm.vault.pk-wrap', { userId, keyId, purpose: 'encryption' })),
    deriveWrappingKey(vaultRootKey, contextBytes('cm.vault.pk-wrap', { userId, keyId, purpose: 'signing' })),
  ]);
  return { encryption, signing };
}

/**
 * Checks that the unwrapped private keys belong to the public keys: an RSA-OAEP round trip of a
 * random 32-byte value (INV-17) and an ECDSA signature over a random challenge. Together with the
 * fingerprint in the AAD, this detects a server that returns public keys not matching the vault.
 */
async function checkKeyPairs(identity: VerifiedIdentity, encryptionKey: Key, signingKey: Key): Promise<void> {
  const ids = { userId: identity.userId, keyId: identity.keyId };
  const value = randomBytes(RSA_OAEP.wrappedValueBytes);
  const label = contextBytes('cm.vault.pair-check', { ...ids, suite: SUITE });
  const recovered = await unwrap32(encryptionKey, await wrap32(identity.encryptionPublicKey, value, label), label);
  const encryptionMatches = bytesEqual(value, recovered);
  wipe(value, recovered);
  const statement = contextBytes('cm.vault.signing-check', { ...ids, challenge: toBase64Url(randomBytes(32)) });
  const signingMatches = await verifyStatement(
    identity.signingPublicKey,
    statement,
    await signStatement(signingKey, statement),
  );
  if (!encryptionMatches || !signingMatches) throw unlockFailed();
}

/** Unwraps both private keys and checks them. Every failure is the generic VAULT_UNLOCK_FAILED. */
async function openWithKeys(
  record: VaultRecord,
  identity: VerifiedIdentity,
  keys: WrappingKeys,
  extractable: boolean,
): Promise<UnlockedVault> {
  try {
    const [encryptionPrivateKey, signingPrivateKey] = await Promise.all([
      unwrapPrivateKey(
        record.wrappedEncryptionKey,
        keys.encryption,
        privateKeyContext(identity, 'encryption'),
        UNWRAP_TARGETS.encryption,
        extractable,
      ),
      unwrapPrivateKey(
        record.wrappedSigningKey,
        keys.signing,
        privateKeyContext(identity, 'signing'),
        UNWRAP_TARGETS.signing,
        extractable,
      ),
    ]);
    await checkKeyPairs(identity, encryptionPrivateKey, signingPrivateKey);
    return { identity, encryptionPrivateKey, signingPrivateKey };
  } catch {
    throw unlockFailed();
  }
}

/** Checks that a record belongs to `userId` and verifies its public identity. */
async function verifyRecordIdentity(record: VaultRecord, userId: string): Promise<VerifiedIdentity> {
  // Untrusted input may carry any version whatever its static type says (no downgrade).
  const version: number = record.vaultVersion;
  if (version !== VAULT_VERSION) throw new CryptoError(CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
  if (record.identity.userId !== userId) throw new CryptoError(CryptoErrorCode.INVALID_VAULT_FORMAT);
  return verifyPublicIdentity(record.identity);
}

function normalizeForUnlock(passphrase: string): string {
  const normalized = normalizeVaultPassphrase(passphrase);
  if (normalized === undefined || utf8Encode(normalized).length < MIN_PASSPHRASE_BYTES) throw unlockFailed();
  return normalized;
}

async function wrapBoth(
  identity: VerifiedIdentity,
  keys: WrappingKeys,
  encryptionPrivateKey: Key,
  signingPrivateKey: Key,
): Promise<Pick<VaultRecord, 'wrappedEncryptionKey' | 'wrappedSigningKey'>> {
  const [wrappedEncryptionKey, wrappedSigningKey] = await Promise.all([
    wrapPrivateKey(encryptionPrivateKey, keys.encryption, privateKeyContext(identity, 'encryption')),
    wrapPrivateKey(signingPrivateKey, keys.signing, privateKeyContext(identity, 'signing')),
  ]);
  return { wrappedEncryptionKey, wrappedSigningKey };
}

const newKdf = (params: Argon2idParameters): VaultKdf => ({
  algorithm: 'argon2id',
  version: 19,
  memoryKiB: params.memoryKiB,
  iterations: params.iterations,
  parallelism: params.parallelism,
  salt: randomBytes(VAULT_KDF.saltBytes),
});

// ------------------------------------------------------------------------------------- setup

export interface VaultSetup {
  /** What is uploaded: public identity, KDF parameters and salt, and the two wrapped keys. */
  readonly record: VaultRecord;
  /**
   * Opens the record the server stored with the keys derived during setup, as non-extractable
   * keys. This proves the round trip without a second Argon2id run; the extractable originals
   * are dropped with this function's scope.
   */
  readonly complete: (stored: VaultRecord) => Promise<UnlockedVault>;
}

/**
 * Creates a new identity and its vault (DF-03). Used for first setup and for a vault reset after
 * a lost passphrase. Throws PASSPHRASE_REJECTED if the passphrase fails the policy (the caller
 * shows checkVaultPassphrase() problems before calling).
 */
export async function createVault(input: {
  readonly userId: string;
  readonly passphrase: string;
  readonly account: { readonly email: string; readonly displayName: string };
  readonly runner: KdfRunner;
}): Promise<VaultSetup> {
  const check = checkVaultPassphrase(input.passphrase, input.account);
  if (!check.ok) throw new CryptoError(CryptoErrorCode.PASSPHRASE_REJECTED);
  const kdf = newKdf(VAULT_KDF.target);
  // Key generation (WebCrypto) and Argon2id (worker) run at the same time; only the HKDF step
  // needs the key ID of the new identity.
  const [generated, vaultRootKey] = await Promise.all([
    generateIdentity(input.userId),
    deriveVaultRootKey(input.runner, check.normalized, kdf.salt, kdf),
  ]);
  const keys = await wrappingKeysFromRoot(vaultRootKey, input.userId, generated.identity.keyId);
  const wrapped = await wrapBoth(generated.identity, keys, generated.encryptionPrivateKey, generated.signingPrivateKey);
  const record: VaultRecord = {
    vaultVersion: VAULT_VERSION,
    identity: publicOnly(generated.identity),
    kdf,
    ...wrapped,
  };
  return {
    record,
    complete: async (stored) => {
      const identity = await verifyRecordIdentity(stored, input.userId);
      if (identity.fingerprint !== record.identity.fingerprint) throw new CryptoError(CryptoErrorCode.IDENTITY_INVALID);
      return openWithKeys(stored, identity, keys, false);
    },
  };
}

const publicOnly = (identity: VerifiedIdentity): VaultRecord['identity'] => ({
  userId: identity.userId,
  keyId: identity.keyId,
  suite: identity.suite,
  encryptionKeySpki: identity.encryptionKeySpki,
  signingKeySpki: identity.signingKeySpki,
  bindingSignature: identity.bindingSignature,
  fingerprint: identity.fingerprint,
});

// ------------------------------------------------------------------------------------ unlock

/**
 * Unlocks a vault (DF-04): structural checks, public identity verification, Argon2id, unwrap as
 * non-extractable keys, pair checks. A wrong passphrase, a modified ciphertext, IV or AAD, and a
 * key mismatch all produce the same VAULT_UNLOCK_FAILED. Unlock attempts are local; the server
 * never learns about them.
 */
export async function unlockVault(input: {
  readonly record: VaultRecord;
  readonly userId: string;
  readonly passphrase: string;
  readonly runner: KdfRunner;
}): Promise<UnlockedVault> {
  const identity = await verifyRecordIdentity(input.record, input.userId);
  const normalized = normalizeForUnlock(input.passphrase);
  let keys: WrappingKeys;
  try {
    keys = await deriveWrappingKeys(input.runner, normalized, input.record.kdf, input.userId, identity.keyId);
  } catch (error) {
    if (isEnvironmentError(error)) throw error;
    throw unlockFailed();
  }
  return openWithKeys(input.record, identity, keys, false);
}

// ------------------------------------------------------------------------- re-wrap (CM-T028)

export interface VaultRewrapRequest {
  readonly keyId: string;
  readonly previousKdfSalt: VaultKdf['salt'];
  readonly kdf: VaultKdf;
  readonly wrappedEncryptionKey: VaultRecord['wrappedEncryptionKey'];
  readonly wrappedSigningKey: VaultRecord['wrappedSigningKey'];
  /** ECDSA signature by the identity over cm.vault.rewrap (ADR-015 section 3). */
  readonly signature: Uint8Array;
}

export interface VaultRewrap {
  readonly request: VaultRewrapRequest;
  /** Opens the record the server stored afterwards with the new keys, as non-extractable keys. */
  readonly complete: (stored: VaultRecord) => Promise<UnlockedVault>;
}

/** The stronger of the stored parameters and the current target: a re-wrap never weakens. */
const strongest = (stored: Argon2idParameters): Argon2idParameters => ({
  memoryKiB: Math.max(stored.memoryKiB, VAULT_KDF.target.memoryKiB),
  iterations: Math.max(stored.iterations, VAULT_KDF.target.iterations),
  parallelism: VAULT_KDF.target.parallelism,
});

async function rewrap(
  record: VaultRecord,
  userId: string,
  currentPassphrase: string,
  nextNormalized: string,
  runner: KdfRunner,
): Promise<VaultRewrap> {
  const identity = await verifyRecordIdentity(record, userId);
  const current = normalizeForUnlock(currentPassphrase);
  let oldKeys: WrappingKeys;
  try {
    oldKeys = await deriveWrappingKeys(runner, current, record.kdf, userId, identity.keyId);
  } catch (error) {
    if (isEnvironmentError(error)) throw error;
    throw unlockFailed();
  }
  // Extractable only here and only for this function: the same keys are wrapped again.
  const opened = await openWithKeys(record, identity, oldKeys, true);
  const kdf = newKdf(strongest(record.kdf));
  const newKeys = await deriveWrappingKeys(runner, nextNormalized, kdf, userId, identity.keyId);
  const wrapped = await wrapBoth(identity, newKeys, opened.encryptionPrivateKey, opened.signingPrivateKey);
  const fields = { userId, keyId: identity.keyId, previousKdfSalt: record.kdf.salt, kdf, ...wrapped };
  const signature = await signStatement(opened.signingPrivateKey, rewrapStatement(fields));
  return {
    request: { keyId: identity.keyId, previousKdfSalt: record.kdf.salt, kdf, ...wrapped, signature },
    complete: async (stored) => {
      const storedIdentity = await verifyRecordIdentity(stored, userId);
      if (storedIdentity.fingerprint !== identity.fingerprint) throw new CryptoError(CryptoErrorCode.IDENTITY_INVALID);
      return openWithKeys(stored, storedIdentity, newKeys, false);
    },
  };
}

/**
 * Vault Passphrase change (CM-T028, DF-04 variant): the current passphrase opens the vault, a new
 * salt and the new passphrase derive new wrapping keys, and the SAME private keys are wrapped
 * again. The identity, its key ID and its fingerprint do not change. This does not protect
 * against someone who already holds the old encrypted record and the old passphrase; that needs
 * a vault reset (new identity).
 */
export async function changeVaultPassphrase(input: {
  readonly record: VaultRecord;
  readonly userId: string;
  readonly currentPassphrase: string;
  readonly newPassphrase: string;
  readonly account: { readonly email: string; readonly displayName: string };
  readonly runner: KdfRunner;
}): Promise<VaultRewrap> {
  const check = checkVaultPassphrase(input.newPassphrase, input.account);
  if (!check.ok) throw new CryptoError(CryptoErrorCode.PASSPHRASE_REJECTED);
  return rewrap(input.record, input.userId, input.currentPassphrase, check.normalized, input.runner);
}

/**
 * Re-wraps with the same passphrase under the current target parameters, for vaults whose stored
 * parameters are below the target (ADR-010). The passphrase policy is not re-applied: a stronger
 * KDF must never be blocked because the policy changed after the passphrase was chosen.
 */
export async function upgradeVaultProtection(input: {
  readonly record: VaultRecord;
  readonly userId: string;
  readonly passphrase: string;
  readonly runner: KdfRunner;
}): Promise<VaultRewrap> {
  return rewrap(input.record, input.userId, input.passphrase, normalizeForUnlock(input.passphrase), input.runner);
}
