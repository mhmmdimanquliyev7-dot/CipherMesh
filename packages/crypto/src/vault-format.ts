import type { Sealed } from './aead';
import { contextBytes, type CanonicalBytes } from './contexts';
import { fromBase64Url, toBase64Url } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import type { PublicIdentity } from './identity';
import {
  AES_GCM,
  ECDSA,
  isAcceptableKdf,
  RSA_OAEP,
  SUITE,
  VAULT_KDF,
  VAULT_VERSION,
  WRAPPED_KEY_BYTES,
  type Argon2idParameters,
} from './params';
import type { Bytes } from './types';

/**
 * Vault format version 1 (docs/crypto/vault.md): the record the API stores for each identity,
 * its JSON wire form, and the re-wrap statement. Shared by the browser and the API, so both
 * validate and sign exactly the same structure. Contains no key handling and no WebCrypto calls
 * except through the shared validators, so the API can import it without browser code.
 */
export type KeyPurpose = 'encryption' | 'signing';

export interface VaultKdf extends Argon2idParameters {
  readonly algorithm: 'argon2id';
  readonly version: 19;
  readonly salt: Bytes;
}

export interface VaultRecord {
  readonly vaultVersion: typeof VAULT_VERSION;
  readonly identity: PublicIdentity;
  readonly kdf: VaultKdf;
  readonly wrappedEncryptionKey: Sealed;
  readonly wrappedSigningKey: Sealed;
}

/** JSON form of a public identity (API requests and responses). */
export interface PublicIdentityWire {
  readonly keyId: string;
  readonly suite: string;
  readonly encryptionPublicKey: string;
  readonly signingPublicKey: string;
  readonly bindingSignature: string;
  readonly fingerprint: string;
}

export interface SealedWire {
  readonly iv: string;
  readonly ciphertext: string;
}

export interface VaultKdfWire {
  readonly algorithm: string;
  readonly version: number;
  readonly memoryKiB: number;
  readonly iterations: number;
  readonly parallelism: number;
  readonly salt: string;
}

/** JSON form of a vault record. The user ID is not part of it: it comes from the session. */
export interface VaultWire {
  readonly vaultVersion: number;
  readonly identity: PublicIdentityWire;
  readonly kdf: VaultKdfWire;
  readonly wrappedEncryptionKey: SealedWire;
  readonly wrappedSigningKey: SealedWire;
}

/** JSON form of a re-wrap request (passphrase change or parameter upgrade). */
export interface VaultRewrapWire {
  readonly keyId: string;
  readonly previousKdfSalt: string;
  readonly kdf: VaultKdfWire;
  readonly wrappedEncryptionKey: SealedWire;
  readonly wrappedSigningKey: SealedWire;
  readonly signature: string;
}

const formatError = (): CryptoError => new CryptoError(CryptoErrorCode.INVALID_VAULT_FORMAT);

function decode(text: string, length?: number): Bytes {
  try {
    return fromBase64Url(text, length);
  } catch {
    throw formatError();
  }
}

function sealedFromWire(wire: SealedWire, bounds: { readonly min: number; readonly max: number }): Sealed {
  const iv = decode(wire.iv, AES_GCM.ivBytes);
  const ciphertext = decode(wire.ciphertext);
  if (ciphertext.length < bounds.min || ciphertext.length > bounds.max) throw formatError();
  return { iv, ciphertext };
}

const sealedToWire = (sealed: Sealed): SealedWire => ({
  iv: toBase64Url(sealed.iv),
  ciphertext: toBase64Url(sealed.ciphertext),
});

/** Decodes a public identity. Throws INVALID_VAULT_FORMAT; the identity is not yet verified. */
export function publicIdentityFromWire(wire: PublicIdentityWire, userId: string): PublicIdentity {
  if (wire.suite !== SUITE) throw new CryptoError(CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
  return {
    userId,
    keyId: wire.keyId,
    suite: SUITE,
    encryptionKeySpki: decode(wire.encryptionPublicKey, RSA_OAEP.spkiBytes),
    signingKeySpki: decode(wire.signingPublicKey, ECDSA.spkiBytes),
    bindingSignature: decode(wire.bindingSignature, ECDSA.signatureBytes),
    fingerprint: wire.fingerprint,
  };
}

export const publicIdentityToWire = (identity: PublicIdentity): PublicIdentityWire => ({
  keyId: identity.keyId,
  suite: identity.suite,
  encryptionPublicKey: toBase64Url(identity.encryptionKeySpki),
  signingPublicKey: toBase64Url(identity.signingKeySpki),
  bindingSignature: toBase64Url(identity.bindingSignature),
  fingerprint: identity.fingerprint,
});

/**
 * Decodes and checks the KDF section. Algorithm and version must be Argon2id 1.3; parameters
 * must lie within the floor and ceiling (a record below the floor is refused, never "repaired").
 */
export function kdfFromWire(wire: VaultKdfWire): VaultKdf {
  if (wire.algorithm !== VAULT_KDF.algorithm || wire.version !== VAULT_KDF.version) {
    throw new CryptoError(CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
  }
  const params = { memoryKiB: wire.memoryKiB, iterations: wire.iterations, parallelism: wire.parallelism };
  if (!isAcceptableKdf(params)) throw new CryptoError(CryptoErrorCode.KDF_PARAMETERS_OUT_OF_RANGE);
  return { algorithm: 'argon2id', version: 19, ...params, salt: decode(wire.salt, VAULT_KDF.saltBytes) };
}

export const kdfToWire = (kdf: VaultKdf): VaultKdfWire => ({
  algorithm: kdf.algorithm,
  version: kdf.version,
  memoryKiB: kdf.memoryKiB,
  iterations: kdf.iterations,
  parallelism: kdf.parallelism,
  salt: toBase64Url(kdf.salt),
});

/**
 * Decodes a vault record and checks its structure: version, suite, KDF, sizes. Unknown versions
 * are refused (no downgrade to a format this client cannot fully check). Throws
 * UNSUPPORTED_VAULT_VERSION, KDF_PARAMETERS_OUT_OF_RANGE or INVALID_VAULT_FORMAT, all before any
 * key derivation, so none of them says anything about the passphrase.
 */
export function vaultRecordFromWire(wire: VaultWire, userId: string): VaultRecord {
  if (wire.vaultVersion !== VAULT_VERSION) throw new CryptoError(CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);
  return {
    vaultVersion: VAULT_VERSION,
    identity: publicIdentityFromWire(wire.identity, userId),
    kdf: kdfFromWire(wire.kdf),
    wrappedEncryptionKey: sealedFromWire(wire.wrappedEncryptionKey, WRAPPED_KEY_BYTES.encryption),
    wrappedSigningKey: sealedFromWire(wire.wrappedSigningKey, WRAPPED_KEY_BYTES.signing),
  };
}

export const vaultRecordToWire = (record: VaultRecord): VaultWire => ({
  vaultVersion: record.vaultVersion,
  identity: publicIdentityToWire(record.identity),
  kdf: kdfToWire(record.kdf),
  wrappedEncryptionKey: sealedToWire(record.wrappedEncryptionKey),
  wrappedSigningKey: sealedToWire(record.wrappedSigningKey),
});

/** Decodes the wrapped keys of a re-wrap request with the same size checks as a record. */
export function rewrapFromWire(wire: VaultRewrapWire): {
  readonly previousKdfSalt: Bytes;
  readonly kdf: VaultKdf;
  readonly wrappedEncryptionKey: Sealed;
  readonly wrappedSigningKey: Sealed;
  readonly signature: Bytes;
} {
  return {
    previousKdfSalt: decode(wire.previousKdfSalt, VAULT_KDF.saltBytes),
    kdf: kdfFromWire(wire.kdf),
    wrappedEncryptionKey: sealedFromWire(wire.wrappedEncryptionKey, WRAPPED_KEY_BYTES.encryption),
    wrappedSigningKey: sealedFromWire(wire.wrappedSigningKey, WRAPPED_KEY_BYTES.signing),
    signature: decode(wire.signature, ECDSA.signatureBytes),
  };
}

/** AAD of one wrapped private key: binds it to user, key ID, purpose, identity and format. */
export function privateKeyContext(identity: PublicIdentity, purpose: KeyPurpose): CanonicalBytes {
  return contextBytes('cm.vault.private-key', {
    userId: identity.userId,
    keyId: identity.keyId,
    purpose,
    fingerprint: identity.fingerprint,
    suite: SUITE,
    vaultVersion: VAULT_VERSION,
  });
}

/**
 * The statement a re-wrap request is signed over (ADR-015 section 3). It names the salt being
 * replaced, so a captured request cannot be replayed after any later change, and it covers every
 * byte of the new record, so the server cannot store anything other than what was signed.
 */
export function rewrapStatement(fields: {
  readonly userId: string;
  readonly keyId: string;
  readonly previousKdfSalt: Bytes;
  readonly kdf: VaultKdf;
  readonly wrappedEncryptionKey: Sealed;
  readonly wrappedSigningKey: Sealed;
}): CanonicalBytes {
  return contextBytes('cm.vault.rewrap', {
    userId: fields.userId,
    keyId: fields.keyId,
    suite: SUITE,
    vaultVersion: VAULT_VERSION,
    previousKdfSalt: toBase64Url(fields.previousKdfSalt),
    kdfAlgorithm: 'argon2id',
    kdfMemoryKiB: fields.kdf.memoryKiB,
    kdfIterations: fields.kdf.iterations,
    kdfParallelism: fields.kdf.parallelism,
    kdfSalt: toBase64Url(fields.kdf.salt),
    encryptionKeyIv: toBase64Url(fields.wrappedEncryptionKey.iv),
    encryptionKeyCiphertext: toBase64Url(fields.wrappedEncryptionKey.ciphertext),
    signingKeyIv: toBase64Url(fields.wrappedSigningKey.iv),
    signingKeyCiphertext: toBase64Url(fields.wrappedSigningKey.ciphertext),
  });
}

/** JSON form of a re-wrap request built in the browser. */
export function rewrapToWire(request: {
  readonly keyId: string;
  readonly previousKdfSalt: Bytes;
  readonly kdf: VaultKdf;
  readonly wrappedEncryptionKey: Sealed;
  readonly wrappedSigningKey: Sealed;
  readonly signature: Uint8Array;
}): VaultRewrapWire {
  return {
    keyId: request.keyId,
    previousKdfSalt: toBase64Url(request.previousKdfSalt),
    kdf: kdfToWire(request.kdf),
    wrappedEncryptionKey: sealedToWire(request.wrappedEncryptionKey),
    wrappedSigningKey: sealedToWire(request.wrappedSigningKey),
    signature: toBase64Url(request.signature),
  };
}

/** True when `next` is at least as costly as `previous` in memory and passes (no downgrade). */
export function isNotWeaker(next: Argon2idParameters, previous: Argon2idParameters): boolean {
  return next.memoryKiB >= previous.memoryKiB && next.iterations >= previous.iterations;
}
