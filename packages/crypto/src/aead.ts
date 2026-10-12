import type { CanonicalBytes } from './contexts';
import { CryptoError, CryptoErrorCode } from './errors';
import { aesGcmDecryptWithIv, aesGcmEncryptWithIv } from './internal/raw';
import { AES_GCM } from './params';
import { randomBytes } from './random';
import type { Bytes, Key } from './types';
import { guarded, subtle } from './webcrypto';

/**
 * AES-256-GCM (CP-01, ADR-003). The IV is generated here from the CSPRNG for every operation and
 * returned with the ciphertext; no function accepts an IV for encryption, so a caller cannot
 * reuse one (INV-02). The AAD must be a canonical context, so every ciphertext is bound to its
 * purpose and identifiers. Decryption fails closed: nothing is returned unless the tag verifies.
 */
export interface Sealed {
  /** 96-bit IV, not secret, stored next to the ciphertext. */
  readonly iv: Bytes;
  /** Ciphertext followed by the 128-bit tag. */
  readonly ciphertext: Bytes;
}

const requireContext = (aad: CanonicalBytes): void => {
  if (!(aad instanceof Uint8Array) || aad.length === 0) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
};

const requireSealed = (sealed: Sealed): void => {
  if (sealed.iv.length !== AES_GCM.ivBytes || sealed.ciphertext.length < AES_GCM.tagBytes) {
    throw new CryptoError(CryptoErrorCode.AUTHENTICATION_FAILED);
  }
};

export async function encrypt(key: Key, plaintext: Bytes, aad: CanonicalBytes): Promise<Sealed> {
  requireContext(aad);
  const iv = randomBytes(AES_GCM.ivBytes);
  return { iv, ciphertext: await aesGcmEncryptWithIv(key, iv, plaintext, aad) };
}

export async function decrypt(key: Key, sealed: Sealed, aad: CanonicalBytes): Promise<Bytes> {
  requireContext(aad);
  requireSealed(sealed);
  return aesGcmDecryptWithIv(key, sealed.iv, sealed.ciphertext, aad);
}

/** AES-GCM parameters of a DEK wrap: the canonical `cm.dek.wrap` context is the AAD. */
const dataKeyWrapParams = (iv: Bytes, aad: CanonicalBytes) => ({
  name: AES_GCM.name,
  iv,
  additionalData: aad,
  tagLength: AES_GCM.tagBytes * 8,
});

/**
 * A fresh data-encryption key (DEK) from the platform CSPRNG: AES-256-GCM, usable only to encrypt.
 * It is extractable only so that wrapDataKey can wrap it once (cryptographic-architecture section
 * 16); callers drop it right after wrapping and never export it any other way.
 */
export async function generateDataKey(): Promise<Key> {
  return guarded(CryptoErrorCode.UNAVAILABLE, () =>
    subtle().generateKey({ name: AES_GCM.name, length: AES_GCM.keyBits }, true, ['encrypt']),
  );
}

/**
 * Imports 32 random bytes as a non-extractable AES-256-GCM key for one usage, and wipes the input.
 * Used only for SEKs (Phase 9): unlike a FEK or NEK, a SEK is wrapped with RSA-OAEP, which takes
 * the raw 32 bytes (INV-17), so the sender holds the bytes briefly to wrap them and the recipient
 * gets them back from the unwrap. WebCrypto copies the bytes when importing, so wiping the
 * caller's buffer afterwards leaves only the non-extractable key.
 */
export async function importDataKey(raw: Bytes, usage: 'encrypt' | 'decrypt'): Promise<Key> {
  try {
    if (raw.length !== AES_GCM.keyBits / 8) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
    return await guarded(CryptoErrorCode.INVALID_INPUT, () =>
      subtle().importKey('raw', raw, { name: AES_GCM.name, length: AES_GCM.keyBits }, false, [usage]),
    );
  } finally {
    raw.fill(0);
  }
}

/**
 * Wraps a DEK under a room wrapping key (RWK_v) with AES-256-GCM, a fresh IV and the canonical
 * `cm.dek.wrap` context as AAD. The raw key bytes exist only inside WebCrypto.
 */
export async function wrapDataKey(dataKey: Key, wrappingKey: Key, aad: CanonicalBytes): Promise<Sealed> {
  requireContext(aad);
  const iv = randomBytes(AES_GCM.ivBytes);
  const wrapped = await guarded(
    CryptoErrorCode.INVALID_INPUT,
    async () => new Uint8Array(await subtle().wrapKey('raw', dataKey, wrappingKey, dataKeyWrapParams(iv, aad))),
  );
  return { iv, ciphertext: wrapped };
}

/**
 * Unwraps a DEK as a non-extractable key that can only decrypt. A wrong wrapping key, IV, AAD
 * (another room, key version, item or item type) or any modified byte fails with
 * AUTHENTICATION_FAILED, so a wrapped DEK cannot be moved into another context.
 */
export async function unwrapDataKey(sealed: Sealed, wrappingKey: Key, aad: CanonicalBytes): Promise<Key> {
  requireContext(aad);
  requireSealed(sealed);
  return guarded(CryptoErrorCode.AUTHENTICATION_FAILED, () =>
    subtle().unwrapKey(
      'raw',
      sealed.ciphertext,
      wrappingKey,
      dataKeyWrapParams(sealed.iv, aad),
      { name: AES_GCM.name, length: AES_GCM.keyBits },
      false,
      ['decrypt'],
    ),
  );
}

/**
 * Wraps a private key in PKCS#8 form under an AES-GCM wrapping key. The PKCS#8 bytes are produced
 * inside the WebCrypto implementation and never appear in JavaScript; only the ciphertext does.
 */
export async function wrapPrivateKey(privateKey: Key, wrappingKey: Key, aad: CanonicalBytes): Promise<Sealed> {
  requireContext(aad);
  const iv = randomBytes(AES_GCM.ivBytes);
  const ciphertext = await guarded(
    CryptoErrorCode.INVALID_INPUT,
    async () =>
      new Uint8Array(
        await subtle().wrapKey('pkcs8', privateKey, wrappingKey, {
          name: AES_GCM.name,
          iv,
          additionalData: aad,
          tagLength: AES_GCM.tagBytes * 8,
        }),
      ),
  );
  return { iv, ciphertext };
}

/** The algorithm and usages a wrapped private key is imported with. */
export interface UnwrapTarget {
  readonly algorithm: { readonly name: string; readonly hash?: string; readonly namedCurve?: string };
  readonly usages: readonly ('decrypt' | 'unwrapKey' | 'sign')[];
}

/**
 * Unwraps a PKCS#8 private key. `extractable` is true only inside the vault re-wrap, which must
 * wrap the same key again under a new passphrase; every other caller gets a non-extractable key.
 * A wrong key, IV, AAD or any modified byte fails with AUTHENTICATION_FAILED.
 */
export async function unwrapPrivateKey(
  sealed: Sealed,
  wrappingKey: Key,
  aad: CanonicalBytes,
  target: UnwrapTarget,
  extractable: boolean,
): Promise<Key> {
  requireContext(aad);
  requireSealed(sealed);
  return guarded(CryptoErrorCode.AUTHENTICATION_FAILED, () =>
    subtle().unwrapKey(
      'pkcs8',
      sealed.ciphertext,
      wrappingKey,
      { name: AES_GCM.name, iv: sealed.iv, additionalData: aad, tagLength: AES_GCM.tagBytes * 8 },
      { ...target.algorithm },
      extractable,
      [...target.usages],
    ),
  );
}
