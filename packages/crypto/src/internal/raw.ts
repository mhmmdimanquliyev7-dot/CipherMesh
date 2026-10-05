import { CryptoErrorCode } from '../errors';
import { AES_GCM, ECDSA, HKDF, RSA_OAEP } from '../params';
import type { Bytes, Key } from '../types';
import { guarded, subtle } from '../webcrypto';

/**
 * Low-level WebCrypto calls with explicit IVs, salts and labels. INTERNAL: this module is the
 * test seam of the cryptographic architecture (section 9). It is not exported from the package,
 * an ESLint rule forbids importing it from outside packages/crypto/src, and production code
 * reaches it only through the wrappers, which generate every IV themselves and take contexts
 * only from the canonical builders. Known-answer tests call it directly with the published
 * vectors (fixed IVs, RFC 5869 salts, Wycheproof labels).
 */

/** AES-256-GCM encryption with a caller-chosen IV. Returns ciphertext || tag. */
export async function aesGcmEncryptWithIv(key: Key, iv: Bytes, plaintext: Bytes, aad: Bytes): Promise<Bytes> {
  return guarded(CryptoErrorCode.INVALID_INPUT, async () => {
    const out = await subtle().encrypt(
      { name: AES_GCM.name, iv, additionalData: aad, tagLength: AES_GCM.tagBytes * 8 },
      key,
      plaintext,
    );
    return new Uint8Array(out);
  });
}

/** AES-256-GCM decryption. Any failure, including a wrong tag, is AUTHENTICATION_FAILED. */
export async function aesGcmDecryptWithIv(key: Key, iv: Bytes, ciphertext: Bytes, aad: Bytes): Promise<Bytes> {
  return guarded(CryptoErrorCode.AUTHENTICATION_FAILED, async () => {
    const out = await subtle().decrypt(
      { name: AES_GCM.name, iv, additionalData: aad, tagLength: AES_GCM.tagBytes * 8 },
      key,
      ciphertext,
    );
    return new Uint8Array(out);
  });
}

/** Imports raw AES-256 key bytes; used by known-answer tests only. */
export async function importAesGcmKeyForTest(raw: Bytes, usages: readonly ('encrypt' | 'decrypt')[]): Promise<Key> {
  return guarded(CryptoErrorCode.INVALID_INPUT, () =>
    subtle().importKey('raw', raw, { name: AES_GCM.name, length: AES_GCM.keyBits }, false, [...usages]),
  );
}

/** HKDF-SHA-256 with explicit salt and info (RFC 5869 test vectors). */
export async function hkdfSha256Bits(ikm: Key, salt: Bytes, info: Bytes, lengthBytes: number): Promise<Bytes> {
  return guarded(CryptoErrorCode.INVALID_INPUT, async () => {
    const bits = await subtle().deriveBits({ name: HKDF.name, hash: HKDF.hash, salt, info }, ikm, lengthBytes * 8);
    return new Uint8Array(bits);
  });
}

/** RSA-OAEP decryption of any length with an explicit label (Wycheproof vectors). */
export async function rsaOaepDecryptRaw(privateKey: Key, ciphertext: Bytes, label: Bytes): Promise<Bytes> {
  return guarded(CryptoErrorCode.AUTHENTICATION_FAILED, async () => {
    const out = await subtle().decrypt({ name: RSA_OAEP.name, label }, privateKey, ciphertext);
    return new Uint8Array(out);
  });
}

/** Imports an RSA-OAEP private key from PKCS#8; used by known-answer tests only. */
export async function importRsaOaepPrivateKeyForTest(pkcs8: Bytes): Promise<Key> {
  return guarded(CryptoErrorCode.INVALID_INPUT, () =>
    subtle().importKey('pkcs8', pkcs8, { name: RSA_OAEP.name, hash: RSA_OAEP.hash }, false, ['decrypt']),
  );
}

/** ECDSA P-256 / SHA-256 verification of arbitrary bytes (Wycheproof vectors). */
export async function ecdsaVerifyRaw(publicKey: Key, message: Bytes, signature: Bytes): Promise<boolean> {
  if (signature.length !== ECDSA.signatureBytes) return false;
  try {
    return await subtle().verify({ name: ECDSA.name, hash: ECDSA.hash }, publicKey, signature, message);
  } catch {
    return false;
  }
}
