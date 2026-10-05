import type { CanonicalBytes } from './contexts';
import { bytesEqual } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { rsaOaepDecryptRaw } from './internal/raw';
import { RSA_OAEP } from './params';
import { algorithmOf, type Bytes, type Key, type KeyPair } from './types';
import { guarded, subtle } from './webcrypto';

/**
 * RSA-OAEP-3072 with SHA-256 (CP-02, ADR-007), the identity's encryption key. It transports only
 * 32-byte random values: room key material, per-secret keys and the vault pair-check value
 * (INV-17). There is deliberately no function that encrypts anything else, and the label is
 * always a canonical context that binds the value to its purpose and recipient.
 */
const ALGORITHM = { name: RSA_OAEP.name, hash: RSA_OAEP.hash } as const;

/**
 * Generates the encryption key pair. The private key is extractable only so that the vault can
 * wrap it once; after setup it is only ever loaded back as a non-extractable key.
 */
export async function generateEncryptionKeyPair(): Promise<KeyPair> {
  return guarded(CryptoErrorCode.UNAVAILABLE, async () => {
    const pair = (await subtle().generateKey(
      {
        name: RSA_OAEP.name,
        modulusLength: RSA_OAEP.modulusLength,
        publicExponent: new Uint8Array(RSA_OAEP.publicExponent),
        hash: RSA_OAEP.hash,
      },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    )) as KeyPair;
    return pair;
  });
}

export async function exportSpki(publicKey: Key): Promise<Bytes> {
  return guarded(
    CryptoErrorCode.INVALID_INPUT,
    async () => new Uint8Array(await subtle().exportKey('spki', publicKey)),
  );
}

/**
 * Imports and validates an encryption public key: exactly RSA, 3072 bits, e = 65537, and the DER
 * must be the canonical encoding WebCrypto itself produces (re-export equality). Anything else,
 * including other algorithm identifiers or alternative encodings, is IDENTITY_INVALID.
 */
export async function importEncryptionPublicKey(spki: Bytes): Promise<Key> {
  if (spki.length !== RSA_OAEP.spkiBytes) throw new CryptoError(CryptoErrorCode.IDENTITY_INVALID);
  const key = await guarded(CryptoErrorCode.IDENTITY_INVALID, () =>
    subtle().importKey('spki', spki, ALGORITHM, true, ['encrypt']),
  );
  const algorithm = algorithmOf(key);
  const exponent = algorithm.publicExponent;
  const ok =
    algorithm.name === RSA_OAEP.name &&
    algorithm.modulusLength === RSA_OAEP.modulusLength &&
    exponent !== undefined &&
    bytesEqual(new Uint8Array(exponent), new Uint8Array(RSA_OAEP.publicExponent)) &&
    bytesEqual(await exportSpki(key), spki);
  if (!ok) throw new CryptoError(CryptoErrorCode.IDENTITY_INVALID);
  return key;
}

/** Encrypts exactly 32 bytes to an encryption public key. Output: 384 bytes (CP-02, INV-17). */
export async function wrap32(publicKey: Key, value: Bytes, label: CanonicalBytes): Promise<Bytes> {
  if (value.length !== RSA_OAEP.wrappedValueBytes || label.length === 0) {
    throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  }
  return guarded(
    CryptoErrorCode.INVALID_INPUT,
    async () => new Uint8Array(await subtle().encrypt({ name: RSA_OAEP.name, label }, publicKey, value)),
  );
}

/**
 * Decrypts a 384-byte value and requires a 32-byte result. A wrong key, label or modified byte
 * fails with one generic error; the client stops after a failure instead of retrying, which
 * denies an attacker the adaptive queries of a Manger-style attack (ADR-007).
 */
export async function unwrap32(privateKey: Key, ciphertext: Bytes, label: CanonicalBytes): Promise<Bytes> {
  if (ciphertext.length !== RSA_OAEP.ciphertextBytes || label.length === 0) {
    throw new CryptoError(CryptoErrorCode.AUTHENTICATION_FAILED);
  }
  const value = await rsaOaepDecryptRaw(privateKey, ciphertext, label);
  if (value.length !== RSA_OAEP.wrappedValueBytes) {
    value.fill(0);
    throw new CryptoError(CryptoErrorCode.AUTHENTICATION_FAILED);
  }
  return value;
}
