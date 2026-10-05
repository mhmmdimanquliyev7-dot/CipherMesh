import type { CanonicalBytes } from './contexts';
import { wipe } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { AES_GCM, HKDF } from './params';
import type { Bytes, Key } from './types';
import { guarded, subtle } from './webcrypto';

/**
 * HKDF-SHA-256 key separation (CP-03): salt = 32 zero bytes, info = a canonical context. The
 * input keying material is imported as a non-extractable HKDF key, so derived keys can be used
 * without their bytes ever existing in JavaScript.
 *
 * The all-zero salt equals RFC 5869's "salt not provided" (HMAC pads a shorter key with zeros),
 * which the RFC 5869 test case 3 vector confirms. Inputs are either uniformly random (room key
 * material) or Argon2id output (the vault root key), so a salt adds no strength here; separation
 * between purposes comes from the context in `info`.
 */
const ZERO_SALT: Bytes = new Uint8Array(HKDF.saltBytes);

/** Imports 32 bytes of key material as a non-extractable HKDF key and wipes the input buffer. */
export async function importKeyMaterial(material: Bytes): Promise<Key> {
  if (material.length !== 32) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  try {
    return await guarded(CryptoErrorCode.INVALID_INPUT, () =>
      subtle().importKey('raw', material, HKDF.name, false, ['deriveKey', 'deriveBits']),
    );
  } finally {
    wipe(material);
  }
}

/**
 * Derives a non-extractable AES-256-GCM key for wrapping and unwrapping other keys only. It can
 * never encrypt or decrypt data, and its bytes cannot be exported.
 */
export async function deriveWrappingKey(material: Key, info: CanonicalBytes): Promise<Key> {
  return guarded(CryptoErrorCode.INVALID_INPUT, () =>
    subtle().deriveKey(
      { name: HKDF.name, hash: HKDF.hash, salt: ZERO_SALT, info },
      material,
      { name: AES_GCM.name, length: AES_GCM.keyBits },
      false,
      ['wrapKey', 'unwrapKey'],
    ),
  );
}

/** Derives 256 bits for a public value such as a key commitment (Phase 6). */
export async function deriveBits(material: Key, info: CanonicalBytes): Promise<Bytes> {
  return guarded(CryptoErrorCode.INVALID_INPUT, async () => {
    const bits = await subtle().deriveBits(
      { name: HKDF.name, hash: HKDF.hash, salt: ZERO_SALT, info },
      material,
      HKDF.outputBits,
    );
    return new Uint8Array(bits);
  });
}
