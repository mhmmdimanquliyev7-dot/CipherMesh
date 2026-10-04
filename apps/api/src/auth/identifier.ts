import { createHmac, createSecretKey, type KeyObject } from 'node:crypto';

/**
 * CP-12: login attempts for identifiers that match no account store only
 * HMAC-SHA-256(IDENTIFIER_HMAC_KEY, normalized identifier). Users sometimes type a password into
 * the identifier field, so the raw value must never be stored. The keyed HMAC still lets rate
 * limiting count attempts per identifier. The key lives outside the database.
 */
export function createIdentifierHasher(keyBase64Url: string): (normalizedIdentifier: string) => Buffer {
  const key: KeyObject = createSecretKey(Buffer.from(keyBase64Url, 'base64url'));
  return (normalizedIdentifier) => createHmac('sha256', key).update(normalizedIdentifier, 'utf8').digest();
}
