import { createHash, randomBytes } from 'node:crypto';

/**
 * Opaque bearer tokens for sessions and pre-authentication challenges (ADR-008, INV-12):
 * 32 bytes (256 bits) from the CSPRNG, base64url encoded (43 characters). The token carries no
 * data. The database stores only its SHA-256 digest; a fast hash is sufficient because the input
 * has full entropy (CP-08). Never logged, never placed in URLs or browser storage.
 */
const TOKEN_BYTES = 32;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface IssuedToken {
  /** Goes into the cookie only. */
  readonly token: string;
  /** Goes into the database only. */
  readonly digest: Buffer;
}

export function issueToken(): IssuedToken {
  const token = randomBytes(TOKEN_BYTES).toString('base64url');
  return { token, digest: digestToken(token) };
}

export function digestToken(token: string): Buffer {
  return createHash('sha256').update(token, 'ascii').digest();
}

/** Rejects anything that cannot be a token before it reaches a database query. */
export function isWellFormedToken(value: string): boolean {
  return TOKEN_PATTERN.test(value);
}
