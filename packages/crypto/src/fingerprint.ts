import { contextBytes } from './contexts';
import { toBase64Url, toHex } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { sha256 } from './hash';
import { SUITE } from './params';
import type { Bytes } from './types';

/**
 * Identity fingerprint (CP-17 as revised by ADR-015): SHA-256 over the canonical statement
 * cm.identity.fingerprint {suite, encryptionKeySpki, signingKeySpki}, so one out-of-band
 * comparison covers both public keys. A fingerprint is public and is not a secret. It helps
 * people detect key substitution only when they compare it over a channel the server does not
 * control (TB-12, T-25); the comparison itself is a human act the system cannot verify (L-18).
 *
 * Each client computes fingerprints from the keys it actually uses. A fingerprint string sent by
 * the server is only ever compared against such a locally computed value, never shown as verified.
 */
const FINGERPRINT = /^[0-9a-f]{64}$/;

export async function computeFingerprint(encryptionKeySpki: Bytes, signingKeySpki: Bytes): Promise<string> {
  const statement = contextBytes('cm.identity.fingerprint', {
    suite: SUITE,
    encryptionKeySpki: toBase64Url(encryptionKeySpki),
    signingKeySpki: toBase64Url(signingKeySpki),
  });
  return toHex(await sha256(statement));
}

export function isFingerprint(value: unknown): value is string {
  return typeof value === 'string' && FINGERPRINT.test(value);
}

/** Display form: 64 hexadecimal characters in 16 groups of 4 (CP-17). Always compared in full. */
export function formatFingerprint(fingerprint: string): readonly string[] {
  if (!isFingerprint(fingerprint)) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  return Array.from({ length: 16 }, (_, i) => fingerprint.slice(i * 4, i * 4 + 4));
}
