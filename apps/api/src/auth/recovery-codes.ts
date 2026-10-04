import { RECOVERY_CODE_COUNT } from '@ciphermesh/shared';
import { createHash, randomInt } from 'node:crypto';

/**
 * Recovery codes (CP-10, CM-T019): ten codes, each 20 characters from the Crockford base32
 * alphabet chosen with the CSPRNG (100 bits), displayed as XXXXX-XXXXX-XXXXX-XXXXX. Only the
 * SHA-256 digest of the canonical form is stored; a fast hash is acceptable for random values of
 * this entropy, unlike passwords. Codes are shown once and are single use.
 */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CODE_LENGTH = 20;
/** Exactly 20 characters of the Crockford alphabet above. */
const CANONICAL_PATTERN = /^[0-9A-HJKMNP-TV-Z]{20}$/;

export function generateRecoveryCodes(): { readonly codes: string[]; readonly digests: Buffer[] } {
  const codes: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i += 1) {
    let raw = '';
    for (let j = 0; j < CODE_LENGTH; j += 1) raw += ALPHABET.charAt(randomInt(ALPHABET.length));
    codes.push(raw.match(/.{5}/g)?.join('-') ?? raw);
  }
  return { codes, digests: codes.map((code) => recoveryCodeDigest(canonicalRecoveryCode(code) ?? '')) };
}

/** Accepts the code with or without separators and in any case; maps Crockford look-alikes. */
export function canonicalRecoveryCode(input: string): string | undefined {
  const cleaned = input.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  return CANONICAL_PATTERN.test(cleaned) ? cleaned : undefined;
}

export function recoveryCodeDigest(canonical: string): Buffer {
  return createHash('sha256').update(canonical, 'ascii').digest();
}
