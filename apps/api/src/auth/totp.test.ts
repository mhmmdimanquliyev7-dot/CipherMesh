import { describe, expect, it } from 'vitest';
import { generateTotpSecret, TOTP_PARAMETERS, totpCodeAt, totpEnrollment, verifyTotp } from './totp';

// RFC 6238 Appendix B test vectors for HMAC-SHA-1 (secret: ASCII "12345678901234567890").
// The RFC lists 8-digit values; CipherMesh uses 6 digits (CP-09), which are the last six.
const RFC_SECRET = Buffer.from('12345678901234567890', 'ascii');
const RFC_VECTORS: [number, string][] = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

describe('TOTP (RFC 6238, CP-09)', () => {
  it.each(RFC_VECTORS)('reproduces the RFC 6238 SHA-1 vector at T=%i', (seconds, eightDigits) => {
    expect(totpCodeAt(RFC_SECRET, seconds * 1000)).toBe(eightDigits.slice(-6));
    expect(verifyTotp(RFC_SECRET, eightDigits.slice(-6), seconds * 1000)).toBe(Math.floor(seconds / 30));
  });

  it('uses SHA-1, six digits, a 30-second step and a 160-bit secret', () => {
    expect(TOTP_PARAMETERS).toMatchObject({ algorithm: 'SHA1', digits: 6, period: 30, window: 1, secretBytes: 20 });
    expect(generateTotpSecret()).toHaveLength(20);
    expect(generateTotpSecret().equals(generateTotpSecret())).toBe(false);
  });

  it('accepts the previous and next step and nothing wider (about 90 seconds in total)', () => {
    const secret = generateTotpSecret();
    const now = 1_800_000_000_000;
    const step = Math.floor(now / 30_000);
    expect(verifyTotp(secret, totpCodeAt(secret, now - 30_000), now)).toBe(step - 1);
    expect(verifyTotp(secret, totpCodeAt(secret, now), now)).toBe(step);
    expect(verifyTotp(secret, totpCodeAt(secret, now + 30_000), now)).toBe(step + 1);
    expect(verifyTotp(secret, totpCodeAt(secret, now - 60_000), now)).toBeUndefined();
    expect(verifyTotp(secret, totpCodeAt(secret, now + 60_000), now)).toBeUndefined();
  });

  it('rejects codes for another secret and malformed codes', () => {
    const now = Date.now();
    expect(verifyTotp(generateTotpSecret(), totpCodeAt(generateTotpSecret(), now), now)).toBeUndefined();
    for (const bad of ['', '12345', '1234567', 'abcdef']) expect(verifyTotp(RFC_SECRET, bad, now)).toBeUndefined();
  });

  it('builds an otpauth URI with the issuer, the account and the base32 secret', () => {
    const { uri, base32 } = totpEnrollment(RFC_SECRET, 'user@example.test');
    expect(base32).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(uri).toMatch(/^otpauth:\/\/totp\/CipherMesh:user%40example\.test\?/);
    expect(uri).toContain('algorithm=SHA1');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
  });
});
