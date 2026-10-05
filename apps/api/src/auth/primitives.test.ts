import { PREAUTH_COOKIE, SESSION_COOKIE } from '@ciphermesh/shared';
import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { clearAuthCookie, readSingleCookie, serializeAuthCookie } from './cookies';
import { createIdentifierHasher } from './identifier';
import { backoffSeconds, FixedWindowLimiter } from './limits';
import { canonicalRecoveryCode, generateRecoveryCodes, recoveryCodeDigest } from './recovery-codes';
import { requireRecentAuthentication, requireStepUp, SESSION_POLICY, type Actor } from './sessions';
import { digestToken, isWellFormedToken, issueToken } from './tokens';
import { TotpSecretBox } from './totp-secret-box';

describe('session tokens (ADR-008, CP-08)', () => {
  it('are 256-bit random values, base64url encoded, stored only as SHA-256 digests', () => {
    const { token, digest } = issueToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    expect(digest.equals(createHash('sha256').update(token).digest())).toBe(true);
    expect(digestToken(token).equals(digest)).toBe(true);
    const many = new Set(Array.from({ length: 1000 }, () => issueToken().token));
    expect(many.size).toBe(1000);
  });

  it('rejects anything that is not a token before a database lookup', () => {
    for (const bad of ['', 'x', `${'a'.repeat(42)}=`, `${'a'.repeat(43)}a`, "a' OR '1'='1"]) {
      expect(isWellFormedToken(bad)).toBe(false);
    }
  });
});

describe('authentication cookies (session-and-csrf.md section 2)', () => {
  it('always carry HttpOnly, Secure, SameSite=Strict, Path=/ and no Domain', () => {
    const cookie = serializeAuthCookie(SESSION_COOKIE, 'tok', 43200);
    expect(cookie).toBe('__Host-cm_session=tok; Max-Age=43200; Path=/; Secure; HttpOnly; SameSite=Strict');
    expect(cookie.toLowerCase()).not.toContain('domain');
    expect(clearAuthCookie(PREAUTH_COOKIE)).toBe(
      '__Host-cm_preauth=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict',
    );
  });

  it('reads a cookie only when it appears exactly once', () => {
    expect(readSingleCookie('a=1; __Host-cm_session=abc; b=2', SESSION_COOKIE)).toBe('abc');
    expect(readSingleCookie('__Host-cm_session=abc; __Host-cm_session=evil', SESSION_COOKIE)).toBeUndefined();
    expect(readSingleCookie('cm_session=abc', SESSION_COOKIE)).toBeUndefined();
    expect(readSingleCookie(undefined, SESSION_COOKIE)).toBeUndefined();
  });
});

describe('recovery codes (CP-10)', () => {
  it('generates ten 100-bit codes in groups of five, stored as SHA-256 digests', () => {
    const { codes, digests } = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const [i, code] of codes.entries()) {
      expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$/);
      expect(digests[i]?.equals(recoveryCodeDigest(code.replaceAll('-', '')))).toBe(true);
    }
    // 32 symbols x 20 characters = 100 bits.
    expect(Math.log2(32) * 20).toBe(100);
  });

  it('accepts lower case, missing separators and Crockford look-alikes; rejects anything else', () => {
    expect(canonicalRecoveryCode('abcde-fghjk-mnpqr-stvwx')).toBe('ABCDEFGHJKMNPQRSTVWX');
    expect(canonicalRecoveryCode('0O1IL abcde fghjk mnpqr'.replace('L', 'l'))).toBe('00111ABCDEFGHJKMNPQR');
    expect(canonicalRecoveryCode('ABCDE-FGHJK-MNPQR')).toBeUndefined();
    expect(canonicalRecoveryCode('ABCDE-FGHJK-MNPQR-STVWU')).toBeUndefined();
  });
});

describe('progressive backoff (CM-T018)', () => {
  it('allows four failures, then doubles from 30 seconds up to 15 minutes, never permanent', () => {
    expect([1, 2, 3, 4].map(backoffSeconds)).toEqual([0, 0, 0, 0]);
    expect([5, 6, 7, 8, 9, 10, 11].map(backoffSeconds)).toEqual([30, 60, 120, 240, 480, 900, 900]);
    expect(backoffSeconds(10_000)).toBe(900);
  });

  it('fixed windows reset after the window and bound their memory', () => {
    let now = 0;
    const limiter = new FixedWindowLimiter(2, 1000, 3, () => now);
    expect([1, 2, 3].map(() => limiter.consume('a').allowed)).toEqual([true, true, false]);
    expect(limiter.consume('a').retryAfterSeconds).toBe(1);
    now = 1000;
    expect(limiter.consume('a').allowed).toBe(true);
    for (const key of ['b', 'c', 'd', 'e']) limiter.consume(key);
    expect(limiter.consume('a').allowed).toBe(true); // evicted: the map holds at most three keys
  });
});

describe('identifier HMAC (CP-12)', () => {
  it('is keyed: the same identifier gives different values under different keys', () => {
    const a = createIdentifierHasher(randomBytes(32).toString('base64url'));
    const b = createIdentifierHasher(randomBytes(32).toString('base64url'));
    expect(a('x@example.test')).toHaveLength(32);
    expect(a('x@example.test').equals(a('x@example.test'))).toBe(true);
    expect(a('x@example.test').equals(b('x@example.test'))).toBe(false);
  });
});

describe('TOTP secret encryption at rest (CP-11)', () => {
  const box = new TotpSecretBox(randomBytes(32).toString('base64url'), 'k1');
  const secret = randomBytes(20);
  const userId = '7b3f0d0e-4b8f-4c4d-9a35-4a5b0f6a1c11';

  it('round-trips and produces IV || ciphertext || tag (48 bytes for a 160-bit secret)', () => {
    const sealed = box.seal(userId, secret);
    expect(sealed).toHaveLength(48);
    expect(sealed.includes(secret)).toBe(false);
    expect(box.open(userId, 'k1', sealed).equals(secret)).toBe(true);
    expect(box.seal(userId, secret).equals(sealed)).toBe(false); // fresh IV every time
  });

  it('fails closed for another user, another key ID, a flipped bit or another key', () => {
    const sealed = box.seal(userId, secret);
    expect(() => box.open('00000000-0000-4000-8000-000000000000', 'k1', sealed)).toThrow();
    expect(() => box.open(userId, 'k2', sealed)).toThrow();
    const flipped = Buffer.from(sealed);
    flipped[20] = (flipped[20] ?? 0) ^ 1;
    expect(() => box.open(userId, 'k1', flipped)).toThrow();
    const other = new TotpSecretBox(randomBytes(32).toString('base64url'), 'k1');
    expect(() => other.open(userId, 'k1', sealed)).toThrow();
  });

  it('opens a secret sealed by the Phase 3 code: the CD-22 context migration kept the AAD bytes', () => {
    // Fixture produced on 2026-10-05 by the Phase 3 implementation (local canonicalServerContext)
    // before it was replaced: a synthetic key of 32 bytes 0x42, key ID fixture-key-1, and the
    // RFC 6238 seed "12345678901234567890" as the TOTP secret. Not a secret of any system.
    const PHASE3_SEALED = 'sAnTz0PqGGu1bbVavk_Hcz2h7YEHEVuNccRvYT6E1O0rbVqiyNoRuV_6yvmUog3z';
    const phase3Box = new TotpSecretBox(Buffer.alloc(32, 0x42).toString('base64url'), 'fixture-key-1');
    const opened = phase3Box.open(
      '6f1c2b8e-3d4a-4f5b-9c6d-7e8f9a0b1c2d',
      'fixture-key-1',
      Buffer.from(PHASE3_SEALED, 'base64url'),
    );
    expect(opened.toString('ascii')).toBe('12345678901234567890');
  });

  it('refuses a user ID that is not a UUIDv4 instead of building an ambiguous context', () => {
    expect(() => box.seal('not-a-uuid', secret)).toThrow();
  });
});

describe('freshness and step-up gates (CM-T021, PC-02, PC-03)', () => {
  const now = new Date('2026-10-04T12:00:00.000Z');
  const actor = (authenticatedAt: Date, stepUpAt: Date | null): Actor =>
    ({ session: { authenticatedAt, stepUpAt } }) as unknown as Actor;

  it('step-up is valid for exactly 15 minutes (5 minutes in strict mode)', () => {
    const at = (ms: number) => actor(now, new Date(now.getTime() - ms));
    expect(requireStepUp(at(SESSION_POLICY.stepUpMs), SESSION_POLICY.stepUpMs, now)).toBeUndefined();
    expect(requireStepUp(at(SESSION_POLICY.stepUpMs + 1), SESSION_POLICY.stepUpMs, now)).toBe('STEP_UP_REQUIRED');
    expect(requireStepUp(at(5 * 60_000 + 1), SESSION_POLICY.stepUpStrictMs, now)).toBe('STEP_UP_REQUIRED');
    expect(requireStepUp(actor(now, null), SESSION_POLICY.stepUpMs, now)).toBe('STEP_UP_REQUIRED');
    // A step-up time in the future (clock skew or tampering) is not accepted.
    expect(requireStepUp(actor(now, new Date(now.getTime() + 1000)), SESSION_POLICY.stepUpMs, now)).toBe(
      'STEP_UP_REQUIRED',
    );
  });

  it('recent authentication returns REAUTH_REQUIRED past the allowed age', () => {
    const hour = 60 * 60_000;
    expect(requireRecentAuthentication(actor(new Date(now.getTime() - hour), null), hour, now)).toBeUndefined();
    expect(requireRecentAuthentication(actor(new Date(now.getTime() - hour - 1), null), hour, now)).toBe(
      'REAUTH_REQUIRED',
    );
  });
});
