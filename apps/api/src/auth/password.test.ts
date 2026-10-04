import { PasswordProblem } from '@ciphermesh/shared';
import { argon2Sync, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { BusyError, ConcurrencyLimiter } from './limits';
import { ARGON2_PARAMETERS, checkNewPassword, createPasswordHasher, normalizePassword, parsePhc } from './password';

const identity = { email: 'someone@example.test', displayName: 'Synthetic User' };
const hasher = createPasswordHasher(new ConcurrencyLimiter(2, 16));
const strong = (): string => `${randomBytes(12).toString('base64url')}#x`;

describe('password policy (CP-06)', () => {
  it('accepts 12 to 128 code points and rejects shorter or longer, without truncation', () => {
    expect(checkNewPassword('a'.repeat(5) + 'Q7#mz!kp', identity)).toMatchObject({ ok: true });
    expect(checkNewPassword('short-pw-11', identity)).toEqual({ ok: false, problems: [PasswordProblem.TOO_SHORT] });
    const long = 'x9'.repeat(64);
    expect(checkNewPassword(long, identity)).toMatchObject({ ok: true, normalized: long });
    expect(checkNewPassword(`${long}z`, identity)).toEqual({ ok: false, problems: [PasswordProblem.TOO_LONG] });
  });

  it('counts Unicode code points after NFKC, so 128 emoji are accepted', () => {
    const emoji = '\u{1F512}'.repeat(128);
    expect(emoji.length).toBe(256); // UTF-16 code units
    expect(checkNewPassword(emoji, identity)).toMatchObject({ ok: true });
  });

  it('normalizes with NFKC so equivalent input matches on every device (CD-15)', () => {
    const fullwidth = 'Ｓｙｎｔｈｅｔｉｃ-pass-77';
    const check = checkNewPassword(fullwidth, identity);
    expect(check).toMatchObject({ ok: true, normalized: 'Synthetic-pass-77' });
    expect(normalizePassword(fullwidth)).toBe('Synthetic-pass-77');
  });

  it('refuses lone surrogates instead of guessing an encoding', () => {
    expect(checkNewPassword(`abcdefghijkl\uD800`, identity)).toEqual({
      ok: false,
      problems: [PasswordProblem.MALFORMED],
    });
    expect(normalizePassword('x\uDC00')).toBeUndefined();
  });

  it.each(['1qaz2wsx3edc', 'qwerty123456', 'Q1W2E3R4T5Y6'])('rejects the breached password %s', (common) => {
    expect(checkNewPassword(common, identity)).toEqual({ ok: false, problems: [PasswordProblem.COMMON] });
  });

  it('rejects passwords built from the account identity or the product name', () => {
    expect(checkNewPassword('someone-2026-secure', identity)).toEqual({
      ok: false,
      problems: [PasswordProblem.CONTAINS_IDENTITY],
    });
    expect(checkNewPassword('my-CipherMesh-login', identity)).toEqual({
      ok: false,
      problems: [PasswordProblem.CONTAINS_IDENTITY],
    });
  });

  it('has no composition rules: a long lower-case passphrase is fine', () => {
    expect(checkNewPassword('correct orchard battery lantern', identity)).toMatchObject({ ok: true });
  });
});

describe('Argon2id hashing (CP-05, LIB-04)', () => {
  it('stores a PHC string with the registered parameters and a fresh salt', async () => {
    const password = strong();
    const a = await hasher.hash(password);
    const b = await hasher.hash(password);
    expect(a).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    expect(a).not.toBe(b);
    expect(a).not.toContain(password);
    expect(parsePhc(a)).toMatchObject({ memoryKiB: 65536, passes: 3, parallelism: 4 });
    expect(ARGON2_PARAMETERS).toEqual({ memoryKiB: 65536, passes: 3, parallelism: 4, saltBytes: 16, hashBytes: 32 });
  });

  it('verifies the right password and rejects a wrong one', async () => {
    const password = strong();
    const phc = await hasher.hash(password);
    expect(await hasher.verify(password, phc)).toEqual({ valid: true, needsRehash: false });
    expect(await hasher.verify(`${password}x`, phc)).toEqual({ valid: false, needsRehash: false });
  });

  it('flags hashes made with older parameters for rehashing', async () => {
    const password = strong();
    const salt = randomBytes(16);
    const derived = argon2Sync('argon2id', {
      message: Buffer.from(password),
      nonce: salt,
      memory: 19456,
      passes: 2,
      parallelism: 1,
      tagLength: 32,
    });
    const old = `$argon2id$v=19$m=19456,t=2,p=1$${salt.toString('base64').replace(/=+$/, '')}$${derived.toString('base64').replace(/=+$/, '')}`;
    expect(await hasher.verify(password, old)).toEqual({ valid: true, needsRehash: true });
  });

  it.each([
    [
      'an Argon2i hash',
      '$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g',
    ],
    [
      'memory below the floor',
      '$argon2id$v=19$m=1024,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g',
    ],
    [
      'memory far above the bound',
      '$argon2id$v=19$m=99999999,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g',
    ],
    ['a truncated string', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA'],
    ['garbage', 'not-a-hash'],
  ])('fails closed on %s', async (_label, phc) => {
    expect(parsePhc(phc)).toBeUndefined();
    expect(await hasher.verify(strong(), phc)).toEqual({ valid: false, needsRehash: false });
  });

  it('spends real Argon2id work for unknown accounts', async () => {
    const start = Date.now();
    await hasher.verifyDummy(strong());
    await hasher.verifyDummy(strong());
    expect(Date.now() - start).toBeGreaterThan(40);
  });
});

describe('Argon2id concurrency limit (CM-T018)', () => {
  it('runs at most the configured number at once and fails fast when the queue is full', async () => {
    const limiter = new ConcurrencyLimiter(2, 2);
    let active = 0;
    let peak = 0;
    const release: (() => void)[] = [];
    const task = () =>
      limiter.run(async () => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise<void>((resolve) => release.push(resolve));
        active -= 1;
      });
    const running = [task(), task(), task(), task()];
    await expect(task()).rejects.toBeInstanceOf(BusyError);
    while (release.length > 0 || active > 0) {
      release.shift()?.();
      await new Promise((r) => setTimeout(r, 1));
    }
    await Promise.all(running);
    expect(peak).toBe(2);
  });
});
