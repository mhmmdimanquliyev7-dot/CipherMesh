import { describe, expect, it } from 'vitest';
import { checkVaultPassphrase, normalizeVaultPassphrase, PassphraseProblem } from './passphrase';

// CP-06 Vault Passphrase policy. Every check runs in the browser; nothing here is sent anywhere.

const account = { email: 'alice.example@example.test', displayName: 'Alice Example' };
const problems = (raw: string): readonly string[] => {
  const result = checkVaultPassphrase(raw, account);
  return result.ok ? [] : result.problems;
};

describe('Vault Passphrase policy (CP-06)', () => {
  it('accepts long passphrases of words, spaces and any script', () => {
    for (const ok of [
      'orbit velvet canyon pilot',
      'tall green lamps hum softly at noon',
      'Здравствуй мир, как дела сегодня',
    ]) {
      expect(problems(ok)).toEqual([]);
    }
  });

  it('counts Unicode code points after NFKC and never truncates', () => {
    expect(problems('a'.repeat(15))).toEqual([PassphraseProblem.TOO_SHORT]);
    // 16 emoji are 32 UTF-16 code units but 16 code points: long enough.
    expect(problems('😀'.repeat(16))).toEqual([]);
    expect(problems('x'.repeat(256)).length).toBe(0);
    expect(problems('x'.repeat(257))).toEqual([PassphraseProblem.TOO_LONG]);
    // A fullwidth string normalizes (NFKC) to ASCII before counting and comparison: ASCII 0x21 to
    // 0x7E have fullwidth forms at U+FF01 to U+FF5E, and the ideographic space U+3000 becomes ' '.
    const fullwidth = 'quiet harbour lamps'
      .split('')
      .map((c) => (c === ' ' ? '\u3000' : String.fromCodePoint((c.codePointAt(0) ?? 0) + 0xfee0)))
      .join('');
    expect(fullwidth).not.toBe('quiet harbour lamps');
    const result = checkVaultPassphrase(fullwidth, account);
    expect(result.ok && result.normalized).toBe('quiet harbour lamps');
  });

  it('refuses lone surrogates', () => {
    expect(problems(`${'a'.repeat(20)}\ud800`)).toEqual([PassphraseProblem.MALFORMED]);
    expect(normalizeVaultPassphrase('\udfffabc')).toBeUndefined();
  });

  it('refuses breached passwords of 16 or more characters, in any case', () => {
    expect(problems('1234567890123456')).toEqual([PassphraseProblem.COMMON]);
    expect(problems('QWERTYUIOPASDFGH')).toEqual([PassphraseProblem.COMMON]);
  });

  it('refuses passphrases built from the account identity or the product name', () => {
    expect(problems('alice.example forever and ever')).toEqual([PassphraseProblem.CONTAINS_IDENTITY]);
    expect(problems('my Alice Example vault phrase')).toEqual([PassphraseProblem.CONTAINS_IDENTITY]);
    expect(problems('the CipherMesh vault passphrase')).toEqual([PassphraseProblem.CONTAINS_IDENTITY]);
  });

  it('keeps whitespace exactly as typed', () => {
    const result = checkVaultPassphrase('  spaced out passphrase here  ', account);
    expect(result.ok && result.normalized).toBe('  spaced out passphrase here  ');
  });
});
