import { describe, expect, it } from 'vitest';
import { canonicalBytes, canonicalize, type CanonicalValue } from './canonical';
import { contextBytes } from './contexts';
import { fromHex, utf8Decode } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';

// RFC 8785 (JCS) test data, restricted to the CP-15 subset (no floating-point numbers). The
// vectors are copied from the RFC text; nothing here is computed by the code under test.

const refused = (value: unknown): void => {
  let caught: unknown;
  try {
    canonicalize(value as CanonicalValue);
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught, CryptoErrorCode.INVALID_INPUT)).toBe(true);
};

describe('RFC 8785 section 3.2.3: sorting of object properties', () => {
  // The RFC's test object. Keys are written as JavaScript escapes for the RFC's JSON escapes.
  const input: Record<string, string> = {
    '\u20ac': 'Euro Sign',
    '\r': 'Carriage Return',
    '\ufb33': 'Hebrew Letter Dalet With Dagesh',
    '1': 'One',
    '\ud83d\ude00': 'Emoji: Grinning Face',
    '\u0080': 'Control',
    '\u00f6': 'Latin Small Letter O With Diaeresis',
  };

  it('orders members by UTF-16 code units, as the RFC lists', () => {
    const text = canonicalize(input);
    const values = [...text.matchAll(/:"([^"]*)"/g)].map((m) => m[1]);
    expect(values).toEqual([
      'Carriage Return',
      'One',
      'Control',
      'Latin Small Letter O With Diaeresis',
      'Euro Sign',
      'Emoji: Grinning Face',
      'Hebrew Letter Dalet With Dagesh',
    ]);
    // Control characters are escaped (\r); U+0080 and all other characters are emitted as is.
    expect(text.startsWith('{"\\r":"Carriage Return","1":"One","\u0080":"Control"')).toBe(true);
  });
});

describe('RFC 8785 sections 3.2.2 to 3.2.4: string serialization and UTF-8 bytes', () => {
  // Section 3.2.4 lists the canonical bytes of the section 3.2.2 sample. That sample contains a
  // "numbers" member with floating-point values, which CP-15 excludes; the member is removed
  // from both the input and the RFC bytes, which leaves the string and literal rules intact.
  // The six lines of the RFC 8785 section 3.2.4 dump, exactly as printed.
  const RFC_DUMP = [
    '7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72',
    '75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a',
    '5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31',
    '65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37',
    '5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30',
    '30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d',
  ];
  const NUMBERS = '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],';

  it('reproduces the RFC bytes for the subset', () => {
    const rfcText = utf8Decode(fromHex(RFC_DUMP.join(' ').replaceAll(' ', '')));
    expect(rfcText).toContain(NUMBERS);
    const expected = rfcText.replace(NUMBERS, '');
    // RFC 8785 section 3.2.2 input without the "numbers" member. The JSON string
    // "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/" is, as a JavaScript string:
    const input: CanonicalValue = { string: '\u20ac$\u000f\nA\'B"\\\\"/', literals: [null, true, false] };
    expect(canonicalize(input)).toBe(expected);
    expect(Buffer.from(canonicalBytes(input)).toString('utf8')).toBe(expected);
  });

  it('refuses the full sample, because it contains floating-point numbers', () => {
    refused(JSON.parse('{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}'));
  });
});

describe('RFC 8785 Appendix B: numbers within the safe-integer subset', () => {
  it('serializes zero, minus zero and the largest safe integers', () => {
    expect(canonicalize(0)).toBe('0');
    expect(canonicalize(-0)).toBe('0');
    expect(canonicalize(9007199254740991)).toBe('9007199254740991');
    expect(canonicalize(-9007199254740991)).toBe('-9007199254740991');
  });

  it('refuses values outside the subset instead of rounding them', () => {
    for (const value of [9007199254740992, -9007199254740992, 1.5, 5e-324, 1e21, Number.NaN, Infinity, -Infinity]) {
      refused(value);
    }
  });
});

describe('canonicalize: everything outside CP-15 is refused, nothing is dropped', () => {
  it('refuses undefined members, lone surrogates, non-plain objects and cycles', () => {
    refused({ a: undefined });
    refused({ a: '\ud800' });
    refused({ '\udfff': 1 });
    refused(new Date(0));
    refused(new Uint8Array(1));
    refused(new Map());
    refused(BigInt(1));
    refused(Symbol('x'));
    refused(() => 1);
    const cycle: Record<string, unknown> = {};
    cycle['self'] = cycle;
    refused(cycle);
    let deep: CanonicalValue = 'x';
    for (let i = 0; i < 40; i++) deep = [deep];
    refused(deep);
  });

  it('sorts nested objects and keeps array order', () => {
    expect(canonicalize({ b: [{ z: 1, a: 2 }, 'x'], a: { d: null, c: true } })).toBe(
      '{"a":{"c":true,"d":null},"b":[{"a":2,"z":1},"x"]}',
    );
  });
});

describe('CD-22: the server TOTP context keeps its bytes', () => {
  // Captured from the Phase 3 builder (apps/api/src/auth/totp-secret-box.ts, canonicalServerContext)
  // before it was replaced by contextBytes(). Existing MFA secrets were sealed with these bytes.
  const PHASE3_BYTES =
    '{"ctx":"cm.srv.totp","keyId":"fixture-key-1","userId":"6f1c2b8e-3d4a-4f5b-9c6d-7e8f9a0b1c2d","v":1}';

  it('contextBytes reproduces the Phase 3 context exactly', () => {
    const bytes = contextBytes('cm.srv.totp', {
      userId: '6f1c2b8e-3d4a-4f5b-9c6d-7e8f9a0b1c2d',
      keyId: 'fixture-key-1',
    });
    expect(Buffer.from(bytes).toString('utf8')).toBe(PHASE3_BYTES);
  });
});
