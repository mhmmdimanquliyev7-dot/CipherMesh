import { describe, expect, it } from 'vitest';
import {
  base64UrlLength,
  bytesEqual,
  fromBase64Url,
  fromHex,
  isWellFormedUnicode,
  toBase64Url,
  toHex,
  utf8Decode,
  utf8Encode,
} from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';

const invalidInput = (fn: () => unknown): void => {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught, CryptoErrorCode.INVALID_INPUT)).toBe(true);
};

describe('base64url (RFC 4648 section 5, unpadded)', () => {
  it('matches the RFC 4648 test vectors', () => {
    // RFC 4648 section 10 vectors, without padding and with the URL alphabet.
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'Zg'],
      ['fo', 'Zm8'],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg'],
      ['fooba', 'Zm9vYmE'],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [text, encoded] of vectors) {
      expect(toBase64Url(new TextEncoder().encode(text))).toBe(encoded);
      expect(new TextDecoder().decode(fromBase64Url(encoded))).toBe(text);
    }
    expect(toBase64Url(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('-_-_');
    expect(Buffer.from(fromBase64Url('-_-_')).toString('hex')).toBe('fbffbf');
  });

  it('round-trips every length and agrees with Node.js', () => {
    for (let length = 0; length < 70; length++) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + length) & 255);
      const encoded = toBase64Url(bytes);
      expect(encoded).toBe(Buffer.from(bytes).toString('base64url'));
      expect(encoded.length).toBe(base64UrlLength(length));
      expect(bytesEqual(fromBase64Url(encoded, length), bytes)).toBe(true);
    }
  });

  it('refuses padding, other alphabets, impossible lengths and non-canonical trailing bits', () => {
    // 'Zh', 'Zm9', 'Zm-' and 'Zm9vYmF' have non-zero unused trailing bits: each byte string has
    // exactly one accepted encoding ('Zg' is the canonical form of 0x66, 'Zm9vYmE' of "fooba").
    for (const bad of ['Zg==', 'Zm9v+', 'Zm9v/', 'Zm9 v', 'Z', 'Zm9vY', 'Zh', 'Zm9', 'Zm-', 'Zm9vYmF']) {
      invalidInput(() => fromBase64Url(bad));
    }
    expect(new TextDecoder().decode(fromBase64Url('Zm9vYmE'))).toBe('fooba');
  });

  it('enforces an expected length', () => {
    expect(fromBase64Url('AAAA', 3)).toHaveLength(3);
    invalidInput(() => fromBase64Url('AAAA', 4));
  });
});

describe('hex', () => {
  it('encodes lower case and decodes only canonical lower case', () => {
    expect(toHex(new Uint8Array([0, 15, 16, 255]))).toBe('000f10ff');
    expect(Array.from(fromHex('000f10ff'))).toEqual([0, 15, 16, 255]);
    for (const bad of ['0', 'ABCD', '0g', 'zz', '00 ']) invalidInput(() => fromHex(bad));
    invalidInput(() => fromHex('0000', 1));
  });
});

describe('UTF-8', () => {
  it('refuses lone surrogates instead of replacing them', () => {
    expect(isWellFormedUnicode('a😀b')).toBe(true);
    expect(isWellFormedUnicode('\ud83d')).toBe(false);
    expect(isWellFormedUnicode('\ude00x')).toBe(false);
    invalidInput(() => utf8Encode('x\ud800'));
    expect(utf8Decode(utf8Encode('Grüße 😀'))).toBe('Grüße 😀');
    invalidInput(() => utf8Decode(new Uint8Array([0xc3, 0x28])));
  });
});

describe('bytesEqual', () => {
  it('compares length and every byte', () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});
