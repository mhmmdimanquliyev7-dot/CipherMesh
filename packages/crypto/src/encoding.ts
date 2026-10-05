import { CryptoError, CryptoErrorCode } from './errors';
import type { Bytes } from './types';

/**
 * Encodings used by CipherMesh. Encoding is not encryption: base64url and hex only represent
 * bytes as text. Decoders are strict and canonical, so each byte string has exactly one accepted
 * text form; anything else is refused instead of being silently repaired.
 */

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_VALUES: Readonly<Record<string, number>> = Object.fromEntries(
  B64URL.split('').map((char, index) => [char, index]),
);

const invalid = (): CryptoError => new CryptoError(CryptoErrorCode.INVALID_INPUT);

/** Unpadded base64url (RFC 4648 section 5), the binary encoding of CP-15. */
export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += `${B64URL[(n >> 18) & 63] ?? ''}${B64URL[(n >> 12) & 63] ?? ''}${B64URL[(n >> 6) & 63] ?? ''}${B64URL[n & 63] ?? ''}`;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] ?? 0) << 16;
    out += `${B64URL[(n >> 18) & 63] ?? ''}${B64URL[(n >> 12) & 63] ?? ''}`;
  } else if (rest === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8);
    out += `${B64URL[(n >> 18) & 63] ?? ''}${B64URL[(n >> 12) & 63] ?? ''}${B64URL[(n >> 6) & 63] ?? ''}`;
  }
  return out;
}

/**
 * Decodes unpadded base64url. Rejects padding, other alphabets, impossible lengths and
 * non-canonical encodings (unused trailing bits that are not zero). With `expectedLength`, the
 * decoded size must match exactly.
 */
export function fromBase64Url(text: string, expectedLength?: number): Bytes {
  if (typeof text !== 'string' || text.length % 4 === 1) throw invalid();
  const values: number[] = [];
  for (const char of text) {
    const value = B64URL_VALUES[char];
    if (value === undefined) throw invalid();
    values.push(value);
  }
  const out = new Uint8Array(Math.floor((values.length * 3) / 4));
  let o = 0;
  let i = 0;
  for (; i + 3 < values.length; i += 4) {
    const n =
      ((values[i] ?? 0) << 18) | ((values[i + 1] ?? 0) << 12) | ((values[i + 2] ?? 0) << 6) | (values[i + 3] ?? 0);
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  const rest = values.length - i;
  if (rest === 2) {
    const a = values[i] ?? 0;
    const b = values[i + 1] ?? 0;
    if ((b & 15) !== 0) throw invalid();
    out[o] = ((a << 2) | (b >> 4)) & 255;
  } else if (rest === 3) {
    const a = values[i] ?? 0;
    const b = values[i + 1] ?? 0;
    const c = values[i + 2] ?? 0;
    if ((c & 3) !== 0) throw invalid();
    out[o] = ((a << 2) | (b >> 4)) & 255;
    out[o + 1] = ((b << 4) | (c >> 2)) & 255;
  }
  if (expectedLength !== undefined && out.length !== expectedLength) throw invalid();
  return out;
}

/** Length of the unpadded base64url text for `byteLength` bytes. */
export function base64UrlLength(byteLength: number): number {
  return Math.ceil((byteLength * 4) / 3);
}

/** Lower-case hexadecimal. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/** Decodes lower-case hexadecimal only, so every value has one canonical form. */
export function fromHex(text: string, expectedLength?: number): Bytes {
  if (typeof text !== 'string' || text.length % 2 !== 0 || !/^[0-9a-f]*$/.test(text)) throw invalid();
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  if (expectedLength !== undefined && out.length !== expectedLength) throw invalid();
  return out;
}

/** True when the string contains no lone UTF-16 surrogate (it can be encoded as UTF-8). */
export function isWellFormedUnicode(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** UTF-8 encoding. Refuses lone surrogates instead of replacing them with U+FFFD. */
export function utf8Encode(text: string): Bytes {
  if (!isWellFormedUnicode(text)) throw invalid();
  return new Uint8Array(new TextEncoder().encode(text));
}

/** Strict UTF-8 decoding: malformed input throws instead of producing replacement characters. */
export function utf8Decode(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw invalid();
  }
}

/**
 * Compares two byte strings without an early exit on the first difference. JavaScript gives no
 * timing guarantees, so this is best effort; secrets are compared this way in the browser only
 * where a timing difference would not be observable by another party anyway.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Overwrites a buffer with zeros. Best effort only: JavaScript may hold other copies (L-15). */
export function wipe(...buffers: (Uint8Array | undefined)[]): void {
  for (const buffer of buffers) buffer?.fill(0);
}
