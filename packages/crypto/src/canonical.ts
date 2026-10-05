import { isWellFormedUnicode, utf8Encode } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import type { Bytes } from './types';

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) for the value subset allowed by CP-15: strings,
 * safe integers, booleans, null, plain objects and arrays. Floating-point numbers are refused,
 * so the number serialization of RFC 8785 reduces to the decimal form of an integer.
 *
 * For this subset, RFC 8785 equals:
 *   - strings serialized as ECMAScript JSON.stringify does (the RFC adopts that algorithm);
 *   - object members sorted by their names as arrays of UTF-16 code units (Array.prototype.sort
 *     without a comparator compares exactly that), recursively;
 *   - array order preserved; no whitespace;
 *   - the result encoded as UTF-8.
 * Lone surrogates are refused (I-JSON, RFC 7493), as are undefined values, -Infinity, NaN,
 * non-safe integers, class instances and cycles. Nothing is silently dropped or converted.
 *
 * The decision to implement this subset in the repository instead of adding a dependency is
 * OCD-04 / LIB-05 (crypto-decisions.md). It is verified against the RFC 8785 test data and must
 * reproduce the bytes of the server's earlier `cm.srv.totp` builder (CD-22).
 */
export type CanonicalValue =
  string | number | boolean | null | readonly CanonicalValue[] | { readonly [key: string]: CanonicalValue };

const MAX_DEPTH = 32;

const invalid = (): CryptoError => new CryptoError(CryptoErrorCode.INVALID_INPUT);

function serializeString(value: string): string {
  if (!isWellFormedUnicode(value)) throw invalid();
  return JSON.stringify(value);
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function serialize(value: unknown, depth: number, ancestors: Set<object>): string {
  if (depth > MAX_DEPTH) throw invalid();
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return serializeString(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw invalid();
      // RFC 8785 serializes -0 as 0 (Appendix B).
      return Object.is(value, -0) ? '0' : String(value);
    case 'object': {
      if (ancestors.has(value)) throw invalid();
      ancestors.add(value);
      let out: string;
      if (Array.isArray(value)) {
        out = `[${value.map((item: unknown) => serialize(item, depth + 1, ancestors)).join(',')}]`;
      } else if (isPlainObject(value)) {
        const names = Object.keys(value).sort();
        const members = names.map((name) => {
          const member = value[name];
          if (member === undefined) throw invalid();
          return `${serializeString(name)}:${serialize(member, depth + 1, ancestors)}`;
        });
        out = `{${members.join(',')}}`;
      } else {
        throw invalid();
      }
      ancestors.delete(value);
      return out;
    }
    default:
      throw invalid();
  }
}

/** The canonical JSON text of `value`. Throws CRYPTO_INVALID_INPUT outside the CP-15 subset. */
export function canonicalize(value: CanonicalValue): string {
  return serialize(value, 0, new Set());
}

/** The canonical UTF-8 bytes of `value`, the form used for AAD, labels, info and signatures. */
export function canonicalBytes(value: CanonicalValue): Bytes {
  return utf8Encode(canonicalize(value));
}
