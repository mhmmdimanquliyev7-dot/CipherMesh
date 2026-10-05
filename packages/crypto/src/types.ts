/**
 * Platform-neutral type aliases. The package runs in browsers (DOM WebCrypto) and in Node.js
 * (the API verifies public identities and builds contexts with the same code), and the two type
 * environments name WebCrypto types differently. Deriving them from `globalThis.crypto` keeps
 * every module type-checked in both.
 */
type PlatformCrypto = typeof globalThis.crypto;

/** The platform SubtleCrypto. */
export type Subtle = PlatformCrypto['subtle'];

/** A WebCrypto key handle (`CryptoKey`). */
export type Key = Awaited<ReturnType<Subtle['importKey']>>;

export interface KeyPair {
  readonly publicKey: Key;
  readonly privateKey: Key;
}

/** Bytes backed by an ArrayBuffer, the only form WebCrypto accepts as a BufferSource. */
export type Bytes = Uint8Array<ArrayBuffer>;

/** The algorithm description of a key, read only for validation. */
export interface KeyAlgorithmView {
  readonly name: string;
  readonly modulusLength?: number;
  readonly publicExponent?: Uint8Array;
  readonly namedCurve?: string;
  readonly hash?: { readonly name: string };
}

export const algorithmOf = (key: Key): KeyAlgorithmView => key.algorithm;
