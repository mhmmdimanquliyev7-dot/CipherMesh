import { CryptoError, CryptoErrorCode } from './errors';
import type { Subtle } from './types';

type PlatformCrypto = typeof globalThis.crypto;

/**
 * The only access point to the platform cryptography (LIB-01 in browsers, LIB-02 in Node.js).
 * Browsers expose `crypto.subtle` only in secure contexts. If it is missing, every operation
 * fails closed with CRYPTO_UNAVAILABLE; there is no fallback implementation (INV-15, CD-14).
 */
export function subtle(): Subtle {
  const api = (globalThis as { crypto?: PlatformCrypto }).crypto;
  if (api?.subtle === undefined) throw new CryptoError(CryptoErrorCode.UNAVAILABLE);
  return api.subtle;
}

/** The platform CSPRNG (CP-23). Math.random is never used for anything here. */
export function cryptoApi(): PlatformCrypto {
  const api = (globalThis as { crypto?: PlatformCrypto }).crypto;
  if (api === undefined || typeof api.getRandomValues !== 'function') {
    throw new CryptoError(CryptoErrorCode.UNAVAILABLE);
  }
  return api;
}

/**
 * Runs a WebCrypto call and replaces any failure with a fixed CryptoError. Library errors are
 * dropped on purpose: their messages are implementation details and never reach a caller.
 */
export async function guarded<T>(code: CryptoErrorCode, operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(code);
  }
}
