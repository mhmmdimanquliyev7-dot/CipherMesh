import { CryptoError, CryptoErrorCode } from './errors';
import type { Bytes } from './types';
import { cryptoApi } from './webcrypto';

/** CSPRNG bytes (CP-23). getRandomValues accepts at most 65,536 bytes per call. */
export function randomBytes(length: number): Bytes {
  if (!Number.isSafeInteger(length) || length < 1 || length > 65_536) {
    throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  }
  return cryptoApi().getRandomValues(new Uint8Array(length));
}

/** A UUIDv4 from the platform CSPRNG, for client-generated identifiers used in contexts (CD-08). */
export function randomUuidV4(): string {
  const api = cryptoApi();
  if (typeof api.randomUUID !== 'function') throw new CryptoError(CryptoErrorCode.UNAVAILABLE);
  return api.randomUUID();
}
