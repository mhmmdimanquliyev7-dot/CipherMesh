import { CryptoErrorCode } from './errors';
import type { Bytes } from './types';
import { guarded, subtle } from './webcrypto';

/**
 * SHA-256 (CP-07). A hash function: it is not encryption, not a MAC (it has no key) and never a
 * password or passphrase hash. Used for public-key fingerprints and digests of public values.
 */
export async function sha256(data: Bytes): Promise<Bytes> {
  return guarded(CryptoErrorCode.INVALID_INPUT, async () => new Uint8Array(await subtle().digest('SHA-256', data)));
}
