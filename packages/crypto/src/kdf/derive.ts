import { utf8Encode, wipe } from '../encoding';
import { CryptoError, CryptoErrorCode } from '../errors';
import { importKeyMaterial } from '../hkdf';
import { isAcceptableKdf, VAULT_KDF, type Argon2idParameters } from '../params';
import type { Bytes, Key } from '../types';
import type { KdfRunner } from './runner';

/**
 * VRK = Argon2id(passphrase, salt, params) (cryptographic-architecture section 5). The 32-byte
 * output is imported at once as a non-extractable HKDF key and its buffer is wiped, so the Vault
 * Root Key exists as bytes only for an instant and only in this browser. It is never sent,
 * stored or logged (INV-01).
 *
 * Resource control: one derivation at a time per page. A second request while one is running is
 * refused with KDF_BUSY instead of being queued, so repeated clicks or a script cannot stack up
 * 64 MiB derivations and exhaust memory. Parameters outside the floor and ceiling of CP-04 are
 * refused before any work is done.
 */
let running = false;

/** True while a derivation is running (the auto-lock waits for it to finish). */
export function isDerivationRunning(): boolean {
  return running;
}

export async function deriveVaultRootKey(
  runner: KdfRunner,
  normalizedPassphrase: string,
  salt: Bytes,
  params: Argon2idParameters,
): Promise<Key> {
  if (!isAcceptableKdf(params)) throw new CryptoError(CryptoErrorCode.KDF_PARAMETERS_OUT_OF_RANGE);
  if (salt.length !== VAULT_KDF.saltBytes) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  if (running) throw new CryptoError(CryptoErrorCode.KDF_BUSY);
  running = true;
  const password = utf8Encode(normalizedPassphrase);
  try {
    const output = await runner.run({
      password,
      salt: new Uint8Array(salt),
      memoryKiB: params.memoryKiB,
      iterations: params.iterations,
      parallelism: params.parallelism,
    });
    if (output.length !== VAULT_KDF.outputBytes) {
      wipe(output);
      throw new CryptoError(CryptoErrorCode.KDF_FAILED);
    }
    return await importKeyMaterial(output);
  } finally {
    wipe(password);
    running = false;
  }
}
