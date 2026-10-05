import { isAcceptableKdf, VAULT_KDF, type Argon2idParameters } from '../params';
import type { Bytes } from '../types';

/**
 * Messages between the page and the Argon2id worker. The worker is a trust boundary inside the
 * client: it accepts exactly one well-formed request, validates it like any other input, and
 * answers with the 32-byte output or a bare failure flag. It never sends back the passphrase,
 * error texts or library state.
 */
export interface KdfRequest extends Argon2idParameters {
  /** UTF-8 of the NFKC-normalized passphrase. Transferred to the worker, then wiped there. */
  readonly password: Bytes;
  readonly salt: Bytes;
}

export type KdfResponse = { readonly ok: true; readonly output: ArrayBuffer } | { readonly ok: false };

/** Wire form of a request: the password travels as a transferred ArrayBuffer. */
export interface KdfRequestMessage extends Argon2idParameters {
  readonly type: 'argon2id';
  readonly password: ArrayBuffer;
  readonly salt: ArrayBuffer;
}

/** Upper bound for the password bytes: 256 code points of at most 4 UTF-8 bytes each. */
export const MAX_PASSWORD_BYTES = 1024;

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null;

/** Validates a request message inside the worker. Returns undefined for anything malformed. */
export function parseKdfRequest(data: unknown): KdfRequest | undefined {
  if (!isObject(data) || data['type'] !== 'argon2id') return undefined;
  const { password, salt, memoryKiB, iterations, parallelism } = data;
  if (!(password instanceof ArrayBuffer) || !(salt instanceof ArrayBuffer)) return undefined;
  if (password.byteLength < 1 || password.byteLength > MAX_PASSWORD_BYTES) return undefined;
  if (salt.byteLength !== VAULT_KDF.saltBytes) return undefined;
  if (typeof memoryKiB !== 'number' || typeof iterations !== 'number' || typeof parallelism !== 'number') {
    return undefined;
  }
  const params = { memoryKiB, iterations, parallelism };
  if (!isAcceptableKdf(params)) return undefined;
  return { password: new Uint8Array(password), salt: new Uint8Array(salt), ...params };
}

/** Validates a response on the page. */
export function parseKdfResponse(data: unknown): Bytes | undefined {
  if (!isObject(data) || data['ok'] !== true) return undefined;
  const output = data['output'];
  if (!(output instanceof ArrayBuffer) || output.byteLength !== VAULT_KDF.outputBytes) return undefined;
  return new Uint8Array(output);
}
