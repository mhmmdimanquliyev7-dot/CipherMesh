import setupWasm from 'argon2id/lib/setup.js';
import { CryptoError, CryptoErrorCode } from '../errors';
import { VAULT_KDF } from '../params';
import type { Bytes } from '../types';
import { ARGON2ID_WASM_NO_SIMD, ARGON2ID_WASM_SIMD } from './argon2id-wasm';

/**
 * Argon2id (RFC 9106, version 1.3) through the `argon2id` library of OpenPGP.js (LIB-03). This
 * module is the only place that touches the library, so it can be replaced behind this
 * interface. The library runs Argon2id in JavaScript with its block function compiled to
 * WebAssembly; it reproduces the RFC 9106 test vector including the secret and associated data,
 * and its output matches Node.js crypto.argon2 (OpenSSL) for the production parameters
 * (argon2id.test.ts).
 *
 * Input checks: the library compares the password and salt arrays themselves, not their lengths,
 * with its limits, so those checks never fire for multi-byte input (LIB-03 review). Callers
 * validate every length first: protocol.ts in the worker, derive.ts for the vault.
 *
 * Memory: the library clears only its small scratch area, not the block memory. CipherMesh does
 * not rely on that clearing: every derivation runs in a fresh Web Worker that is terminated
 * afterwards, which releases the whole WebAssembly memory (it is not wiped physically, L-15).
 */
export interface Argon2idInput {
  readonly password: Bytes;
  readonly salt: Bytes;
  readonly memoryKiB: number;
  readonly iterations: number;
  readonly parallelism: number;
  /** RFC 9106 optional inputs, used only by the known-answer test. */
  readonly secret?: Bytes;
  readonly associatedData?: Bytes;
}

export type Argon2idFunction = (input: Argon2idInput) => Bytes;

function decodeBase64(base64: string): Bytes {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Instantiates a fresh WebAssembly instance (SIMD when supported). Fails closed without WASM. */
export async function loadArgon2id(): Promise<Argon2idFunction> {
  if (typeof WebAssembly !== 'object') throw new CryptoError(CryptoErrorCode.UNAVAILABLE);
  let compute: Awaited<ReturnType<typeof setupWasm>>;
  try {
    compute = await setupWasm(
      (imports) => WebAssembly.instantiate(decodeBase64(ARGON2ID_WASM_SIMD.base64), imports),
      (imports) => WebAssembly.instantiate(decodeBase64(ARGON2ID_WASM_NO_SIMD.base64), imports),
    );
  } catch {
    // A CSP without 'wasm-unsafe-eval' or a browser without WebAssembly ends here (INV-15).
    throw new CryptoError(CryptoErrorCode.UNAVAILABLE);
  }
  return (input) => {
    const output = compute({
      password: input.password,
      salt: input.salt,
      parallelism: input.parallelism,
      passes: input.iterations,
      memorySize: input.memoryKiB,
      tagLength: VAULT_KDF.outputBytes,
      ...(input.secret === undefined ? {} : { secret: input.secret }),
      ...(input.associatedData === undefined ? {} : { ad: input.associatedData }),
    });
    // A copy with its own buffer, so the worker can transfer exactly these bytes.
    const copy = new Uint8Array(output);
    output.fill(0);
    return copy;
  };
}
