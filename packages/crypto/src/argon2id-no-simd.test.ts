import { afterEach, describe, expect, it, vi } from 'vitest';
import { toHex } from './encoding';
import { loadArgon2id } from './kdf/argon2id';
import { ARGON2ID_WASM_NO_SIMD, ARGON2ID_WASM_SIMD } from './kdf/argon2id-wasm';

// Browsers without WebAssembly SIMD get the library's second, non-SIMD build. The library tries
// SIMD once per page and remembers the result, so this check has its own test file: the SIMD
// build is refused before the first load here, and the non-SIMD build must then reproduce the
// RFC 9106 test vector exactly like the SIMD build in argon2id.test.ts. A different result would
// mean that a vault created in one browser cannot be opened in another.

const SIMD_BYTES = Buffer.from(ARGON2ID_WASM_SIMD.base64, 'base64').length;
const NO_SIMD_BYTES = Buffer.from(ARGON2ID_WASM_NO_SIMD.base64, 'base64').length;

afterEach(() => {
  vi.restoreAllMocks();
});

describe('non-SIMD WebAssembly build (LIB-03)', () => {
  it('is used when SIMD is refused and reproduces the RFC 9106 Argon2id test vector', async () => {
    const instantiate = WebAssembly.instantiate.bind(WebAssembly);
    const loaded: number[] = [];
    vi.spyOn(WebAssembly, 'instantiate').mockImplementation(((bytes: Uint8Array, imports?: WebAssembly.Imports) => {
      loaded.push(bytes.byteLength);
      if (bytes.byteLength === SIMD_BYTES) return Promise.reject(new WebAssembly.CompileError('no SIMD support'));
      return instantiate(bytes, imports);
    }) as unknown as typeof WebAssembly.instantiate);

    const argon2id = await loadArgon2id();
    const tag = argon2id({
      password: new Uint8Array(32).fill(1),
      salt: new Uint8Array(16).fill(2),
      secret: new Uint8Array(8).fill(3),
      associatedData: new Uint8Array(12).fill(4),
      memoryKiB: 32,
      iterations: 3,
      parallelism: 4,
    });
    expect(toHex(tag)).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
    expect(loaded).toEqual([SIMD_BYTES, NO_SIMD_BYTES]);
  });
});
