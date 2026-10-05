import { loadArgon2id } from './argon2id';
import { parseKdfRequest, type KdfResponse } from './protocol';

/**
 * Dedicated Web Worker that runs one Argon2id derivation and exits (CP-04, ADR-010). Running it
 * here keeps the page responsive during the deliberately expensive derivation. The worker:
 *   - accepts exactly one message and ignores any further ones;
 *   - validates the request (protocol.ts) before doing any work;
 *   - wipes the password bytes it received, whatever the outcome;
 *   - answers only with the 32-byte output or { ok: false }, never with error details;
 *   - closes itself; the page also terminates it, which releases the WebAssembly memory.
 * The worker script is served by CipherMesh itself and runs under the same CSP, which allows
 * WebAssembly compilation through 'wasm-unsafe-eval' and nothing else (ADR-010).
 */
interface DedicatedWorkerScope {
  onmessage: ((event: { readonly data: unknown }) => void) | null;
  postMessage(message: KdfResponse, transfer: ArrayBuffer[]): void;
  close(): void;
}

const scope = globalThis as unknown as DedicatedWorkerScope;
let started = false;

scope.onmessage = (event) => {
  if (started) return;
  started = true;
  void derive(event.data);
};

async function derive(data: unknown): Promise<void> {
  const request = parseKdfRequest(data);
  if (request === undefined) {
    scope.postMessage({ ok: false }, []);
    scope.close();
    return;
  }
  try {
    const argon2id = await loadArgon2id();
    const output = argon2id(request);
    scope.postMessage({ ok: true, output: output.buffer }, [output.buffer]);
  } catch {
    scope.postMessage({ ok: false }, []);
  } finally {
    request.password.fill(0);
    scope.close();
  }
}
