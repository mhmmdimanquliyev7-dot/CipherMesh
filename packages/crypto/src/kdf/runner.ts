import { CryptoError, CryptoErrorCode } from '../errors';
import type { Bytes } from '../types';
import { loadArgon2id } from './argon2id';
import { parseKdfResponse, type KdfRequest, type KdfRequestMessage } from './protocol';

/**
 * Where Argon2id runs. Browsers use a fresh dedicated Web Worker per derivation (ADR-010);
 * Node.js tests use the same engine in-process. There is no other runner and no fallback to a
 * weaker KDF: if workers or WebAssembly are unavailable, derivation fails closed (INV-15).
 */
export interface KdfRunner {
  run(request: KdfRequest): Promise<Bytes>;
}

/** A derivation that takes longer than this is treated as failed and its worker is terminated. */
const WORKER_TIMEOUT_MS = 120_000;

export function createWorkerRunner(): KdfRunner {
  return {
    run: (request) =>
      new Promise<Bytes>((resolve, reject) => {
        if (typeof Worker !== 'function' || typeof WebAssembly !== 'object') {
          reject(new CryptoError(CryptoErrorCode.UNAVAILABLE));
          return;
        }
        let worker: Worker;
        try {
          worker = new Worker(new URL('./argon2id.worker.ts', import.meta.url), {
            type: 'module',
            name: 'cm-argon2id',
          });
        } catch {
          reject(new CryptoError(CryptoErrorCode.UNAVAILABLE));
          return;
        }
        const fail = (code: CryptoErrorCode): void => {
          clearTimeout(timer);
          worker.terminate();
          reject(new CryptoError(code));
        };
        const timer = setTimeout(() => {
          fail(CryptoErrorCode.KDF_FAILED);
        }, WORKER_TIMEOUT_MS);
        worker.onmessage = (event: MessageEvent<unknown>) => {
          clearTimeout(timer);
          worker.terminate();
          const output = parseKdfResponse(event.data);
          if (output === undefined) reject(new CryptoError(CryptoErrorCode.KDF_FAILED));
          else resolve(output);
        };
        worker.onerror = (event: ErrorEvent) => {
          // The event may describe the failure; it is not logged or forwarded.
          event.preventDefault();
          fail(CryptoErrorCode.KDF_FAILED);
        };
        worker.onmessageerror = () => {
          fail(CryptoErrorCode.KDF_FAILED);
        };
        // The password moves to the worker (transfer): this side keeps only a detached buffer.
        const password = new Uint8Array(request.password);
        request.password.fill(0);
        const message: KdfRequestMessage = {
          type: 'argon2id',
          password: password.buffer,
          salt: new Uint8Array(request.salt).buffer,
          memoryKiB: request.memoryKiB,
          iterations: request.iterations,
          parallelism: request.parallelism,
        };
        worker.postMessage(message, [message.password]);
      }),
  };
}

/**
 * The same engine on the calling thread. For Node.js (tests and benchmarks), where there is no
 * page to keep responsive. The browser application never uses it.
 */
export function createInProcessRunner(): KdfRunner {
  return {
    run: async (request) => {
      try {
        const argon2id = await loadArgon2id();
        return argon2id(request);
      } catch (error) {
        if (error instanceof CryptoError) throw error;
        throw new CryptoError(CryptoErrorCode.KDF_FAILED);
      } finally {
        request.password.fill(0);
      }
    },
  };
}
