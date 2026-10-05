import { afterEach, describe, expect, it, vi } from 'vitest';
import { CryptoError, CryptoErrorCode, isCryptoError } from './errors';
import { loadArgon2id } from './kdf/argon2id';
import { deriveVaultRootKey } from './kdf/derive';
import type { KdfRequest, KdfRequestMessage } from './kdf/protocol';
import { createInProcessRunner, createWorkerRunner } from './kdf/runner';
import { VAULT_KDF } from './params';
import { randomBytes, randomUuidV4 } from './random';
import { cryptoApi, guarded, subtle } from './webcrypto';

// INV-15 and CD-14: when a required primitive is missing or misbehaves, every path fails closed
// with a fixed error code and never falls back to something weaker. The environment is changed
// with stubs, which are removed after each test.

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught), String(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
}

function expectCodeSync(run: () => unknown, code: string): void {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught), String(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
}

const request = (): KdfRequest => ({
  password: new TextEncoder().encode('correct horse battery staple'),
  salt: new Uint8Array(VAULT_KDF.saltBytes).fill(2),
  ...VAULT_KDF.floor,
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('platform cryptography missing (secure context required)', () => {
  it('WebCrypto without subtle, or without a CSPRNG, gives CRYPTO_UNAVAILABLE', () => {
    vi.stubGlobal('crypto', { getRandomValues: <T>(array: T): T => array });
    expectCodeSync(() => subtle(), CryptoErrorCode.UNAVAILABLE);
    vi.stubGlobal('crypto', undefined);
    expectCodeSync(() => cryptoApi(), CryptoErrorCode.UNAVAILABLE);
    expectCodeSync(() => randomBytes(16), CryptoErrorCode.UNAVAILABLE);
  });

  it('randomUUID missing gives CRYPTO_UNAVAILABLE, never a home-made UUID', () => {
    vi.stubGlobal('crypto', { getRandomValues: <T>(array: T): T => array });
    expectCodeSync(() => randomUuidV4(), CryptoErrorCode.UNAVAILABLE);
  });

  it('randomBytes refuses lengths outside 1 to 65,536', () => {
    for (const length of [0, -1, 1.5, 65_537, Number.NaN]) {
      expectCodeSync(() => randomBytes(length), CryptoErrorCode.INVALID_INPUT);
    }
    expect(randomBytes(65_536)).toHaveLength(65_536);
  });

  it('guarded() replaces library errors by its fixed code but keeps CipherMesh errors', async () => {
    await expectCode(
      guarded(CryptoErrorCode.AUTHENTICATION_FAILED, () => Promise.reject(new Error('OperationError: details'))),
      CryptoErrorCode.AUTHENTICATION_FAILED,
    );
    await expectCode(
      guarded(CryptoErrorCode.AUTHENTICATION_FAILED, () =>
        Promise.reject(new CryptoError(CryptoErrorCode.IDENTITY_INVALID)),
      ),
      CryptoErrorCode.IDENTITY_INVALID,
    );
  });
});

describe('Argon2id WebAssembly unavailable', () => {
  it('no WebAssembly gives CRYPTO_UNAVAILABLE', async () => {
    vi.stubGlobal('WebAssembly', undefined);
    await expectCode(loadArgon2id(), CryptoErrorCode.UNAVAILABLE);
  });

  it("a CSP without 'wasm-unsafe-eval' (compilation refused) gives CRYPTO_UNAVAILABLE", async () => {
    vi.spyOn(WebAssembly, 'instantiate').mockRejectedValue(
      new WebAssembly.CompileError("Refused to compile WebAssembly because 'wasm-unsafe-eval' is not allowed"),
    );
    await expectCode(loadArgon2id(), CryptoErrorCode.UNAVAILABLE);
  });

  it('the in-process runner wipes the password and keeps CRYPTO_UNAVAILABLE', async () => {
    vi.spyOn(WebAssembly, 'instantiate').mockRejectedValue(new WebAssembly.CompileError('refused'));
    const input = request();
    await expectCode(createInProcessRunner().run(input), CryptoErrorCode.UNAVAILABLE);
    expect(input.password.every((b) => b === 0)).toBe(true);
  });

  it('the in-process runner reports any other library failure as KDF_FAILED', async () => {
    // The library throws a plain Error for less than 8 KiB of memory per lane.
    const input = { ...request(), memoryKiB: 8, iterations: 1, parallelism: 2 };
    await expectCode(createInProcessRunner().run(input), CryptoErrorCode.KDF_FAILED);
  });
});

describe('vault key derivation input checks', () => {
  it('lengths are enforced by CipherMesh, because the library does not check them', async () => {
    // Review finding (LIB-03): the library compares the byte arrays themselves, not their
    // lengths, with its limits, so its password and salt checks never fire for inputs of several
    // bytes. Every length is therefore validated before the library is called (protocol.ts,
    // derive.ts, and the unlock minimum in vault.ts). If a library update fixes this, this test
    // fails and the review is repeated.
    const argon2id = await loadArgon2id();
    const output = argon2id({
      password: new Uint8Array([1, 2, 3]),
      salt: new Uint8Array([4, 5, 6]),
      ...VAULT_KDF.floor,
    });
    expect(output).toHaveLength(32);
  });

  it('refuses a salt that is not 16 bytes before any work', async () => {
    let calls = 0;
    const runner = {
      run: () => {
        calls++;
        return Promise.resolve(new Uint8Array(32));
      },
    };
    await expectCode(
      deriveVaultRootKey(runner, 'a passphrase of enough length', new Uint8Array(15), VAULT_KDF.target),
      CryptoErrorCode.INVALID_INPUT,
    );
    expect(calls).toBe(0);
  });
});

/** A stand-in for the browser's Worker, scripted per test. */
class FakeWorker {
  static created: FakeWorker[] = [];
  static failOnCreate = false;
  static onPost: (worker: FakeWorker) => void = () => undefined;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: ((event: { preventDefault: () => void }) => void) | null = null;
  onmessageerror: ((event: unknown) => void) | null = null;
  terminated = false;
  posted: { message: KdfRequestMessage; transfer: ArrayBuffer[] } | undefined;
  constructor(
    readonly url: URL,
    readonly options: { type: string; name: string },
  ) {
    if (FakeWorker.failOnCreate) throw new Error('SecurityError: blocked by worker-src');
    FakeWorker.created.push(this);
  }
  postMessage(message: KdfRequestMessage, transfer: ArrayBuffer[]): void {
    this.posted = { message, transfer };
    FakeWorker.onPost(this);
  }
  terminate(): void {
    this.terminated = true;
  }
}

function useFakeWorker(onPost: (worker: FakeWorker) => void): void {
  FakeWorker.created = [];
  FakeWorker.failOnCreate = false;
  FakeWorker.onPost = onPost;
  vi.stubGlobal('Worker', FakeWorker);
}

const answer = (worker: FakeWorker, data: unknown): void => {
  queueMicrotask(() => worker.onmessage?.({ data }));
};

describe('worker runner (page side of the KDF worker boundary)', () => {
  it('starts a module worker, transfers the passphrase bytes and wipes its own copy', async () => {
    const output = new Uint8Array(32).fill(7);
    useFakeWorker((worker) => {
      answer(worker, { ok: true, output: output.slice().buffer });
    });
    const input = request();
    const sent = new Uint8Array(input.password);
    const result = await createWorkerRunner().run(input);

    expect(result).toEqual(output);
    const [worker] = FakeWorker.created;
    expect(worker?.url.pathname.endsWith('/argon2id.worker.ts')).toBe(true);
    expect(worker?.options).toEqual({ type: 'module', name: 'cm-argon2id' });
    expect(worker?.terminated).toBe(true);
    const posted = worker?.posted;
    expect(posted?.message.type).toBe('argon2id');
    expect(new Uint8Array(posted?.message.password ?? new ArrayBuffer(0))).toEqual(sent);
    expect(posted?.transfer).toEqual([posted?.message.password]);
    expect({
      memoryKiB: posted?.message.memoryKiB,
      iterations: posted?.message.iterations,
      parallelism: posted?.message.parallelism,
    }).toEqual(VAULT_KDF.floor);
    expect(input.password.every((b) => b === 0)).toBe(true);
  });

  it('a malformed or failed answer, a worker error and an undeliverable message give KDF_FAILED', async () => {
    const scripts: ((worker: FakeWorker) => void)[] = [
      (worker) => {
        answer(worker, { ok: true, output: new ArrayBuffer(31) });
      },
      (worker) => {
        answer(worker, { ok: true, output: new Uint8Array(32) });
      },
      (worker) => {
        answer(worker, { ok: false });
      },
      (worker) => {
        answer(worker, 'not an object');
      },
      (worker) => {
        queueMicrotask(() => worker.onmessageerror?.({}));
      },
    ];
    for (const script of scripts) {
      useFakeWorker(script);
      await expectCode(createWorkerRunner().run(request()), CryptoErrorCode.KDF_FAILED);
      expect(FakeWorker.created[0]?.terminated).toBe(true);
    }

    let prevented = false;
    useFakeWorker((worker) => {
      queueMicrotask(() =>
        worker.onerror?.({
          preventDefault: () => {
            prevented = true;
          },
        }),
      );
    });
    await expectCode(createWorkerRunner().run(request()), CryptoErrorCode.KDF_FAILED);
    // The error event is consumed, so its details are not reported to the console.
    expect(prevented).toBe(true);
  });

  it('a derivation that never answers is stopped after 120 seconds', async () => {
    vi.useFakeTimers();
    useFakeWorker(() => undefined);
    const pending = createWorkerRunner().run(request());
    const outcome = expectCode(pending, CryptoErrorCode.KDF_FAILED);
    await vi.advanceTimersByTimeAsync(119_999);
    expect(FakeWorker.created[0]?.terminated).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await outcome;
    expect(FakeWorker.created[0]?.terminated).toBe(true);
  });

  it('a worker that cannot be created, or a page without WebAssembly, gives CRYPTO_UNAVAILABLE', async () => {
    useFakeWorker(() => undefined);
    FakeWorker.failOnCreate = true;
    await expectCode(createWorkerRunner().run(request()), CryptoErrorCode.UNAVAILABLE);

    useFakeWorker(() => undefined);
    vi.stubGlobal('WebAssembly', undefined);
    await expectCode(createWorkerRunner().run(request()), CryptoErrorCode.UNAVAILABLE);
    expect(FakeWorker.created).toHaveLength(0);
  });
});
