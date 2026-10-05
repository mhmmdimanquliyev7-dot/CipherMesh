import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadArgon2id } from './kdf/argon2id';
import { VAULT_KDF } from './params';

// The Argon2id worker script (kdf/argon2id.worker.ts), run in Node.js with the three members of
// the dedicated-worker scope it uses (onmessage, postMessage, close) replaced by recorders. The
// browser behaviour of the same script is covered by the Playwright vault tests.

interface Posted {
  readonly message: unknown;
  readonly transfer: readonly unknown[];
}

let posted: Posted[] = [];
let closed = 0;

async function startWorker(): Promise<(data: unknown) => void> {
  posted = [];
  closed = 0;
  vi.stubGlobal('postMessage', (message: unknown, transfer: readonly unknown[]) => {
    posted.push({ message, transfer });
  });
  vi.stubGlobal('close', () => {
    closed++;
  });
  vi.stubGlobal('onmessage', null);
  vi.resetModules();
  await import('./kdf/argon2id.worker');
  const handler: unknown = (globalThis as { onmessage?: unknown }).onmessage;
  if (typeof handler !== 'function') throw new Error('the worker installed no message handler');
  return (data) => {
    (handler as (event: { readonly data: unknown }) => void)({ data });
  };
}

const SALT = 5;
const request = (overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> => ({
  type: 'argon2id',
  password: new TextEncoder().encode('a vault passphrase for the worker test').buffer,
  salt: new Uint8Array(VAULT_KDF.saltBytes).fill(SALT).buffer,
  ...VAULT_KDF.floor,
  ...overrides,
});

const zeroed = (buffer: unknown): boolean => new Uint8Array(buffer as ArrayBuffer).every((b) => b === 0);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Argon2id worker script', () => {
  it('derives, transfers only the 32-byte result, wipes the passphrase bytes and closes', async () => {
    const send = await startWorker();
    const message = request();
    const password = new Uint8Array((message['password'] as ArrayBuffer).slice(0));
    const expected = (await loadArgon2id())({
      password,
      salt: new Uint8Array(VAULT_KDF.saltBytes).fill(SALT),
      ...VAULT_KDF.floor,
    });

    send(message);
    await vi.waitFor(
      () => {
        expect(closed).toBe(1);
      },
      { timeout: 30_000 },
    );
    expect(posted).toHaveLength(1);
    const answer = posted[0]?.message as { ok: boolean; output: ArrayBuffer };
    expect(answer.ok).toBe(true);
    expect(Object.keys(answer).sort()).toEqual(['ok', 'output']);
    expect(new Uint8Array(answer.output)).toEqual(expected);
    expect(posted[0]?.transfer).toEqual([answer.output]);
    expect(zeroed(message['password'])).toBe(true);
  });

  it('answers a malformed request with a bare failure flag and closes', async () => {
    for (const bad of [
      request({ salt: new ArrayBuffer(15) }),
      request({ password: 'a string instead of bytes' }),
      request({ memoryKiB: 1024 }),
      request({ type: 'something-else' }),
      'not an object',
    ]) {
      const send = await startWorker();
      send(bad);
      expect(posted).toEqual([{ message: { ok: false }, transfer: [] }]);
      expect(closed).toBe(1);
    }
  });

  it('accepts exactly one message and ignores any later one', async () => {
    const send = await startWorker();
    send(request({ type: 'something-else' }));
    send(request());
    expect(posted).toEqual([{ message: { ok: false }, transfer: [] }]);
    expect(closed).toBe(1);
  });

  it('reports a bare failure, not an error text, when Argon2id cannot run, and still wipes the passphrase', async () => {
    const send = await startWorker();
    vi.stubGlobal('WebAssembly', undefined);
    const message = request();
    send(message);
    await vi.waitFor(() => {
      expect(closed).toBe(1);
    });
    expect(posted).toEqual([{ message: { ok: false }, transfer: [] }]);
    expect(zeroed(message['password'])).toBe(true);
  });
});
