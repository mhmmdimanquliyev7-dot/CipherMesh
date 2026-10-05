import { argon2Sync, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { toHex } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';
import { loadArgon2id } from './kdf/argon2id';
import { ARGON2ID_PACKAGE_VERSION, ARGON2ID_WASM_NO_SIMD, ARGON2ID_WASM_SIMD } from './kdf/argon2id-wasm';
import { deriveVaultRootKey, isDerivationRunning } from './kdf/derive';
import { parseKdfRequest, parseKdfResponse } from './kdf/protocol';
import { createInProcessRunner, createWorkerRunner, type KdfRunner } from './kdf/runner';
import { isBelowKdfTarget, VAULT_KDF } from './params';
import { isNotWeaker } from './vault-format';

// Browser Argon2id (LIB-03, CP-04, ADR-010). The library is checked against the RFC 9106 test
// vector (with secret and associated data) and against an independent implementation, OpenSSL's
// Argon2id in Node.js, for the production parameters.

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
}

describe('embedded WebAssembly (supply chain, LIB-03)', () => {
  it('equals the files of the installed, lockfile-pinned argon2id package byte for byte', () => {
    const require = createRequire(join(__dirname, '..', 'package.json'));
    const root = dirname(require.resolve('argon2id/package.json'));
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version: string };
    expect(pkg.version).toBe(ARGON2ID_PACKAGE_VERSION);
    for (const wasm of [ARGON2ID_WASM_SIMD, ARGON2ID_WASM_NO_SIMD]) {
      const installed = readFileSync(join(root, wasm.file));
      expect(Buffer.from(wasm.base64, 'base64').equals(installed)).toBe(true);
      expect(createHash('sha256').update(installed).digest('hex')).toBe(wasm.sha256);
    }
  });
});

describe('Argon2id known answers', () => {
  it('reproduces the RFC 9106 section 5.3 Argon2id test vector', async () => {
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
  });

  it('matches OpenSSL (Node.js crypto.argon2) at the floor and at the production target', async () => {
    const argon2id = await loadArgon2id();
    const password = new Uint8Array(Buffer.from('correct horse battery staple vault', 'utf8'));
    const salt = new Uint8Array(16).map((_, i) => i * 7);
    for (const p of [VAULT_KDF.floor, VAULT_KDF.target]) {
      const ours = argon2id({ password: new Uint8Array(password), salt, ...p });
      const openssl = argon2Sync('argon2id', {
        message: password,
        nonce: salt,
        parallelism: p.parallelism,
        tagLength: 32,
        memory: p.memoryKiB,
        passes: p.iterations,
      });
      expect(toHex(ours)).toBe(openssl.toString('hex'));
    }
  });
});

describe('vault key derivation: limits, concurrency and fail-closed behaviour', () => {
  const salt = new Uint8Array(16).fill(5);

  it('refuses parameters below the floor or above the ceiling before doing any work', async () => {
    let calls = 0;
    const runner: KdfRunner = {
      run: () => {
        calls++;
        return Promise.resolve(new Uint8Array(32));
      },
    };
    const cases = [
      { ...VAULT_KDF.floor, memoryKiB: VAULT_KDF.floor.memoryKiB - 1 },
      { ...VAULT_KDF.floor, iterations: 1 },
      { ...VAULT_KDF.target, parallelism: 0 },
      { ...VAULT_KDF.target, memoryKiB: VAULT_KDF.ceiling.memoryKiB + 1 },
      { ...VAULT_KDF.target, iterations: VAULT_KDF.ceiling.iterations + 1 },
      { ...VAULT_KDF.target, memoryKiB: 65536.5 },
    ];
    for (const params of cases) {
      await expectCode(
        deriveVaultRootKey(runner, 'a passphrase of decent length', salt, params),
        CryptoErrorCode.KDF_PARAMETERS_OUT_OF_RANGE,
      );
    }
    expect(calls).toBe(0);
  });

  it('runs one derivation at a time and refuses a second one while busy', async () => {
    let release: (() => void) | undefined;
    const runner: KdfRunner = {
      run: () =>
        new Promise((resolve) => {
          release = () => {
            resolve(new Uint8Array(32).fill(1));
          };
        }),
    };
    const first = deriveVaultRootKey(runner, 'a passphrase of decent length', salt, VAULT_KDF.target);
    expect(isDerivationRunning()).toBe(true);
    await expectCode(
      deriveVaultRootKey(runner, 'another passphrase', salt, VAULT_KDF.target),
      CryptoErrorCode.KDF_BUSY,
    );
    release?.();
    await expect(first).resolves.toBeDefined();
    expect(isDerivationRunning()).toBe(false);
  });

  it('wipes the passphrase bytes it handed to the runner and rejects outputs of the wrong size', async () => {
    let seen: Uint8Array | undefined;
    const runner: KdfRunner = {
      run: (request) => {
        seen = request.password;
        return Promise.resolve(new Uint8Array(31));
      },
    };
    await expectCode(
      deriveVaultRootKey(runner, 'a passphrase of decent length', salt, VAULT_KDF.target),
      CryptoErrorCode.KDF_FAILED,
    );
    expect(seen?.every((b) => b === 0)).toBe(true);
  });

  it('the derived root key is a non-extractable HKDF key', async () => {
    const key = await deriveVaultRootKey(
      createInProcessRunner(),
      'a passphrase of decent length',
      salt,
      VAULT_KDF.floor,
    );
    expect(key.extractable).toBe(false);
    expect(key.algorithm.name).toBe('HKDF');
    expect([...key.usages].sort()).toEqual(['deriveBits', 'deriveKey']);
  });

  it('fails closed where Web Workers do not exist (no main-thread or weaker fallback)', async () => {
    expect(typeof (globalThis as { Worker?: unknown }).Worker).toBe('undefined');
    await expectCode(
      createWorkerRunner().run({ password: new Uint8Array(20), salt, ...VAULT_KDF.target }),
      CryptoErrorCode.UNAVAILABLE,
    );
  });
});

describe('worker message protocol (trust boundary inside the client)', () => {
  const valid = {
    type: 'argon2id',
    password: new Uint8Array(20).buffer,
    salt: new Uint8Array(16).buffer,
    ...VAULT_KDF.target,
  };

  it('accepts exactly one well-formed request shape', () => {
    expect(parseKdfRequest(valid)).toBeDefined();
    for (const bad of [
      null,
      'argon2id',
      { ...valid, type: 'scrypt' },
      { ...valid, password: 'not bytes' },
      { ...valid, password: new ArrayBuffer(0) },
      { ...valid, password: new ArrayBuffer(1025) },
      { ...valid, salt: new ArrayBuffer(8) },
      { ...valid, memoryKiB: 1024 },
      { ...valid, iterations: '3' },
    ]) {
      expect(parseKdfRequest(bad)).toBeUndefined();
    }
  });

  it('accepts only a 32-byte result', () => {
    expect(parseKdfResponse({ ok: true, output: new ArrayBuffer(32) })).toHaveLength(32);
    for (const bad of [{ ok: false }, { ok: true, output: new ArrayBuffer(31) }, { ok: true }, 'x']) {
      expect(parseKdfResponse(bad)).toBeUndefined();
    }
  });
});

describe('parameter comparisons (upgrade offer and re-wrap downgrade check)', () => {
  it('compare memory and passes separately', () => {
    const { target } = VAULT_KDF;
    expect(isBelowKdfTarget(target)).toBe(false);
    expect(isBelowKdfTarget({ ...target, memoryKiB: target.memoryKiB - 1 })).toBe(true);
    expect(isBelowKdfTarget({ ...target, iterations: target.iterations - 1 })).toBe(true);
    expect(isNotWeaker(target, target)).toBe(true);
    expect(isNotWeaker({ ...target, memoryKiB: target.memoryKiB * 2 }, target)).toBe(true);
    expect(isNotWeaker({ ...target, memoryKiB: target.memoryKiB - 1 }, target)).toBe(false);
    expect(isNotWeaker({ ...target, iterations: target.iterations - 1 }, target)).toBe(false);
  });
});
