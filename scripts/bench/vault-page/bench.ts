// Browser side of `pnpm bench:vault` (scripts/bench/vault-browsers.mjs). It measures the real
// @ciphermesh/crypto code, bundled with its Argon2id worker the way the web client uses it, under
// the production Content-Security-Policy. Identifiers and passphrases are synthetic and random;
// only timings and booleans leave the page.
import {
  changeVaultPassphrase,
  CryptoErrorCode,
  createVault,
  createWorkerRunner,
  isCryptoError,
  unlockVault,
  VAULT_KDF,
  type Argon2idParameters,
  type VaultRecord,
} from '@ciphermesh/crypto';

interface Row {
  readonly name: string;
  readonly times: number[];
}

export interface BenchResult {
  readonly userAgent: string;
  readonly hardwareConcurrency: number;
  readonly rows: Row[];
  /** Longest gap between 10 ms timer ticks on the page while a target derivation ran. */
  readonly maxMainThreadGapMs: number;
  /** A second derivation started while one runs is refused with KDF_BUSY (derive.ts). */
  readonly concurrentDerivationRefused: boolean;
  /** A wrong passphrase is refused with the generic VAULT_UNLOCK_FAILED. */
  readonly wrongPassphraseRefused: boolean;
}

const runner = createWorkerRunner();
const account = { email: 'synthetic.benchmark@example.test', displayName: 'Synthetic Benchmark' };
// Random UUIDs pass the passphrase policy and never contain the account's name parts.
const passphrase = (): string => `${crypto.randomUUID()} ${crypto.randomUUID()}`;

async function time(task: () => Promise<unknown>): Promise<number> {
  const start = performance.now();
  await task();
  return performance.now() - start;
}

async function repeat(name: string, count: number, task: () => Promise<unknown>): Promise<Row> {
  const times: number[] = [];
  for (let i = 0; i < count; i++) times.push(await time(task));
  return { name, times };
}

/** One Argon2id derivation in a fresh worker, as every unlock does (worker start included). */
const derive = (params: Argon2idParameters) => () =>
  runner.run({
    password: new TextEncoder().encode(passphrase()),
    salt: crypto.getRandomValues(new Uint8Array(VAULT_KDF.saltBytes)),
    memoryKiB: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
  });

async function maxTimerGap(task: () => Promise<unknown>): Promise<number> {
  let last = performance.now();
  let gap = 0;
  const timer = setInterval(() => {
    const now = performance.now();
    gap = Math.max(gap, now - last);
    last = now;
  }, 10);
  try {
    await task();
  } finally {
    clearInterval(timer);
  }
  return gap;
}

async function refusedWith(promise: Promise<unknown>, code: CryptoErrorCode): Promise<boolean> {
  try {
    await promise;
    return false;
  } catch (error) {
    return isCryptoError(error) && error.code === code;
  }
}

async function runVaultBench(): Promise<BenchResult> {
  const userId = crypto.randomUUID();
  let secret = passphrase();
  let record: VaultRecord | undefined;
  const rows: Row[] = [
    await repeat('Argon2id at the floor (m = 19456 KiB, t = 2, p = 1)', 3, derive(VAULT_KDF.floor)),
    await repeat('Argon2id at the target (m = 65536 KiB, t = 3, p = 1)', 5, derive(VAULT_KDF.target)),
    await repeat('Vault setup: RSA-3072 and ECDSA P-256 keys, Argon2id, wrapping, self-check', 5, async () => {
      secret = passphrase();
      record = (await createVault({ userId, passphrase: secret, account, runner })).record;
    }),
  ];
  if (record === undefined) throw new Error('setup produced no record');
  const stored = record;
  rows.push(
    await repeat('Vault unlock: Argon2id, unwrapping, pair checks', 5, () =>
      unlockVault({ record: stored, userId, passphrase: secret, runner }),
    ),
    await repeat('Passphrase change: two derivations, re-wrap, signature', 3, () =>
      changeVaultPassphrase({
        record: stored,
        userId,
        currentPassphrase: secret,
        newPassphrase: passphrase(),
        account,
        runner,
      }),
    ),
  );
  const maxMainThreadGapMs = await maxTimerGap(derive(VAULT_KDF.target));
  // Two unlocks at once: exactly one derives, the other is refused instead of queued.
  const both = await Promise.allSettled([
    unlockVault({ record: stored, userId, passphrase: secret, runner }),
    unlockVault({ record: stored, userId, passphrase: secret, runner }),
  ]);
  const busy = both.filter(
    (r) => r.status === 'rejected' && isCryptoError(r.reason) && r.reason.code === CryptoErrorCode.KDF_BUSY,
  );
  const concurrentDerivationRefused = busy.length === 1 && both.some((r) => r.status === 'fulfilled');
  const wrongPassphraseRefused = await refusedWith(
    unlockVault({ record: stored, userId, passphrase: `${secret}x`, runner }),
    CryptoErrorCode.VAULT_UNLOCK_FAILED,
  );
  return {
    userAgent: navigator.userAgent,
    hardwareConcurrency: navigator.hardwareConcurrency,
    rows,
    maxMainThreadGapMs,
    concurrentDerivationRefused,
    wrongPassphraseRefused,
  };
}

Object.assign(window, { runVaultBench });
