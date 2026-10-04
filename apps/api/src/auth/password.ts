import { PASSWORD_POLICY, PasswordProblem } from '@ciphermesh/shared';
import { argon2, randomBytes, timingSafeEqual } from 'node:crypto';
import { COMMON_PASSWORDS } from './data/common-passwords';
import type { ConcurrencyLimiter } from './limits';

/**
 * Account password handling (CM-T015, INV-11). The account password authenticates to the server
 * only. It is never the Vault Passphrase and never derives vault keys (CD-01).
 *
 * Hashing: Argon2id through Node.js crypto (OpenSSL), the implementation selected as LIB-04.
 * Parameters are CP-05 as finalized by the Phase 3 benchmark (crypto-decisions.md). The result is
 * a standard PHC string: $argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>, with
 * unpadded standard base64. Passwords are hashed, never encrypted, and never logged.
 */
export const ARGON2_PARAMETERS = Object.freeze({
  memoryKiB: 65536,
  passes: 3,
  parallelism: 4,
  saltBytes: 16,
  hashBytes: 32,
});

/** Bounds for stored hashes, so a tampered row cannot make verification exhaust memory. */
const STORED_LIMITS = { minMemory: 19456, maxMemory: 1048576, minPasses: 2, maxPasses: 10, maxParallelism: 16 };

const PHC_PATTERN =
  /^\$argon2id\$v=19\$m=(\d{1,8}),t=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9+/]{22,86})\$([A-Za-z0-9+/]{22,86})$/;

interface ParsedHash {
  readonly memoryKiB: number;
  readonly passes: number;
  readonly parallelism: number;
  readonly salt: Buffer;
  readonly hash: Buffer;
}

export function parsePhc(phc: string): ParsedHash | undefined {
  const match = PHC_PATTERN.exec(phc);
  if (match === null) return undefined;
  const [, m, t, p, salt, hash] = match;
  const parsed = {
    memoryKiB: Number(m),
    passes: Number(t),
    parallelism: Number(p),
    salt: Buffer.from(String(salt), 'base64'),
    hash: Buffer.from(String(hash), 'base64'),
  };
  const ok =
    parsed.memoryKiB >= STORED_LIMITS.minMemory &&
    parsed.memoryKiB <= STORED_LIMITS.maxMemory &&
    parsed.passes >= STORED_LIMITS.minPasses &&
    parsed.passes <= STORED_LIMITS.maxPasses &&
    parsed.parallelism >= 1 &&
    parsed.parallelism <= STORED_LIMITS.maxParallelism &&
    parsed.memoryKiB >= 8 * parsed.parallelism &&
    parsed.salt.length >= 16 &&
    parsed.salt.length <= 64 &&
    parsed.hash.length >= 16 &&
    parsed.hash.length <= 64;
  return ok ? parsed : undefined;
}

const b64 = (bytes: Buffer): string => bytes.toString('base64').replace(/=+$/, '');

function argon2id(
  password: string,
  salt: Buffer,
  p: { memoryKiB: number; passes: number; parallelism: number },
  length: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    argon2(
      'argon2id',
      {
        message: Buffer.from(password, 'utf8'),
        nonce: salt,
        memory: p.memoryKiB,
        passes: p.passes,
        parallelism: p.parallelism,
        tagLength: length,
      },
      (error, derived) => {
        if (error) reject(error);
        else resolve(derived);
      },
    );
  });
}

export interface PasswordHasher {
  /** Hashes a policy-checked, NFKC-normalized password. */
  hash(normalizedPassword: string): Promise<string>;
  /** Constant-time comparison; malformed stored hashes fail closed. */
  verify(normalizedPassword: string, phc: string): Promise<{ valid: boolean; needsRehash: boolean }>;
  /** Spends the same work as a real verification, for unknown accounts (enumeration, T-15). */
  verifyDummy(normalizedPassword: string): Promise<void>;
}

/**
 * Argon2id is memory-hard on purpose. The limiter bounds how many computations run at once and how
 * many wait, so a burst of login or registration requests cannot exhaust memory (T-26, CM-T018).
 */
export function createPasswordHasher(limiter: ConcurrencyLimiter): PasswordHasher {
  const params = ARGON2_PARAMETERS;
  let dummy: Promise<string> | undefined;

  const hash = (normalizedPassword: string): Promise<string> =>
    limiter.run(async () => {
      const salt = randomBytes(params.saltBytes);
      const derived = await argon2id(normalizedPassword, salt, params, params.hashBytes);
      return `$argon2id$v=19$m=${String(params.memoryKiB)},t=${String(params.passes)},p=${String(params.parallelism)}$${b64(salt)}$${b64(derived)}`;
    });

  const verify = async (normalizedPassword: string, phc: string): Promise<{ valid: boolean; needsRehash: boolean }> => {
    const parsed = parsePhc(phc);
    if (parsed === undefined) {
      // Fail closed, but still spend the work so the response time does not reveal the defect.
      await verifyDummy(normalizedPassword);
      return { valid: false, needsRehash: false };
    }
    const derived = await limiter.run(() => argon2id(normalizedPassword, parsed.salt, parsed, parsed.hash.length));
    const valid = derived.length === parsed.hash.length && timingSafeEqual(derived, parsed.hash);
    const needsRehash =
      parsed.memoryKiB !== params.memoryKiB ||
      parsed.passes !== params.passes ||
      parsed.parallelism !== params.parallelism ||
      parsed.hash.length !== params.hashBytes ||
      parsed.salt.length !== params.saltBytes;
    return { valid, needsRehash };
  };

  const verifyDummy = async (normalizedPassword: string): Promise<void> => {
    // A hash of a random value nobody knows, created once per process with the current parameters.
    dummy ??= hash(randomBytes(32).toString('base64url'));
    const dummyHash = await dummy;
    await verify(normalizedPassword, dummyHash);
  };

  return { hash, verify, verifyDummy };
}

/** Lone UTF-16 surrogates cannot be normalized or encoded reliably, so they are refused. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;
const isWellFormed = (value: string): boolean => !LONE_SURROGATE.test(value);

let blocklist: ReadonlySet<string> | undefined;
const commonPasswords = (): ReadonlySet<string> => (blocklist ??= new Set(COMMON_PASSWORDS.split('\n')));

export type PasswordCheck =
  | { readonly ok: true; readonly normalized: string }
  | { readonly ok: false; readonly problems: readonly PasswordProblem[] };

/**
 * CP-06: NFKC normalization, 12 to 128 code points, local blocklist of breached passwords, and no
 * password built from the account's own identity. No composition rules: length and the blocklist
 * matter more than character classes. Nothing is truncated.
 */
export function checkNewPassword(raw: string, identity: { email: string; displayName: string }): PasswordCheck {
  if (!isWellFormed(raw)) return { ok: false, problems: [PasswordProblem.MALFORMED] };
  const normalized = raw.normalize('NFKC');
  // Unicode code points, not UTF-16 units: an emoji counts as one character (CP-06).
  const length = Array.from(normalized).length;
  if (length < PASSWORD_POLICY.minLength) return { ok: false, problems: [PasswordProblem.TOO_SHORT] };
  if (length > PASSWORD_POLICY.maxLength) return { ok: false, problems: [PasswordProblem.TOO_LONG] };
  const lower = normalized.toLowerCase();
  if (commonPasswords().has(lower)) return { ok: false, problems: [PasswordProblem.COMMON] };
  const localPart = identity.email.split('@')[0] ?? '';
  const identityParts = [localPart, identity.displayName.toLowerCase(), 'ciphermesh'].filter((p) => p.length >= 4);
  if (identityParts.some((part) => lower.includes(part))) {
    return { ok: false, problems: [PasswordProblem.CONTAINS_IDENTITY] };
  }
  return { ok: true, normalized };
}

/** The same normalization for verification (CD-15); length is not checked when logging in. */
export function normalizePassword(raw: string): string | undefined {
  return isWellFormed(raw) ? raw.normalize('NFKC') : undefined;
}
