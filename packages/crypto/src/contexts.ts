import { canonicalBytes, type CanonicalValue } from './canonical';
import { fromBase64Url } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { ECDSA, RSA_OAEP, SUITE, VAULT_KDF, VAULT_VERSION, WRAPPED_KEY_BYTES } from './params';
import type { Bytes } from './types';

/**
 * Canonical contexts (CP-15, cryptographic-architecture.md section 8). Every AAD, RSA-OAEP label,
 * HKDF info value, signed statement and fingerprint input is the RFC 8785 serialization of
 * {ctx, v, ...fields} with the fixed field set below. This module is the only producer of those
 * bytes: functions that take an AAD, a label, an info value or a statement accept only the
 * branded `CanonicalBytes` type returned here, so ad-hoc string concatenation cannot reach them.
 *
 * Every field is required and validated: a missing, extra or malformed field throws instead of
 * producing bytes that a peer would reject later. `ctx` gives domain separation between
 * purposes; `v` versions the field set.
 */

declare const canonicalBrand: unique symbol;

/** Bytes produced only by contextBytes(). */
export type CanonicalBytes = Bytes & { readonly [canonicalBrand]: 'CanonicalBytes' };

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** What each field kind accepts. */
interface FieldKinds {
  readonly uuid: string;
  readonly suite: typeof SUITE;
  readonly purpose: 'encryption' | 'signing';
  readonly fingerprint: string;
  readonly keyVersion: number;
  readonly revision: number;
  readonly vaultVersion: typeof VAULT_VERSION;
  readonly itemType: 'file' | 'note';
  readonly serverKeyId: string;
  readonly kdfAlgorithm: 'argon2id';
  readonly count: number;
  readonly salt: string;
  readonly iv: string;
  readonly challenge: string;
  readonly encryptionSpki: string;
  readonly signingSpki: string;
  readonly wrappedEncryptionKey: string;
  readonly wrappedSigningKey: string;
}
type FieldKind = keyof FieldKinds;

interface ContextSpec {
  readonly v: number;
  readonly fields: Readonly<Record<string, FieldKind>>;
}

const CONTEXTS = {
  // ------------------------------------------------------------------- vault and identity (Phase 4)
  /** HKDF info for the vault key that wraps one private key (purpose: encryption or signing). */
  'cm.vault.pk-wrap': { v: 1, fields: { userId: 'uuid', keyId: 'uuid', purpose: 'purpose' } },
  /** AES-GCM AAD of one wrapped private key. */
  'cm.vault.private-key': {
    v: 1,
    fields: {
      userId: 'uuid',
      keyId: 'uuid',
      purpose: 'purpose',
      fingerprint: 'fingerprint',
      suite: 'suite',
      vaultVersion: 'vaultVersion',
    },
  },
  /** RSA-OAEP label of the 32-byte pair-check value encrypted during unlock (INV-17). */
  'cm.vault.pair-check': { v: 1, fields: { userId: 'uuid', keyId: 'uuid', suite: 'suite' } },
  /** Statement signed during unlock to check that the signing key matches its public key. */
  'cm.vault.signing-check': { v: 1, fields: { userId: 'uuid', keyId: 'uuid', challenge: 'challenge' } },
  /** Statement signed with the identity key to authorize a vault re-wrap (ADR-015 section 3). */
  'cm.vault.rewrap': {
    v: 1,
    fields: {
      userId: 'uuid',
      keyId: 'uuid',
      suite: 'suite',
      vaultVersion: 'vaultVersion',
      previousKdfSalt: 'salt',
      kdfAlgorithm: 'kdfAlgorithm',
      kdfMemoryKiB: 'count',
      kdfIterations: 'count',
      kdfParallelism: 'count',
      kdfSalt: 'salt',
      encryptionKeyIv: 'iv',
      encryptionKeyCiphertext: 'wrappedEncryptionKey',
      signingKeyIv: 'iv',
      signingKeyCiphertext: 'wrappedSigningKey',
    },
  },
  /** Statement signed by the identity's own signing key (ADR-015 section 2). */
  'cm.identity.binding': {
    v: 1,
    fields: {
      userId: 'uuid',
      keyId: 'uuid',
      suite: 'suite',
      encryptionKeySpki: 'encryptionSpki',
      signingKeySpki: 'signingSpki',
    },
  },
  /** SHA-256 input of the identity fingerprint (CP-17). */
  'cm.identity.fingerprint': {
    v: 1,
    fields: { suite: 'suite', encryptionKeySpki: 'encryptionSpki', signingKeySpki: 'signingSpki' },
  },
  // ------------------------------------------------------------ rooms and content (Phases 6 to 9)
  'cm.room.envelope': {
    v: 1,
    fields: {
      roomId: 'uuid',
      keyVersion: 'keyVersion',
      recipientUserId: 'uuid',
      recipientKeyId: 'uuid',
      suite: 'suite',
    },
  },
  'cm.room.dek-wrap-key': { v: 1, fields: { roomId: 'uuid', keyVersion: 'keyVersion' } },
  'cm.room.commitment': { v: 1, fields: { roomId: 'uuid', keyVersion: 'keyVersion' } },
  'cm.room.safety-code': { v: 1, fields: { roomId: 'uuid', keyVersion: 'keyVersion' } },
  'cm.dek.wrap': {
    v: 1,
    fields: {
      roomId: 'uuid',
      keyVersion: 'keyVersion',
      itemType: 'itemType',
      itemId: 'uuid',
      revision: 'revision',
    },
  },
  'cm.file.content': { v: 1, fields: { roomId: 'uuid', fileId: 'uuid' } },
  'cm.file.manifest': { v: 1, fields: { roomId: 'uuid', fileId: 'uuid' } },
  'cm.note.content': { v: 1, fields: { roomId: 'uuid', noteId: 'uuid', revision: 'revision' } },
  'cm.secret.sek-wrap': {
    v: 1,
    fields: {
      roomId: 'uuid',
      secretId: 'uuid',
      recipientUserId: 'uuid',
      recipientKeyId: 'uuid',
      suite: 'suite',
    },
  },
  'cm.secret.payload': { v: 1, fields: { roomId: 'uuid', secretId: 'uuid' } },
  // ------------------------------------------------------------------- server domain (CP-11, CD-22)
  /** AAD of a TOTP secret encrypted by the API under TOTP_ENCRYPTION_KEY. */
  'cm.srv.totp': { v: 1, fields: { userId: 'uuid', keyId: 'serverKeyId' } },
} as const satisfies Readonly<Record<string, ContextSpec>>;

type Contexts = typeof CONTEXTS;
export type ContextName = keyof Contexts;

/** The exact field set of a context, with the value type of each field kind. */
export type ContextFields<N extends ContextName> = {
  readonly [F in keyof Contexts[N]['fields']]: Contexts[N]['fields'][F] extends FieldKind
    ? FieldKinds[Contexts[N]['fields'][F]]
    : never;
};

const isCount = (value: unknown, min: number): boolean =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= min;

function isBase64UrlOf(value: unknown, min: number, max: number): boolean {
  if (typeof value !== 'string') return false;
  try {
    const length = fromBase64Url(value).length;
    return length >= min && length <= max;
  } catch {
    return false;
  }
}

const VALIDATORS: Readonly<Record<FieldKind, (value: unknown) => boolean>> = {
  uuid: (v) => typeof v === 'string' && UUID_V4.test(v),
  suite: (v) => v === SUITE,
  purpose: (v) => v === 'encryption' || v === 'signing',
  fingerprint: (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v),
  keyVersion: (v) => isCount(v, 1),
  revision: (v) => isCount(v, 0),
  vaultVersion: (v) => v === VAULT_VERSION,
  itemType: (v) => v === 'file' || v === 'note',
  serverKeyId: (v) => typeof v === 'string' && /^[a-z0-9][a-z0-9-]{0,62}$/.test(v),
  kdfAlgorithm: (v) => v === VAULT_KDF.algorithm,
  count: (v) => isCount(v, 0),
  salt: (v) => isBase64UrlOf(v, VAULT_KDF.saltBytes, VAULT_KDF.saltBytes),
  iv: (v) => isBase64UrlOf(v, 12, 12),
  challenge: (v) => isBase64UrlOf(v, 32, 32),
  encryptionSpki: (v) => isBase64UrlOf(v, RSA_OAEP.spkiBytes, RSA_OAEP.spkiBytes),
  signingSpki: (v) => isBase64UrlOf(v, ECDSA.spkiBytes, ECDSA.spkiBytes),
  wrappedEncryptionKey: (v) => isBase64UrlOf(v, WRAPPED_KEY_BYTES.encryption.min, WRAPPED_KEY_BYTES.encryption.max),
  wrappedSigningKey: (v) => isBase64UrlOf(v, WRAPPED_KEY_BYTES.signing.min, WRAPPED_KEY_BYTES.signing.max),
};

/**
 * Builds the canonical bytes of a context. Throws CRYPTO_INVALID_INPUT for an unknown context, a
 * missing or extra field, or a field value of the wrong kind.
 */
export function contextBytes<N extends ContextName>(name: N, fields: ContextFields<N>): CanonicalBytes {
  if (!Object.hasOwn(CONTEXTS, name)) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  const spec: ContextSpec = CONTEXTS[name];
  const given = fields as Readonly<Record<string, unknown>>;
  const expected = Object.keys(spec.fields);
  const supplied = Object.keys(given);
  if (supplied.length !== expected.length || !expected.every((key) => Object.hasOwn(given, key))) {
    throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  }
  const object: Record<string, CanonicalValue> = { ctx: name, v: spec.v };
  for (const key of expected) {
    const kind = spec.fields[key];
    const value = given[key];
    if (kind === undefined || !VALIDATORS[kind](value)) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
    object[key] = value as CanonicalValue;
  }
  return canonicalBytes(object) as CanonicalBytes;
}

/** The names of every context, for tests and documentation checks. */
export const CONTEXT_NAMES: readonly ContextName[] = Object.freeze(Object.keys(CONTEXTS) as ContextName[]);
