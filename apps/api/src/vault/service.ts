import {
  CryptoError,
  isNotWeaker,
  publicIdentityFromWire,
  publicIdentityToWire,
  rewrapFromWire,
  rewrapStatement,
  toBase64Url,
  vaultRecordFromWire,
  verifyPublicIdentity,
  verifyStatement,
  type PublicIdentity,
  type VaultRecord,
  type VaultRewrapWire,
  type VaultWire,
  type VerifiedIdentity,
} from '@ciphermesh/crypto/identity';
import { ErrorCode } from '@ciphermesh/shared';
import type { DirectoryEntry, VaultPayload } from '@ciphermesh/validation';
import { FixedWindowLimiter } from '../auth/limits';
import type { SecurityEventSink } from '../auth/security-events';
import { rotateSession, type Actor, type IssuedSession, type RequestMeta } from '../auth/sessions';
import type {
  DirectoryRecord,
  NewIdentityRow,
  StoredVault,
  VaultStore,
  VaultTransactionStores,
} from '../db/vault-store';
import { HttpError } from '../http/errors';

/**
 * Vault and public-key directory workflows (Phase 4, CM-T025 to CM-T028; DF-03, DF-04; ADR-015).
 *
 * The server stores and serves what browsers produced: public identities, KDF metadata and the
 * AES-256-GCM ciphertext of private keys. It never receives the Vault Passphrase, a vault-derived
 * key or a plaintext private key, and has no code path that could use one (INV-01). It verifies
 * every uploaded public identity with the same code the browsers use (binding signature,
 * fingerprint, key formats), checks every size against the parameter register, and accepts a
 * re-wrap only when it is signed by the identity's own signing key.
 *
 * The owner is always the session's user (OL-10). No request field names a user.
 */
export interface VaultRateLimits {
  /** GET /vault, per user. Unlocking is offline; this only bounds automated record downloads. */
  readonly read: FixedWindowLimiter;
  /** Setup, re-wrap and reset, per user. */
  readonly write: FixedWindowLimiter;
  /** Directory lookups, per user (enumeration, T-15). */
  readonly lookup: FixedWindowLimiter;
}

export function defaultVaultRateLimits(now: () => number = Date.now): VaultRateLimits {
  return {
    read: new FixedWindowLimiter(60, 15 * 60_000, 10_000, now),
    write: new FixedWindowLimiter(10, 60 * 60_000, 10_000, now),
    lookup: new FixedWindowLimiter(20, 10 * 60_000, 10_000, now),
  };
}

export interface VaultDependencies {
  readonly store: VaultStore;
  readonly transaction: <T>(fn: (stores: VaultTransactionStores) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
  readonly limits: VaultRateLimits;
}

const rateLimited = (seconds: number): HttpError =>
  new HttpError(429, ErrorCode.RATE_LIMITED, 'Too many requests. Try again later', undefined, {
    'retry-after': String(seconds),
  });

function limit(limiter: FixedWindowLimiter, key: string): void {
  const decision = limiter.consume(key);
  if (!decision.allowed) throw rateLimited(decision.retryAfterSeconds);
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.VAULT_NOT_FOUND, 'No vault has been set up yet');
const conflict = (): HttpError =>
  new HttpError(409, ErrorCode.VAULT_CONFLICT, 'The vault changed in the meantime. Reload and try again');

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));

/** The stored public identity in the shared format, for verification and projections. */
const storedIdentity = (stored: StoredVault, userId: string): PublicIdentity =>
  publicIdentityFromWire(
    {
      keyId: stored.keyId,
      suite: stored.algorithmSuite,
      encryptionPublicKey: toBase64Url(stored.publicKeySpki),
      signingPublicKey: toBase64Url(stored.signingPublicKeySpki),
      bindingSignature: toBase64Url(stored.identitySignature),
      fingerprint: stored.publicKeyFingerprint,
    },
    userId,
  );

/**
 * A stored row outside the formats this server understands is a server-side integrity problem,
 * never something to serve: the request fails closed (500) instead of returning the row.
 */
function assertStoredFormat(row: { readonly algorithmSuite: string; readonly vaultVersion?: number }): void {
  if (row.algorithmSuite !== 'CM1' || (row.vaultVersion !== undefined && row.vaultVersion !== 1)) {
    throw new Error('A stored identity has an unsupported format');
  }
}

/** The caller's own record in wire form (GET /vault). */
export function vaultToWire(stored: StoredVault): VaultPayload {
  assertStoredFormat(stored);
  if (stored.kdfAlgorithm !== 'argon2id') throw new Error('A stored vault has an unsupported KDF');
  return {
    vaultVersion: 1,
    identity: {
      keyId: stored.keyId,
      suite: 'CM1',
      encryptionPublicKey: toBase64Url(stored.publicKeySpki),
      signingPublicKey: toBase64Url(stored.signingPublicKeySpki),
      bindingSignature: toBase64Url(stored.identitySignature),
      fingerprint: stored.publicKeyFingerprint,
    },
    kdf: {
      algorithm: 'argon2id',
      version: 19,
      memoryKiB: stored.kdfMemoryKiB,
      iterations: stored.kdfIterations,
      parallelism: stored.kdfParallelism,
      salt: toBase64Url(stored.kdfSalt),
    },
    wrappedEncryptionKey: { iv: toBase64Url(stored.privateKeyIv), ciphertext: toBase64Url(stored.encryptedPrivateKey) },
    wrappedSigningKey: {
      iv: toBase64Url(stored.signingPrivateKeyIv),
      ciphertext: toBase64Url(stored.encryptedSigningPrivateKey),
    },
  };
}

/** A directory entry in wire form: public keys and their binding only (SS-05). */
export function directoryToWire(record: DirectoryRecord): DirectoryEntry {
  assertStoredFormat(record);
  const identity = publicIdentityToWire({
    userId: record.userId,
    keyId: record.keyId,
    suite: 'CM1',
    encryptionKeySpki: new Uint8Array(record.publicKeySpki),
    signingKeySpki: new Uint8Array(record.signingPublicKeySpki),
    bindingSignature: new Uint8Array(record.identitySignature),
    fingerprint: record.publicKeyFingerprint,
  });
  return {
    user: {
      id: record.userId,
      displayName: record.displayName,
      emailVerified: false as const,
      accountCreatedAt: record.accountCreatedAt.toISOString(),
    },
    identity: {
      keyId: identity.keyId,
      suite: 'CM1',
      encryptionPublicKey: identity.encryptionPublicKey,
      signingPublicKey: identity.signingPublicKey,
      bindingSignature: identity.bindingSignature,
      fingerprint: identity.fingerprint,
      createdAt: record.keyCreatedAt.toISOString(),
    },
  };
}

function identityRow(record: VaultRecord, now: Date): NewIdentityRow {
  return {
    keyId: record.identity.keyId,
    userId: record.identity.userId,
    algorithmSuite: record.identity.suite,
    vaultVersion: record.vaultVersion,
    publicKeySpki: record.identity.encryptionKeySpki,
    signingPublicKeySpki: record.identity.signingKeySpki,
    publicKeyFingerprint: record.identity.fingerprint,
    identitySignature: record.identity.bindingSignature,
    encryptedPrivateKey: record.wrappedEncryptionKey.ciphertext,
    privateKeyIv: record.wrappedEncryptionKey.iv,
    encryptedSigningPrivateKey: record.wrappedSigningKey.ciphertext,
    signingPrivateKeyIv: record.wrappedSigningKey.iv,
    kdfMemoryKiB: record.kdf.memoryKiB,
    kdfIterations: record.kdf.iterations,
    kdfParallelism: record.kdf.parallelism,
    kdfSalt: record.kdf.salt,
    now,
  };
}

export function createVaultService(deps: VaultDependencies) {
  const { store, events, clock, limits } = deps;

  const reject = (actor: Actor, meta: RequestMeta, reason: string, error: HttpError): HttpError => {
    events.record({
      name: 'VAULT_REJECTED',
      outcome: 'DENIED',
      actorUserId: actor.userId,
      requestId: meta.requestId,
      details: { reason },
    });
    return error;
  };

  /** Strict decoding with the shared vault format; any problem is INVALID_VAULT_FORMAT. */
  function decodeVault(actor: Actor, meta: RequestMeta, wire: VaultWire): VaultRecord {
    try {
      return vaultRecordFromWire(wire, actor.userId);
    } catch (error) {
      const code = error instanceof CryptoError ? error.code.toLowerCase() : 'invalid';
      throw reject(
        actor,
        meta,
        'FORMAT',
        new HttpError(400, ErrorCode.INVALID_VAULT_FORMAT, 'The vault record is not valid', [{ path: 'vault', code }]),
      );
    }
  }

  /** Full public identity verification, the same as every client runs (ADR-015 section 2). */
  async function verifyUploadedIdentity(actor: Actor, meta: RequestMeta, identity: PublicIdentity): Promise<void> {
    try {
      await verifyPublicIdentity(identity);
    } catch {
      throw reject(
        actor,
        meta,
        'IDENTITY',
        new HttpError(400, ErrorCode.IDENTITY_REJECTED, 'The public identity could not be verified'),
      );
    }
  }

  return {
    /** GET /vault: the caller's own vault record, including the wrapped private keys (OL-10). */
    async getVault(actor: Actor): Promise<{ vault: VaultPayload; createdAt: Date; rewrappedAt: Date | null }> {
      limit(limits.read, actor.userId);
      const stored = await store.findActiveVault(actor.userId);
      if (stored === null) throw notFound();
      return { vault: vaultToWire(stored), createdAt: stored.createdAt, rewrappedAt: stored.rewrappedAt };
    },

    /** POST /vault: first vault setup (DF-03, CM-T025). Step-up is enforced by the route. */
    async createVault(actor: Actor, wire: VaultWire, meta: RequestMeta) {
      limit(limits.write, actor.userId);
      const record = decodeVault(actor, meta, wire);
      await verifyUploadedIdentity(actor, meta, record.identity);
      if (await store.hasActiveVault(actor.userId)) {
        throw new HttpError(409, ErrorCode.VAULT_ALREADY_EXISTS, 'A vault already exists for this account');
      }
      const now = clock();
      if ((await store.insertIdentity(identityRow(record, now))) === 'CONFLICT') throw conflict();
      events.record({
        name: 'VAULT_CREATED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: {
          keyId: record.identity.keyId,
          kdfMemoryKiB: record.kdf.memoryKiB,
          kdfIterations: record.kdf.iterations,
        },
      });
      return { keyId: record.identity.keyId, fingerprint: record.identity.fingerprint, createdAt: now };
    },

    /**
     * POST /vault/rewrap: Vault Passphrase change or parameter upgrade (CM-T028). The same identity
     * keeps its public keys; only the KDF section and the two ciphertexts change. Accepted only if
     *   - it names the current identity and the current salt (a captured request cannot be
     *     replayed after any later change),
     *   - the salt changes and the parameters are not weaker than the stored ones (no downgrade),
     *   - it carries a valid signature by the identity's signing key over every new byte.
     */
    async rewrapVault(actor: Actor, wire: VaultRewrapWire, meta: RequestMeta): Promise<{ rewrappedAt: Date }> {
      limit(limits.write, actor.userId);
      const stored = await store.findActiveVault(actor.userId);
      if (stored === null) throw notFound();
      if (wire.keyId !== stored.keyId) throw conflict();
      let request: ReturnType<typeof rewrapFromWire>;
      try {
        request = rewrapFromWire(wire);
      } catch (error) {
        const code = error instanceof CryptoError ? error.code.toLowerCase() : 'invalid';
        throw reject(
          actor,
          meta,
          'FORMAT',
          new HttpError(400, ErrorCode.INVALID_VAULT_FORMAT, 'The vault record is not valid', [
            { path: 'vault', code },
          ]),
        );
      }
      if (!sameBytes(request.previousKdfSalt, stored.kdfSalt)) throw conflict();
      const storedParams = {
        memoryKiB: stored.kdfMemoryKiB,
        iterations: stored.kdfIterations,
        parallelism: stored.kdfParallelism,
      };
      if (sameBytes(request.kdf.salt, stored.kdfSalt) || !isNotWeaker(request.kdf, storedParams)) {
        const code = sameBytes(request.kdf.salt, stored.kdfSalt) ? 'salt_reused' : 'kdf_downgrade';
        throw reject(
          actor,
          meta,
          'FORMAT',
          new HttpError(400, ErrorCode.INVALID_VAULT_FORMAT, 'The vault record is not valid', [{ path: 'kdf', code }]),
        );
      }
      // The stored identity was verified at upload; verifying again also imports its signing key.
      let identity: VerifiedIdentity;
      try {
        identity = await verifyPublicIdentity(storedIdentity(stored, actor.userId));
      } catch {
        throw new Error('A stored public identity failed verification');
      }
      const statement = rewrapStatement({
        userId: actor.userId,
        keyId: stored.keyId,
        previousKdfSalt: request.previousKdfSalt,
        kdf: request.kdf,
        wrappedEncryptionKey: request.wrappedEncryptionKey,
        wrappedSigningKey: request.wrappedSigningKey,
      });
      if (!(await verifyStatement(identity.signingPublicKey, statement, request.signature))) {
        throw reject(
          actor,
          meta,
          'SIGNATURE',
          new HttpError(403, ErrorCode.VAULT_SIGNATURE_INVALID, 'The vault change is not signed by the vault identity'),
        );
      }
      const now = clock();
      const applied = await store.rewrap(
        actor.userId,
        stored.keyId,
        stored.kdfSalt,
        {
          encryptedPrivateKey: request.wrappedEncryptionKey.ciphertext,
          privateKeyIv: request.wrappedEncryptionKey.iv,
          encryptedSigningPrivateKey: request.wrappedSigningKey.ciphertext,
          signingPrivateKeyIv: request.wrappedSigningKey.iv,
          kdfMemoryKiB: request.kdf.memoryKiB,
          kdfIterations: request.kdf.iterations,
          kdfParallelism: request.kdf.parallelism,
          kdfSalt: request.kdf.salt,
        },
        now,
      );
      if (!applied) throw conflict();
      events.record({
        name: 'VAULT_REWRAPPED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { keyId: stored.keyId, kdfMemoryKiB: request.kdf.memoryKiB, kdfIterations: request.kdf.iterations },
      });
      return { rewrappedAt: now };
    },

    /**
     * POST /vault/reset: replaces a lost identity with a new one (key-lifecycle section 3). The old
     * identity becomes SUPERSEDED and loses both encrypted private keys; its public keys stay for
     * audit. Other sessions are revoked, because they may hold the old private keys in memory, and
     * the current session is rotated (session-and-csrf.md section 4). All in one transaction.
     * When rooms exist (Phase 6, CM-T053), the same transaction also deletes the old identity's
     * envelopes, invalidates its pending invitations and increments the membership epochs.
     */
    async resetVault(actor: Actor, supersedesKeyId: string, wire: VaultWire, meta: RequestMeta) {
      limit(limits.write, actor.userId);
      const record = decodeVault(actor, meta, wire);
      await verifyUploadedIdentity(actor, meta, record.identity);
      const now = clock();
      // Any thrown error rolls the whole transaction back: no half-reset identity can remain.
      const outcome = await deps.transaction(async ({ vault, auth }) => {
        if (!(await vault.supersede(actor.userId, supersedesKeyId, now))) return undefined;
        if ((await vault.insertIdentity(identityRow(record, now))) === 'CONFLICT') throw conflict();
        const otherSessionsRevoked = await auth.revokeUserSessions(actor.userId, 'VAULT_RESET', now, actor.sessionId);
        const session: IssuedSession | undefined = await rotateSession(auth, actor, now);
        if (session === undefined) throw new HttpError(401, ErrorCode.UNAUTHENTICATED, 'Authentication required');
        return { otherSessionsRevoked, session };
      });
      if (outcome === undefined) throw conflict();
      events.record({
        name: 'VAULT_RESET',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: {
          supersededKeyId: supersedesKeyId,
          keyId: record.identity.keyId,
          otherSessionsRevoked: outcome.otherSessionsRevoked,
        },
      });
      return {
        keyId: record.identity.keyId,
        fingerprint: record.identity.fingerprint,
        createdAt: now,
        otherSessionsRevoked: outcome.otherSessionsRevoked,
        session: outcome.session,
      };
    },

    /**
     * POST /directory/lookup (SS-05, CM-T027): exact email match. Only users who have an identity
     * themselves may look others up. Unknown addresses, accounts without an identity and disabled
     * accounts all give the same 404, so the lookup reveals no more than registration does (L-35).
     */
    async lookup(actor: Actor, email: string, meta: RequestMeta) {
      const decision = limits.lookup.consume(actor.userId);
      if (!decision.allowed) {
        events.record({
          name: 'DIRECTORY_LOOKUP_THROTTLED',
          outcome: 'DENIED',
          actorUserId: actor.userId,
          requestId: meta.requestId,
        });
        throw rateLimited(decision.retryAfterSeconds);
      }
      if (!(await store.hasActiveVault(actor.userId))) {
        throw new HttpError(403, ErrorCode.VAULT_SETUP_REQUIRED, 'Set up your vault before looking up other users');
      }
      const record = await store.findDirectoryEntry(email);
      if (record === null) throw new HttpError(404, ErrorCode.NOT_FOUND, 'No user with an identity was found');
      return directoryToWire(record);
    },
  };
}

export type VaultService = ReturnType<typeof createVaultService>;
