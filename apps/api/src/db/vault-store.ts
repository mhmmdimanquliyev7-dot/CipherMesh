import { Prisma, type PrismaClient } from '../generated/prisma/client';
import { createAuthStore, type AuthStore } from './auth-store';

/**
 * Data access for the cryptographic identity and Vault (Phase 4, CM-T025 to CM-T028). The only
 * module that touches user_key_pairs. Every result is an explicit projection, and the private-key
 * ciphertexts are selected only for their owner's own vault (OL-10); the directory projection has
 * no ciphertext, salt or KDF column at all.
 *
 * Writes are conditional single statements whose row count decides the outcome: a re-wrap applies
 * only if the salt the client signed against is still current, and a reset supersedes only the
 * identity the client named. Concurrent requests therefore cannot both win.
 */
type Db = PrismaClient | Prisma.TransactionClient;

/** The caller's own vault record, as stored. Bytes are returned as they are; the service encodes. */
export interface StoredVault {
  readonly keyId: string;
  readonly algorithmSuite: string;
  readonly vaultVersion: number;
  readonly publicKeySpki: Uint8Array;
  readonly signingPublicKeySpki: Uint8Array;
  readonly publicKeyFingerprint: string;
  readonly identitySignature: Uint8Array;
  readonly encryptedPrivateKey: Uint8Array;
  readonly privateKeyIv: Uint8Array;
  readonly encryptedSigningPrivateKey: Uint8Array;
  readonly signingPrivateKeyIv: Uint8Array;
  readonly kdfAlgorithm: string;
  readonly kdfMemoryKiB: number;
  readonly kdfIterations: number;
  readonly kdfParallelism: number;
  readonly kdfSalt: Uint8Array;
  readonly createdAt: Date;
  readonly rewrappedAt: Date | null;
}

/** What a new identity row contains. Only public data and ciphertext produced by the browser. */
export interface NewIdentityRow {
  readonly keyId: string;
  readonly userId: string;
  readonly algorithmSuite: string;
  readonly vaultVersion: number;
  readonly publicKeySpki: Uint8Array;
  readonly signingPublicKeySpki: Uint8Array;
  readonly publicKeyFingerprint: string;
  readonly identitySignature: Uint8Array;
  readonly encryptedPrivateKey: Uint8Array;
  readonly privateKeyIv: Uint8Array;
  readonly encryptedSigningPrivateKey: Uint8Array;
  readonly signingPrivateKeyIv: Uint8Array;
  readonly kdfMemoryKiB: number;
  readonly kdfIterations: number;
  readonly kdfParallelism: number;
  readonly kdfSalt: Uint8Array;
  readonly now: Date;
}

/** The fields a re-wrap replaces: the KDF section and both wrapped keys. The identity stays. */
export interface RewrapUpdate {
  readonly encryptedPrivateKey: Uint8Array;
  readonly privateKeyIv: Uint8Array;
  readonly encryptedSigningPrivateKey: Uint8Array;
  readonly signingPrivateKeyIv: Uint8Array;
  readonly kdfMemoryKiB: number;
  readonly kdfIterations: number;
  readonly kdfParallelism: number;
  readonly kdfSalt: Uint8Array;
}

/** A public directory entry: only what SS-05 allows another user to see. */
export interface DirectoryRecord {
  readonly userId: string;
  readonly displayName: string;
  readonly accountCreatedAt: Date;
  readonly keyId: string;
  readonly algorithmSuite: string;
  readonly publicKeySpki: Uint8Array;
  readonly signingPublicKeySpki: Uint8Array;
  readonly identitySignature: Uint8Array;
  readonly publicKeyFingerprint: string;
  readonly keyCreatedAt: Date;
}

const vaultSelect = {
  id: true,
  algorithmSuite: true,
  vaultVersion: true,
  publicKeySpki: true,
  signingPublicKeySpki: true,
  publicKeyFingerprint: true,
  identitySignature: true,
  encryptedPrivateKey: true,
  privateKeyIv: true,
  encryptedSigningPrivateKey: true,
  signingPrivateKeyIv: true,
  kdfAlgorithm: true,
  kdfMemoryKiB: true,
  kdfIterations: true,
  kdfParallelism: true,
  kdfSalt: true,
  createdAt: true,
  rewrappedAt: true,
} as const;

const bytes = (value: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(value);

export function createVaultStore(db: Db) {
  return {
    /** The ACTIVE identity of `userId` with its wrapped keys, or null. Owner only (OL-10). */
    async findActiveVault(userId: string): Promise<StoredVault | null> {
      const row = await db.userKeyPair.findFirst({ where: { userId, status: 'ACTIVE' }, select: vaultSelect });
      if (row === null || row.encryptedPrivateKey === null || row.encryptedSigningPrivateKey === null) return null;
      const { id, encryptedPrivateKey, encryptedSigningPrivateKey, ...rest } = row;
      return { keyId: id, encryptedPrivateKey, encryptedSigningPrivateKey, ...rest };
    },

    async hasActiveVault(userId: string): Promise<boolean> {
      return (await db.userKeyPair.count({ where: { userId, status: 'ACTIVE' } })) > 0;
    },

    /**
     * Inserts a new ACTIVE identity. A second ACTIVE identity for the user, a reused key ID or
     * reused public keys (the fingerprint is unique) lose on the unique indexes.
     */
    async insertIdentity(row: NewIdentityRow): Promise<'CREATED' | 'CONFLICT'> {
      try {
        await db.userKeyPair.create({
          data: {
            id: row.keyId,
            userId: row.userId,
            status: 'ACTIVE',
            algorithmSuite: row.algorithmSuite,
            vaultVersion: row.vaultVersion,
            publicKeySpki: bytes(row.publicKeySpki),
            signingPublicKeySpki: bytes(row.signingPublicKeySpki),
            publicKeyFingerprint: row.publicKeyFingerprint,
            identitySignature: bytes(row.identitySignature),
            encryptedPrivateKey: bytes(row.encryptedPrivateKey),
            privateKeyIv: bytes(row.privateKeyIv),
            encryptedSigningPrivateKey: bytes(row.encryptedSigningPrivateKey),
            signingPrivateKeyIv: bytes(row.signingPrivateKeyIv),
            kdfAlgorithm: 'argon2id',
            kdfMemoryKiB: row.kdfMemoryKiB,
            kdfIterations: row.kdfIterations,
            kdfParallelism: row.kdfParallelism,
            kdfSalt: bytes(row.kdfSalt),
            createdAt: row.now,
          },
          select: { id: true },
        });
        return 'CREATED';
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') return 'CONFLICT';
        throw error;
      }
    },

    /**
     * Replaces the KDF section and both wrapped keys of the ACTIVE identity, but only if the salt
     * the client signed against is still the stored one. False means a concurrent change won.
     */
    async rewrap(userId: string, keyId: string, expectedSalt: Uint8Array, update: RewrapUpdate, now: Date) {
      const result = await db.userKeyPair.updateMany({
        where: { id: keyId, userId, status: 'ACTIVE', kdfSalt: { equals: bytes(expectedSalt) } },
        data: {
          encryptedPrivateKey: bytes(update.encryptedPrivateKey),
          privateKeyIv: bytes(update.privateKeyIv),
          encryptedSigningPrivateKey: bytes(update.encryptedSigningPrivateKey),
          signingPrivateKeyIv: bytes(update.signingPrivateKeyIv),
          kdfMemoryKiB: update.kdfMemoryKiB,
          kdfIterations: update.kdfIterations,
          kdfParallelism: update.kdfParallelism,
          kdfSalt: bytes(update.kdfSalt),
          rewrappedAt: now,
        },
      });
      return result.count === 1;
    },

    /**
     * Retires the named ACTIVE identity (vault reset): status SUPERSEDED and both encrypted private
     * keys removed. The public keys stay for audit and for verifying earlier signatures.
     */
    async supersede(userId: string, keyId: string, now: Date): Promise<boolean> {
      const result = await db.userKeyPair.updateMany({
        where: { id: keyId, userId, status: 'ACTIVE' },
        data: { status: 'SUPERSEDED', encryptedPrivateKey: null, encryptedSigningPrivateKey: null, supersededAt: now },
      });
      return result.count === 1;
    },

    /** Directory lookup by exact (normalized) email: ACTIVE accounts with an ACTIVE identity only. */
    async findDirectoryEntry(email: string): Promise<DirectoryRecord | null> {
      const user = await db.user.findFirst({
        where: { email, status: 'ACTIVE', deletedAt: null },
        select: {
          id: true,
          displayName: true,
          createdAt: true,
          keyPairs: {
            where: { status: 'ACTIVE' },
            take: 1,
            select: {
              id: true,
              algorithmSuite: true,
              publicKeySpki: true,
              signingPublicKeySpki: true,
              identitySignature: true,
              publicKeyFingerprint: true,
              createdAt: true,
            },
          },
        },
      });
      const key = user?.keyPairs[0];
      if (user == null || key === undefined) return null;
      return {
        userId: user.id,
        displayName: user.displayName,
        accountCreatedAt: user.createdAt,
        keyId: key.id,
        algorithmSuite: key.algorithmSuite,
        publicKeySpki: key.publicKeySpki,
        signingPublicKeySpki: key.signingPublicKeySpki,
        identitySignature: key.identitySignature,
        publicKeyFingerprint: key.publicKeyFingerprint,
        keyCreatedAt: key.createdAt,
      };
    },
  };
}

export type VaultStore = ReturnType<typeof createVaultStore>;

/** Stores bound to one transaction: vault changes and their session effects commit together. */
export interface VaultTransactionStores {
  readonly vault: VaultStore;
  readonly auth: AuthStore;
}

export function vaultDataAccess(prisma: PrismaClient): {
  store: VaultStore;
  transaction: <T>(fn: (stores: VaultTransactionStores) => Promise<T>) => Promise<T>;
} {
  return {
    store: createVaultStore(prisma),
    transaction: (fn) =>
      prisma.$transaction((tx) => fn({ vault: createVaultStore(tx), auth: createAuthStore(tx) }), {
        isolationLevel: 'ReadCommitted',
      }),
  };
}
