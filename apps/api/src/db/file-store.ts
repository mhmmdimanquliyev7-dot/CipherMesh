import { isUuidV4 } from '@ciphermesh/shared';
import { Prisma, type PrismaClient } from '../generated/prisma/client';
import type { FileStatus, RekeyReason } from '../generated/prisma/enums';

/**
 * Data access for encrypted files (Phase 7, CM-T038 to CM-T041; data-model 4.11 and 5). Part of the
 * room store, so one transaction can lock the user, the room, the membership and the file row in
 * the established order (user, room, membership, object) and write the file with them.
 *
 * - Reads are constrained by room ID and the caller's ACTIVE membership in an ACTIVE room inside
 *   the query (INV-06, OL-02, OL-08), and refuse expired files at read time (INV-14).
 * - The rows hold ciphertext, the wrapped FEK, IVs and public sizes and hashes; there is no file
 *   name, type or plaintext hash to store (INV-16). Object keys are server-generated.
 * - Writes are conditional on the state that was checked and report whether they applied. A
 *   deleted file becomes a tombstone: status DELETED with the wrapped FEK and the manifest set to
 *   NULL, the crypto-shredding of the live copy (data-model 5). Rows are never deleted.
 */
type Db = PrismaClient | Prisma.TransactionClient;

/** A file a member may read, with what a browser needs to decrypt it. */
export interface FileRecord {
  readonly id: string;
  readonly roomId: string;
  readonly uploaderId: string;
  readonly keyVersion: number;
  readonly status: 'PENDING_UPLOAD' | 'AVAILABLE';
  readonly wrappedDek: Uint8Array;
  readonly dekIv: Uint8Array;
  readonly contentIv: Uint8Array;
  readonly manifestCiphertext: Uint8Array;
  readonly manifestIv: Uint8Array;
  readonly objectKey: string;
  readonly ciphertextSize: number;
  readonly ciphertextSha256: Uint8Array;
  readonly expiresAt: Date | null;
  readonly createdAt: Date;
  readonly uploadedAt: Date | null;
}

/** Facts about a file row of the room, for authorization (OL-02, OL-04) and lifecycle decisions. */
export interface FileFacts {
  readonly id: string;
  readonly roomId: string;
  readonly uploaderId: string;
  readonly keyVersion: number;
  readonly status: FileStatus;
  readonly objectKey: string;
  readonly ciphertextSize: number;
  readonly createdAt: Date;
}

export interface NewPendingFile {
  readonly id: string;
  readonly roomId: string;
  readonly uploaderId: string;
  readonly keyVersion: number;
  readonly algorithmSuite: 'CM1';
  readonly wrappedDek: Uint8Array;
  readonly dekIv: Uint8Array;
  readonly contentIv: Uint8Array;
  readonly manifestCiphertext: Uint8Array;
  readonly manifestIv: Uint8Array;
  readonly objectKey: string;
  readonly ciphertextSize: number;
  readonly ciphertextSha256: Uint8Array;
  readonly expiresAt: Date | null;
  readonly now: Date;
}

export interface StorageUsage {
  /** Ciphertext bytes of the room's files that are not DELETED. */
  readonly roomBytes: number;
  /** Ciphertext bytes of the uploader's files that are not DELETED, in every room. */
  readonly userBytes: number;
  /** The uploader's uploads in PENDING_UPLOAD, in every room. */
  readonly userPending: number;
}

/** The client-chosen file ID was used before (in any room). Raised inside the creating transaction. */
export class FileIdUnavailableError extends Error {
  constructor() {
    super('File ID unavailable');
    this.name = 'FileIdUnavailableError';
  }
}

/** CP-16: RWK_v wraps at most 2^20 DEKs; the database CHECK has the same bound. */
export const MAX_WRAPS_PER_KEY_VERSION = 1_048_576;

const recordSelect = {
  id: true,
  roomId: true,
  uploaderId: true,
  keyVersion: true,
  status: true,
  wrappedDek: true,
  dekIv: true,
  contentIv: true,
  manifestCiphertext: true,
  manifestIv: true,
  objectKey: true,
  ciphertextSize: true,
  ciphertextSha256: true,
  expiresAt: true,
  createdAt: true,
  uploadedAt: true,
} as const;

type SelectedRecord = Prisma.EncryptedFileGetPayload<{ select: typeof recordSelect }>;

/** Rows from the read queries are never DELETED, so the key material is present (CHECK constraint). */
function toRecord(row: SelectedRecord): FileRecord {
  if (row.status === 'DELETED' || row.wrappedDek === null || row.manifestCiphertext === null) {
    throw new Error('A deleted file reached a read projection');
  }
  return {
    ...row,
    status: row.status,
    wrappedDek: row.wrappedDek,
    manifestCiphertext: row.manifestCiphertext,
    ciphertextSize: Number(row.ciphertextSize),
  };
}

const factsSelect = {
  id: true,
  roomId: true,
  uploaderId: true,
  keyVersion: true,
  status: true,
  objectKey: true,
  ciphertextSize: true,
  createdAt: true,
} as const;

const toFacts = (row: Prisma.EncryptedFileGetPayload<{ select: typeof factsSelect }>): FileFacts => ({
  ...row,
  ciphertextSize: Number(row.ciphertextSize),
});

/** Readable at `now`: AVAILABLE and not expired (INV-14), in an ACTIVE room the caller is an ACTIVE member of. */
const readable = (roomId: string, userId: string, now: Date) => ({
  roomId,
  status: 'AVAILABLE' as const,
  OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
  room: { status: 'ACTIVE' as const, members: { some: { userId, status: 'ACTIVE' as const } } },
});

/** The tombstone write: status DELETED, wrapped FEK and manifest removed (crypto-shredding). */
const tombstone = (now: Date) => ({
  status: 'DELETED' as const,
  wrappedDek: null,
  manifestCiphertext: null,
  deletedAt: now,
});

export function fileStoreFunctions(
  db: Db,
  requireRekey: (roomId: string, reason: RekeyReason, now: Date) => Promise<void>,
) {
  return {
    /** A file row of the room by (file ID, room ID) (OL-02), or null. DELETED rows only if asked. */
    async findRoomFile(roomId: string, fileId: string, includeDeleted = false): Promise<FileFacts | null> {
      if (!isUuidV4(roomId) || !isUuidV4(fileId)) return null;
      const row = await db.encryptedFile.findFirst({
        where: { id: fileId, roomId, ...(includeDeleted ? {} : { status: { not: 'DELETED' } }) },
        select: factsSelect,
      });
      return row === null ? null : toFacts(row);
    },

    /** The room's readable files for an ACTIVE member, newest first, one keyset page. */
    async listRoomFiles(
      roomId: string,
      userId: string,
      now: Date,
      after: { readonly at: Date; readonly id: string } | undefined,
      take: number,
    ): Promise<FileRecord[]> {
      const rows = await db.encryptedFile.findMany({
        where: {
          AND: [
            readable(roomId, userId, now),
            after === undefined
              ? {}
              : { OR: [{ createdAt: { lt: after.at } }, { createdAt: after.at, id: { lt: after.id } }] },
          ],
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take,
        select: recordSelect,
      });
      return rows.map(toRecord);
    },

    /** One readable file of the room for an ACTIVE member, or null (not found, not readable, expired). */
    async readRoomFile(roomId: string, fileId: string, userId: string, now: Date): Promise<FileRecord | null> {
      if (!isUuidV4(roomId) || !isUuidV4(fileId)) return null;
      const row = await db.encryptedFile.findFirst({
        where: { id: fileId, ...readable(roomId, userId, now) },
        select: recordSelect,
      });
      return row === null ? null : toRecord(row);
    },

    /**
     * Locks the user row for an upload (after it, the room, then the membership): uploads of one
     * account are serialized, so its quotas hold under concurrency, and a concurrent account
     * disable cannot miss the new file. Returns whether the account is ACTIVE.
     */
    async lockUploader(userId: string): Promise<boolean> {
      const rows = await db.$queryRaw<{ status: string }[]>`
        SELECT status::text AS status FROM users WHERE id = ${userId}::uuid FOR NO KEY UPDATE`;
      return rows[0]?.status === 'ACTIVE';
    },

    /** Locks a file row of the room (after the room and the membership), or returns null. */
    async lockRoomFile(roomId: string, fileId: string): Promise<FileFacts | null> {
      if (!isUuidV4(roomId) || !isUuidV4(fileId)) return null;
      const rows = await db.$queryRaw<
        {
          id: string;
          room_id: string;
          uploader_id: string;
          key_version: number;
          status: FileStatus;
          object_key: string;
          ciphertext_size: bigint;
          created_at: Date;
        }[]
      >`
        SELECT id::text AS id, room_id::text AS room_id, uploader_id::text AS uploader_id, key_version,
               status::text AS status, object_key, ciphertext_size, created_at
          FROM encrypted_files WHERE id = ${fileId}::uuid AND room_id = ${roomId}::uuid FOR UPDATE`;
      const row = rows[0];
      return row === undefined
        ? null
        : {
            id: row.id,
            roomId: row.room_id,
            uploaderId: row.uploader_id,
            keyVersion: row.key_version,
            status: row.status,
            objectKey: row.object_key,
            ciphertextSize: Number(row.ciphertext_size),
            createdAt: row.created_at,
          };
    },

    /** Whether a file ID was ever used, in any room (IDs are never reused, CD-08). */
    async fileIdUsed(fileId: string): Promise<boolean> {
      return (await db.encryptedFile.count({ where: { id: fileId } })) > 0;
    },

    /** Storage the room and the uploader use now (CM-T041 quotas). Call with the user and room locked. */
    async storageUsage(roomId: string, uploaderId: string): Promise<StorageUsage> {
      const live = { status: { not: 'DELETED' as const } };
      const [room, user, pending] = await Promise.all([
        db.encryptedFile.aggregate({ where: { roomId, ...live }, _sum: { ciphertextSize: true } }),
        db.encryptedFile.aggregate({ where: { uploaderId, ...live }, _sum: { ciphertextSize: true } }),
        db.encryptedFile.count({ where: { uploaderId, status: 'PENDING_UPLOAD' } }),
      ]);
      return {
        roomBytes: Number(room._sum.ciphertextSize ?? 0n),
        userBytes: Number(user._sum.ciphertextSize ?? 0n),
        userPending: pending,
      };
    },

    /**
     * Counts one more DEK wrapped under the room's ACTIVE key version (CP-16). At the bound the room
     * becomes REKEY_REQUIRED (WRAP_LIMIT_REACHED) in this transaction and the call returns false:
     * the next key version must be made by a member's browser (ADR-013).
     */
    async consumeWrap(roomId: string, keyVersion: number, now: Date): Promise<boolean> {
      const updated = await db.roomKeyVersion.updateMany({
        where: { roomId, version: keyVersion, status: 'ACTIVE', wrapCount: { lt: MAX_WRAPS_PER_KEY_VERSION } },
        data: { wrapCount: { increment: 1 } },
      });
      if (updated.count === 1) return true;
      await requireRekey(roomId, 'WRAP_LIMIT_REACHED', now);
      return false;
    },

    /** Inserts the file as PENDING_UPLOAD (DF-07). The service has checked everything on locked state. */
    async insertPendingFile(file: NewPendingFile): Promise<FileRecord> {
      try {
        const row = await db.encryptedFile.create({
          data: {
            id: file.id,
            roomId: file.roomId,
            uploaderId: file.uploaderId,
            keyVersion: file.keyVersion,
            status: 'PENDING_UPLOAD',
            algorithmSuite: file.algorithmSuite,
            wrappedDek: new Uint8Array(file.wrappedDek),
            dekIv: new Uint8Array(file.dekIv),
            contentIv: new Uint8Array(file.contentIv),
            manifestCiphertext: new Uint8Array(file.manifestCiphertext),
            manifestIv: new Uint8Array(file.manifestIv),
            objectKey: file.objectKey,
            ciphertextSize: BigInt(file.ciphertextSize),
            ciphertextSha256: new Uint8Array(file.ciphertextSha256),
            expiresAt: file.expiresAt,
            createdAt: file.now,
          },
          select: recordSelect,
        });
        return toRecord(row);
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          throw new FileIdUnavailableError();
        }
        throw error;
      }
    },

    /** PENDING_UPLOAD to AVAILABLE for the uploader's own file; false when the state changed. */
    async completeFile(roomId: string, fileId: string, uploaderId: string, now: Date): Promise<FileRecord | null> {
      const updated = await db.encryptedFile.updateMany({
        where: { id: fileId, roomId, uploaderId, status: 'PENDING_UPLOAD' },
        data: { status: 'AVAILABLE', uploadedAt: now },
      });
      if (updated.count !== 1) return null;
      const row = await db.encryptedFile.findFirst({ where: { id: fileId, roomId }, select: recordSelect });
      return row === null ? null : toRecord(row);
    },

    /** Tombstones a file of the room that is not DELETED yet; false when it already was. */
    async tombstoneFile(roomId: string, fileId: string, now: Date): Promise<boolean> {
      const updated = await db.encryptedFile.updateMany({
        where: { id: fileId, roomId, status: { not: 'DELETED' } },
        data: tombstone(now),
      });
      return updated.count === 1;
    },

    /** Records that the storage object of a DELETED file was removed. */
    async markObjectDeleted(fileId: string, now: Date): Promise<void> {
      await db.encryptedFile.updateMany({
        where: { id: fileId, status: 'DELETED', objectDeletedAt: null },
        data: { objectDeletedAt: now },
      });
    },
  };
}

export type FileStoreFunctions = ReturnType<typeof fileStoreFunctions>;

export { tombstone as fileTombstone };
