import { isUuidV4 } from '@ciphermesh/shared';
import { Prisma, type PrismaClient } from '../generated/prisma/client';

/**
 * Data access for encrypted notes (Phase 8, CM-T042; data-model 4.12 and 5, DF-12). Part of the
 * room store, so one transaction can lock the user, the room, the membership and the note row in
 * the established order (user, room, membership, object) and write the note with them.
 *
 * - Reads are constrained by room ID and the caller's ACTIVE membership in an ACTIVE room inside
 *   the query (INV-06, OL-02, OL-08), and refuse deleted and expired notes at read time (INV-14).
 * - The rows hold the note ciphertext, the wrapped NEK, IVs, the revision and public metadata;
 *   there is no title, body or preview to store (INV-01, INV-16).
 * - An update is conditional on the stored revision being the one the editor read (optimistic
 *   concurrency, DF-12): it replaces the ciphertext and moves the revision by exactly one, or
 *   changes nothing. A deleted note becomes a tombstone (ciphertext and wrapped NEK NULL, the
 *   crypto-shredding of the live copy). Rows are never deleted; the guard trigger of migration
 *   20261008000000_encrypted_notes rejects any other transition.
 */
type Db = PrismaClient | Prisma.TransactionClient;

/** A note a member may read, with what a browser needs to decrypt it. */
export interface NoteRecord {
  readonly id: string;
  readonly roomId: string;
  readonly authorId: string;
  readonly updatedById: string;
  readonly revision: number;
  readonly keyVersion: number;
  readonly wrappedDek: Uint8Array;
  readonly dekIv: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly contentIv: Uint8Array;
  readonly expiresAt: Date | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** Facts about a live note row of the room, for authorization (OL-02, OL-04) and lifecycle decisions. */
export interface NoteFacts {
  readonly id: string;
  readonly roomId: string;
  readonly authorId: string;
  readonly revision: number;
  readonly expiresAt: Date | null;
}

/** The ciphertext of one revision as the author's browser produced it. */
export interface NoteRevisionValues {
  readonly keyVersion: number;
  readonly wrappedDek: Uint8Array;
  readonly dekIv: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly contentIv: Uint8Array;
  /** SHA-256 of the ciphertext, computed by the API (data-model 4.12, INT). */
  readonly ciphertextSha256: Uint8Array;
}

export interface NewNote extends NoteRevisionValues {
  readonly id: string;
  readonly roomId: string;
  readonly authorId: string;
  readonly algorithmSuite: 'CM1';
  readonly expiresAt: Date | null;
  readonly now: Date;
}

/** The client-chosen note ID was used before (in any room). Raised inside the creating transaction. */
export class NoteIdUnavailableError extends Error {
  constructor() {
    super('Note ID unavailable');
    this.name = 'NoteIdUnavailableError';
  }
}

const recordSelect = {
  id: true,
  roomId: true,
  authorId: true,
  updatedById: true,
  revision: true,
  keyVersion: true,
  wrappedDek: true,
  dekIv: true,
  ciphertext: true,
  contentIv: true,
  expiresAt: true,
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
} as const;

type SelectedRecord = Prisma.EncryptedNoteGetPayload<{ select: typeof recordSelect }>;

/** Rows from the read queries are never deleted, so the key material is present (CHECK constraint). */
function toRecord(row: SelectedRecord): NoteRecord {
  const { deletedAt, wrappedDek, ciphertext, ...rest } = row;
  if (deletedAt !== null || wrappedDek === null || ciphertext === null) {
    throw new Error('A deleted note reached a read projection');
  }
  return { ...rest, wrappedDek, ciphertext };
}

/** Live at `now`: not deleted and not expired (INV-14). */
const live = (now: Date) => ({
  deletedAt: null,
  OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
});

/** Readable at `now`: live, in an ACTIVE room the caller is an ACTIVE member of. */
const readable = (roomId: string, userId: string, now: Date) => ({
  roomId,
  ...live(now),
  room: { status: 'ACTIVE' as const, members: { some: { userId, status: 'ACTIVE' as const } } },
});

/** The tombstone write: ciphertext and wrapped NEK removed (crypto-shredding), nothing else changed. */
const tombstone = (now: Date) => ({ wrappedDek: null, ciphertext: null, deletedAt: now, updatedAt: now });

export function noteStoreFunctions(db: Db) {
  return {
    /** A live (not deleted) note of the room by (note ID, room ID) (OL-02), or null. */
    async findRoomNote(roomId: string, noteId: string): Promise<NoteFacts | null> {
      if (!isUuidV4(roomId) || !isUuidV4(noteId)) return null;
      return db.encryptedNote.findFirst({
        where: { id: noteId, roomId, deletedAt: null },
        select: { id: true, roomId: true, authorId: true, revision: true, expiresAt: true },
      });
    },

    /** The room's readable notes for an ACTIVE member, newest first, one keyset page. */
    async listRoomNotes(
      roomId: string,
      userId: string,
      now: Date,
      after: { readonly at: Date; readonly id: string } | undefined,
      take: number,
    ): Promise<NoteRecord[]> {
      const rows = await db.encryptedNote.findMany({
        where: {
          AND: [
            readable(roomId, userId, now),
            after === undefined
              ? {}
              : { OR: [{ createdAt: { lt: after.at } }, { createdAt: after.at, id: { lt: after.id } }] },
          ],
        },
        // Creation time, not update time: an edit during paging must not move a note between pages.
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take,
        select: recordSelect,
      });
      return rows.map(toRecord);
    },

    /** One readable note of the room for an ACTIVE member, or null (not found, deleted, expired). */
    async readRoomNote(roomId: string, noteId: string, userId: string, now: Date): Promise<NoteRecord | null> {
      if (!isUuidV4(roomId) || !isUuidV4(noteId)) return null;
      const row = await db.encryptedNote.findFirst({
        where: { id: noteId, ...readable(roomId, userId, now) },
        select: recordSelect,
      });
      return row === null ? null : toRecord(row);
    },

    /**
     * Locks a live note row of the room (after the user, the room and the membership), or returns
     * null. Concurrent saves of one note are serialized here, so the revision check that follows
     * sees the latest committed revision.
     */
    async lockRoomNote(roomId: string, noteId: string): Promise<NoteFacts | null> {
      if (!isUuidV4(roomId) || !isUuidV4(noteId)) return null;
      const rows = await db.$queryRaw<
        { id: string; room_id: string; author_id: string; revision: number; expires_at: Date | null }[]
      >`
        SELECT id::text AS id, room_id::text AS room_id, author_id::text AS author_id, revision, expires_at
          FROM encrypted_notes
         WHERE id = ${noteId}::uuid AND room_id = ${roomId}::uuid AND deleted_at IS NULL
           FOR UPDATE`;
      const row = rows[0];
      return row === undefined
        ? null
        : {
            id: row.id,
            roomId: row.room_id,
            authorId: row.author_id,
            revision: row.revision,
            expiresAt: row.expires_at,
          };
    },

    /** Whether a note ID was ever used, in any room (IDs are never reused, CD-08). */
    async noteIdUsed(noteId: string): Promise<boolean> {
      return (await db.encryptedNote.count({ where: { id: noteId } })) > 0;
    },

    /** Notes of the room that are not deleted (D-08-01). Call with the room locked. */
    async liveNoteCount(roomId: string): Promise<number> {
      return db.encryptedNote.count({ where: { roomId, deletedAt: null } });
    },

    /** Inserts revision 1 of a note (DF-12). The service has checked everything on locked state. */
    async insertNote(note: NewNote): Promise<NoteRecord> {
      try {
        const row = await db.encryptedNote.create({
          data: {
            id: note.id,
            roomId: note.roomId,
            authorId: note.authorId,
            updatedById: note.authorId,
            revision: 1,
            keyVersion: note.keyVersion,
            algorithmSuite: note.algorithmSuite,
            wrappedDek: new Uint8Array(note.wrappedDek),
            dekIv: new Uint8Array(note.dekIv),
            ciphertext: new Uint8Array(note.ciphertext),
            contentIv: new Uint8Array(note.contentIv),
            ciphertextSha256: new Uint8Array(note.ciphertextSha256),
            expiresAt: note.expiresAt,
            createdAt: note.now,
            updatedAt: note.now,
          },
          select: recordSelect,
        });
        return toRecord(row);
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          throw new NoteIdUnavailableError();
        }
        throw error;
      }
    },

    /**
     * Replaces the ciphertext with the next revision, only while the stored revision is still
     * `expectedRevision` and the note is live (optimistic concurrency, DF-12). Returns the new
     * record, or null when another save, a deletion or an expiry came first.
     */
    async updateNoteRevision(
      roomId: string,
      noteId: string,
      expectedRevision: number,
      editorId: string,
      values: NoteRevisionValues,
      now: Date,
    ): Promise<NoteRecord | null> {
      const updated = await db.encryptedNote.updateMany({
        where: { id: noteId, roomId, revision: expectedRevision, ...live(now) },
        data: {
          revision: expectedRevision + 1,
          keyVersion: values.keyVersion,
          updatedById: editorId,
          wrappedDek: new Uint8Array(values.wrappedDek),
          dekIv: new Uint8Array(values.dekIv),
          ciphertext: new Uint8Array(values.ciphertext),
          contentIv: new Uint8Array(values.contentIv),
          ciphertextSha256: new Uint8Array(values.ciphertextSha256),
          updatedAt: now,
        },
      });
      if (updated.count !== 1) return null;
      const row = await db.encryptedNote.findFirst({ where: { id: noteId, roomId }, select: recordSelect });
      return row === null ? null : toRecord(row);
    },

    /** Tombstones a note of the room that is not deleted yet; false when it already was. */
    async tombstoneNote(roomId: string, noteId: string, now: Date): Promise<boolean> {
      const updated = await db.encryptedNote.updateMany({
        where: { id: noteId, roomId, deletedAt: null },
        data: tombstone(now),
      });
      return updated.count === 1;
    },
  };
}

export type NoteStoreFunctions = ReturnType<typeof noteStoreFunctions>;

export { tombstone as noteTombstone };
