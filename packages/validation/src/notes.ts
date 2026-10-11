import { AES_GCM, NOTES, SUITE } from '@ciphermesh/crypto/params';
import { NOTE_LIMITS, NOTE_LIST_PAGE_SIZE } from '@ciphermesh/shared';
import { listCursorSchema } from './list';
import { keyVersionSchema } from './room-keys';
import { base64Url, isoTimestampSchema, uuidV4Schema } from './schemas';
import { z } from './zod';

/**
 * Encrypted note schemas (Phase 8, CM-T042, DF-12). Every request object is strict: no field can
 * carry a plaintext title or body, a NEK, a room key, a revision the server should store, or an
 * author, editor or role claim, and anything unknown is rejected (INV-01, INV-16, OL-04). Sizes
 * follow CP-28 and the database constraints; the API decodes each value strictly.
 */

const ivSchema = base64Url(AES_GCM.ivBytes);
const wrappedNekSchema = base64Url(NOTES.wrappedNekBytes);
const ciphertextSchema = base64Url(NOTE_LIMITS.minCiphertextBytes, NOTE_LIMITS.maxCiphertextBytes);
const revisionSchema = z.number().int().min(1).max(NOTE_LIMITS.maxRevision);

export const noteParamsSchema = z.strictObject({ roomId: uuidV4Schema, noteId: uuidV4Schema });

export const noteListQuerySchema = z.strictObject({ cursor: listCursorSchema.optional() });

// ------------------------------------------------------------------------------------- requests

/** The ciphertext of one revision: the document under a fresh NEK, the NEK wrapped under RWK_v. */
const revisionFields = {
  /** Must be the room's current key version (PC-16, KEY_VERSION_STALE). */
  keyVersion: keyVersionSchema,
  suite: z.literal(SUITE),
  wrappedNek: wrappedNekSchema,
  nekIv: ivSchema,
  ciphertext: ciphertextSchema,
  contentIv: ivSchema,
};

/** POST /rooms/{roomId}/notes (AZ-19): revision 1 of a new note. */
export const noteCreateRequestSchema = z.strictObject({
  /** Chosen by the author's browser: it is part of every context of the note (CD-08). */
  noteId: uuidV4Schema,
  ...revisionFields,
  /** Required in CONFIDENTIAL and RESTRICTED rooms, bounded by the profile (PC-08). */
  expiresAt: isoTimestampSchema.nullable(),
});

/**
 * POST /rooms/{roomId}/notes/{noteId}/update (AZ-21): the next revision. The browser encrypted it
 * for revision expectedRevision + 1; the API stores it only while the stored revision is still
 * expectedRevision (optimistic concurrency, REVISION_CONFLICT otherwise).
 */
export const noteUpdateRequestSchema = z.strictObject({
  expectedRevision: revisionSchema.max(NOTE_LIMITS.maxRevision - 1),
  ...revisionFields,
});

// ------------------------------------------------------------------------------------ responses

/**
 * One note as the API projects it: server-side metadata (identifiers, revision, key version,
 * times) and the ciphertext with the wrapped NEK. There is no title or body on the server to
 * project (INV-01, INV-16).
 */
export const noteRecordSchema = z.strictObject({
  id: uuidV4Schema,
  authorId: uuidV4Schema,
  updatedById: uuidV4Schema,
  revision: revisionSchema,
  ...revisionFields,
  expiresAt: isoTimestampSchema.nullable(),
  createdAt: isoTimestampSchema,
  updatedAt: isoTimestampSchema,
});
export type NoteRecordView = z.infer<typeof noteRecordSchema>;

export const noteListResponseSchema = z.strictObject({
  notes: z.array(noteRecordSchema).max(NOTE_LIST_PAGE_SIZE),
  nextCursor: listCursorSchema.nullable(),
});

export const noteResponseSchema = z.strictObject({ note: noteRecordSchema });

export const noteDeletedResponseSchema = z.strictObject({ status: z.literal('DELETED') });
