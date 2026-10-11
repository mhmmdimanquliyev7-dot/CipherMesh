import { fromBase64Url } from '@ciphermesh/crypto/identity';
import { ErrorCode, NOTE_LIMITS, NOTE_RULES, type RoomActionId, type RoomResourceFacts } from '@ciphermesh/shared';
import { createHash } from 'node:crypto';
import type { SecurityEventSink } from '../auth/security-events';
import type { Actor, RequestMeta } from '../auth/sessions';
import { reauthorizeRoomAction, roomDenial, type RoomAccess } from '../authorization/rooms';
import { NoteIdUnavailableError, type NoteFacts, type NoteRecord, type NoteRevisionValues } from '../db/note-store';
import type { ListPosition, LockedRoom, RoomStore } from '../db/room-store';
import { HttpError } from '../http/errors';
import { factsOf } from '../rooms/service';

/**
 * Encrypted notes (Phase 8, CM-T042; DF-12, data-model 4.12 and 5).
 *
 * The API never sees a note's title or body, nor its NEK: the author's browser encrypts the note
 * document under a fresh NEK for each revision and wraps the NEK under a verified RWK_v (INV-01).
 * The API decides who may store and read which ciphertext, and keeps revisions in order.
 *
 * Create (AZ-19) and update (AZ-21, own for MEMBER). One transaction locks the editor's user row,
 * the room, the membership and (update) the note, in the established order, re-checks the matrix
 * on that state, then requires: the room's key state ACTIVE (PC-16, REKEY_REQUIRED), the named key
 * version current (KEY_VERSION_STALE), on creation the expiry the profile allows (PC-08), an unused
 * note ID and the room's note limit (D-08-01), on update the stored revision equal to the expected
 * one (REVISION_CONFLICT, optimistic concurrency), and one more wrap under the key version (CP-16).
 * An update writes revision expected + 1 conditionally; the browser encrypted it with that number
 * in both contexts, so ciphertext moved to another revision fails authentication in every browser.
 * The expiry is fixed at creation and cannot be extended by an edit.
 *
 * Read (AZ-20, every role): only live, unexpired notes (INV-14) of the room, for an ACTIVE member.
 * Reads are recorded at the EXTENDED and FULL audit levels (PC-13).
 *
 * Delete (AZ-22, own for MEMBER): a tombstone in one transaction (ciphertext and wrapped NEK NULL).
 * Allowed while the room is REKEY_REQUIRED: only content writes are locked (PC-16).
 */

export interface NoteServiceDependencies {
  readonly store: RoomStore;
  readonly transaction: <T>(fn: (store: RoomStore) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

interface NoteCiphertextInput {
  readonly keyVersion: number;
  readonly suite: 'CM1';
  readonly wrappedNek: string;
  readonly nekIv: string;
  readonly ciphertext: string;
  readonly contentIv: string;
}

export interface NoteCreateInput extends NoteCiphertextInput {
  readonly noteId: string;
  readonly expiresAt: string | null;
}

export interface NoteUpdateInput extends NoteCiphertextInput {
  readonly expectedRevision: number;
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
const rekeyRequired = (): HttpError =>
  new HttpError(409, ErrorCode.REKEY_REQUIRED, 'The room key must be rotated before new content can be added');
const keyVersionStale = (): HttpError =>
  new HttpError(
    409,
    ErrorCode.KEY_VERSION_STALE,
    'The note was encrypted with a key version that is no longer current',
  );
const revisionConflict = (): HttpError =>
  new HttpError(409, ErrorCode.REVISION_CONFLICT, 'The note was changed by someone else; reload it before saving');

type NoteEvent = 'NOTE_CREATED' | 'NOTE_UPDATED' | 'NOTE_READ' | 'NOTE_DELETED' | 'REKEY_REQUIRED';

export function createNoteService(deps: NoteServiceDependencies) {
  const { store, transaction, events, clock } = deps;

  /** Locks the room and the actor's membership (in that order) and decides again on that state. */
  async function lockAndReauthorize(
    tx: RoomStore,
    actor: Actor,
    roomId: string,
    meta: RequestMeta,
    action: RoomActionId,
    resource?: () => Promise<RoomResourceFacts | null>,
  ): Promise<LockedRoom> {
    const request = { actorUserId: actor.userId, requestId: meta.requestId };
    const room = await tx.lockRoom(roomId);
    const member = room === null ? null : await tx.lockMembership(roomId, actor.userId);
    let facts: RoomResourceFacts | undefined;
    if (room !== null && member !== null && resource !== undefined) {
      const loaded = await resource();
      if (loaded === null) throw roomDenial(events, { ...request, action }, 'RESOURCE_NOT_FOUND');
      facts = loaded;
    }
    reauthorizeRoomAction(events, request, {
      actorUserId: actor.userId,
      roomId,
      membership: factsOf(room, member),
      action,
      ...(facts === undefined ? {} : { resource: facts }),
    });
    if (room === null || member === null) throw notFound();
    return room;
  }

  /** PC-08: the expiry the profile requires and allows, measured from now. */
  function checkExpiry(room: LockedRoom, expiresAt: Date | null, now: Date): void {
    const rules = NOTE_RULES[room.securityProfile];
    const refuse = (): HttpError =>
      new HttpError(422, ErrorCode.EXPIRY_NOT_ALLOWED, 'The expiry is missing or outside what this room allows');
    if (expiresAt === null) {
      if (rules.expiryRequired) throw refuse();
      return;
    }
    if (expiresAt.getTime() <= now.getTime()) throw refuse();
    if (rules.maxExpiryMs !== null && expiresAt.getTime() > now.getTime() + rules.maxExpiryMs) throw refuse();
  }

  /** Decodes the ciphertext of one revision; the schema bounded every length already. */
  function revisionValues(input: NoteCiphertextInput): NoteRevisionValues {
    try {
      const ciphertext = fromBase64Url(input.ciphertext);
      if (ciphertext.length < NOTE_LIMITS.minCiphertextBytes || ciphertext.length > NOTE_LIMITS.maxCiphertextBytes) {
        throw new Error('ciphertext size');
      }
      return {
        keyVersion: input.keyVersion,
        wrappedDek: fromBase64Url(input.wrappedNek),
        dekIv: fromBase64Url(input.nekIv),
        ciphertext,
        contentIv: fromBase64Url(input.contentIv),
        // A storage-integrity reference over the ciphertext only (data-model 4.12, CD-09).
        ciphertextSha256: new Uint8Array(createHash('sha256').update(ciphertext).digest()),
      };
    } catch {
      throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed');
    }
  }

  function record(
    name: NoteEvent,
    actor: Actor,
    meta: RequestMeta,
    details: Readonly<Record<string, string | number | boolean>>,
  ): void {
    events.record({ name, outcome: 'SUCCESS', actorUserId: actor.userId, requestId: meta.requestId, details });
  }

  /** PC-13: note reads are audit events at the EXTENDED and FULL levels. */
  function recordRead(actor: Actor, access: RoomAccess, meta: RequestMeta, details: Record<string, string | number>) {
    if (NOTE_RULES[access.room.securityProfile].auditReads) {
      record('NOTE_READ', actor, meta, { roomId: access.roomId, ...details });
    }
  }

  /** CP-16: one more wrap under the key version, or the room becomes REKEY_REQUIRED (committed). */
  function wrapLimitReached(actor: Actor, access: RoomAccess, meta: RequestMeta): never {
    record('REKEY_REQUIRED', actor, meta, { roomId: access.roomId, reason: 'WRAP_LIMIT_REACHED' });
    throw rekeyRequired();
  }

  return {
    /** AZ-20 list: live notes with their ciphertext, newest first (the title is inside the ciphertext). */
    async listNotes(
      actor: Actor,
      access: RoomAccess,
      after: ListPosition | undefined,
      take: number,
      meta: RequestMeta,
    ): Promise<NoteRecord[]> {
      const notes = await store.listRoomNotes(access.roomId, actor.userId, clock(), after, take);
      recordRead(actor, access, meta, { notes: notes.length });
      return notes;
    },

    /** AZ-20 one note. */
    async readNote(actor: Actor, access: RoomAccess, noteId: string, meta: RequestMeta): Promise<NoteRecord> {
      const note = await store.readRoomNote(access.roomId, noteId, actor.userId, clock());
      if (note === null) throw notFound();
      recordRead(actor, access, meta, { noteId });
      return note;
    },

    /** AZ-19 (DF-12): revision 1 of a new note. */
    async createNote(actor: Actor, access: RoomAccess, input: NoteCreateInput, meta: RequestMeta): Promise<NoteRecord> {
      const now = clock();
      const expiresAt = input.expiresAt === null ? null : new Date(input.expiresAt);
      const values = revisionValues(input);
      const outcome = await transaction(async (tx) => {
        if (!(await tx.lockUploader(actor.userId))) throw notFound();
        const room = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-19');
        if (room.keyState !== 'ACTIVE') throw rekeyRequired();
        if (input.keyVersion !== room.currentKeyVersion) throw keyVersionStale();
        checkExpiry(room, expiresAt, now);
        if (await tx.noteIdUsed(input.noteId)) throw new NoteIdUnavailableError();
        if ((await tx.liveNoteCount(room.id)) >= NOTE_LIMITS.maxLiveNotesPerRoom) {
          throw new HttpError(409, ErrorCode.NOTE_LIMIT_REACHED, 'This room holds the most notes it can');
        }
        if (!(await tx.consumeWrap(room.id, input.keyVersion, now))) return { kind: 'wrap-limit' as const };
        const note = await tx.insertNote({
          id: input.noteId,
          roomId: room.id,
          authorId: actor.userId,
          algorithmSuite: input.suite,
          ...values,
          expiresAt,
          now,
        });
        return { kind: 'ok' as const, note };
      }).catch((error: unknown) => {
        if (error instanceof NoteIdUnavailableError) {
          throw new HttpError(409, ErrorCode.NOTE_ID_UNAVAILABLE, 'This note ID cannot be used');
        }
        throw error;
      });
      if (outcome.kind === 'wrap-limit') return wrapLimitReached(actor, access, meta);
      record('NOTE_CREATED', actor, meta, {
        roomId: access.roomId,
        noteId: input.noteId,
        revision: 1,
        keyVersion: input.keyVersion,
      });
      return outcome.note;
    },

    /**
     * AZ-21 (DF-12): the next revision, only if the stored revision is still the expected one. Two
     * editors who both read revision r cannot both save r + 1: the note row is locked, the second
     * save sees r + 1 and gets REVISION_CONFLICT, and its ciphertext is not stored.
     */
    async updateNote(
      actor: Actor,
      access: RoomAccess,
      noteId: string,
      input: NoteUpdateInput,
      meta: RequestMeta,
    ): Promise<NoteRecord> {
      const now = clock();
      const values = revisionValues(input);
      const outcome = await transaction(async (tx) => {
        if (!(await tx.lockUploader(actor.userId))) throw notFound();
        let target: NoteFacts | null = null;
        const room = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-21', async () => {
          target = await tx.lockRoomNote(access.roomId, noteId);
          return target === null ? null : { roomId: target.roomId, createdById: target.authorId };
        });
        const locked = target as NoteFacts | null;
        // An expired note is refused like a missing one, before cleanup removes it (INV-14).
        if (locked === null || (locked.expiresAt !== null && locked.expiresAt.getTime() <= now.getTime())) {
          throw notFound();
        }
        if (room.keyState !== 'ACTIVE') throw rekeyRequired();
        if (input.keyVersion !== room.currentKeyVersion) throw keyVersionStale();
        if (locked.revision !== input.expectedRevision) throw revisionConflict();
        if (!(await tx.consumeWrap(room.id, input.keyVersion, now))) return { kind: 'wrap-limit' as const };
        const note = await tx.updateNoteRevision(room.id, noteId, input.expectedRevision, actor.userId, values, now);
        if (note === null) throw revisionConflict();
        return { kind: 'ok' as const, note };
      });
      if (outcome.kind === 'wrap-limit') return wrapLimitReached(actor, access, meta);
      record('NOTE_UPDATED', actor, meta, {
        roomId: access.roomId,
        noteId,
        revision: outcome.note.revision,
        keyVersion: outcome.note.keyVersion,
      });
      return outcome.note;
    },

    /** AZ-22: tombstone (ciphertext and wrapped NEK removed). */
    async deleteNote(actor: Actor, access: RoomAccess, noteId: string, meta: RequestMeta): Promise<void> {
      await transaction(async (tx) => {
        let target: NoteFacts | null = null;
        const room = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-22', async () => {
          target = await tx.lockRoomNote(access.roomId, noteId);
          return target === null ? null : { roomId: target.roomId, createdById: target.authorId };
        });
        if ((target as NoteFacts | null) === null || !(await tx.tombstoneNote(room.id, noteId, clock()))) {
          throw notFound();
        }
      });
      record('NOTE_DELETED', actor, meta, { roomId: access.roomId, noteId });
    },
  };
}

export type NoteService = ReturnType<typeof createNoteService>;
