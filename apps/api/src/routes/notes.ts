import { toBase64Url } from '@ciphermesh/crypto/identity';
import { NOTE_LIST_PAGE_SIZE } from '@ciphermesh/shared';
import {
  emptyBodySchema,
  emptyQuerySchema,
  formatListCursor,
  noteCreateRequestSchema,
  noteDeletedResponseSchema,
  noteListQuerySchema,
  noteListResponseSchema,
  noteParamsSchema,
  noteResponseSchema,
  noteUpdateRequestSchema,
  parseListCursor,
  roomParamsSchema,
} from '@ciphermesh/validation';
import type { NoteRecord } from '../db/note-store';
import type { RoomStore } from '../db/room-store';
import type { NoteService } from '../notes/service';
import { actorOf, defineRoute, roomOf, type AnyRoute, type RoomResourceInput } from './registry';

/**
 * Encrypted note routes (Phase 8, CM-T042; DF-12). Every route is a room route: the registry
 * authorizes it centrally against the caller's database-loaded membership before the handler runs
 * (OL-01, INV-05), and notes are loaded by note ID AND room ID (OL-02). No route accepts or returns
 * a title, body, NEK or room key; the responses carry the note ciphertext, the wrapped NEK, IVs,
 * the revision and public metadata (INV-01, INV-16).
 *
 *   GET  /rooms/{roomId}/notes                   AZ-20  live notes with ciphertext, newest first
 *   POST /rooms/{roomId}/notes                   AZ-19  revision 1 of a new note
 *   GET  /rooms/{roomId}/notes/{noteId}          AZ-20  one note
 *   POST /rooms/{roomId}/notes/{noteId}/update   AZ-21  the next revision (expected revision, 409 when stale)
 *   POST /rooms/{roomId}/notes/{noteId}/delete   AZ-22  tombstone; own notes for MEMBERs
 */

/** The explicit projection of a note. */
function noteView(note: NoteRecord) {
  return {
    id: note.id,
    authorId: note.authorId,
    updatedById: note.updatedById,
    revision: note.revision,
    keyVersion: note.keyVersion,
    suite: 'CM1' as const,
    wrappedNek: toBase64Url(note.wrappedDek),
    nekIv: toBase64Url(note.dekIv),
    ciphertext: toBase64Url(note.ciphertext),
    contentIv: toBase64Url(note.contentIv),
    expiresAt: note.expiresAt === null ? null : note.expiresAt.toISOString(),
    createdAt: note.createdAt.toISOString(),
    updatedAt: note.updatedAt.toISOString(),
  };
}

export function noteRoutes(notes: NoteService, store: RoomStore): readonly AnyRoute[] {
  // OL-02, OL-04: the note is loaded by its ID and the room ID; the stored author decides `own`.
  const noteResource = async ({ room, params }: RoomResourceInput<{ noteId: string }, unknown, unknown>) => {
    const note = await store.findRoomNote(room.roomId, params.noteId);
    return note === null ? null : { roomId: note.roomId, createdById: note.authorId };
  };

  return [
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/notes',
      action: 'AZ-20-NOTE-LIST',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: noteListQuerySchema,
      body: undefined,
      response: noteListResponseSchema,
      handler: async (ctx) => {
        const after = ctx.query.cursor === undefined ? undefined : parseListCursor(ctx.query.cursor);
        const page = await notes.listNotes(actorOf(ctx), roomOf(ctx), after, NOTE_LIST_PAGE_SIZE + 1, ctx.request);
        const visible = page.slice(0, NOTE_LIST_PAGE_SIZE);
        const last = visible.at(-1);
        return {
          status: 200,
          body: {
            notes: visible.map(noteView),
            nextCursor:
              page.length > NOTE_LIST_PAGE_SIZE && last !== undefined
                ? formatListCursor(last.createdAt, last.id)
                : null,
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/notes',
      action: 'AZ-19-NOTE-CREATE',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: noteCreateRequestSchema,
      response: noteResponseSchema,
      handler: async (ctx) => ({
        status: 201,
        body: { note: noteView(await notes.createNote(actorOf(ctx), roomOf(ctx), ctx.body, ctx.request)) },
      }),
    }),
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/notes/:noteId',
      action: 'AZ-20-NOTE-READ',
      access: { kind: 'room' },
      params: noteParamsSchema,
      query: emptyQuerySchema,
      body: undefined,
      response: noteResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: { note: noteView(await notes.readNote(actorOf(ctx), roomOf(ctx), ctx.params.noteId, ctx.request)) },
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/notes/:noteId/update',
      action: 'AZ-21-NOTE-UPDATE',
      access: { kind: 'room', resource: noteResource },
      params: noteParamsSchema,
      query: emptyQuerySchema,
      body: noteUpdateRequestSchema,
      response: noteResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: {
          note: noteView(await notes.updateNote(actorOf(ctx), roomOf(ctx), ctx.params.noteId, ctx.body, ctx.request)),
        },
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/notes/:noteId/delete',
      action: 'AZ-22-NOTE-DELETE',
      access: { kind: 'room', resource: noteResource },
      params: noteParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: noteDeletedResponseSchema,
      handler: async (ctx) => {
        await notes.deleteNote(actorOf(ctx), roomOf(ctx), ctx.params.noteId, ctx.request);
        return { status: 200, body: { status: 'DELETED' as const } };
      },
    }),
  ];
}
