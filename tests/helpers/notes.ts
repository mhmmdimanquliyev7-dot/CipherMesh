import {
  encryptNote,
  noteCiphertextToWire,
  openNote,
  storedNoteFromWire,
  type EncryptedNote,
  type OpenedNote,
  type StoredNoteWire,
} from '@ciphermesh/crypto';
import { randomUUID } from 'node:crypto';
import { expect } from 'vitest';
import { currentRoomKey } from './files';
import { openRoom, type Identified } from './room-crypto';

// Encrypted notes for the API suites (Phase 8). Notes are encrypted by packages/crypto with the
// room key opened exactly as a browser opens it, and decrypted the same way. Every title and body
// is synthetic; nothing here is a real note.

type Response = { readonly status: number; readonly body: Record<string, unknown> };

/** A note as the API projects it. */
export interface NoteView {
  readonly id: string;
  readonly authorId: string;
  readonly updatedById: string;
  readonly revision: number;
  readonly keyVersion: number;
  readonly suite: string;
  readonly wrappedNek: string;
  readonly nekIv: string;
  readonly ciphertext: string;
  readonly contentIv: string;
  readonly expiresAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/** Encrypts one revision under the room's newest verified key version. */
export async function encryptRevision(
  who: Identified,
  roomId: string,
  noteId: string,
  revision: number,
  title: string,
  body: string,
): Promise<EncryptedNote> {
  return encryptNote(await currentRoomKey(who, roomId), { noteId, revision, title, body });
}

/** POST /rooms/{roomId}/notes with revision 1 (fields may be overridden). */
export async function createNote(
  who: Identified,
  roomId: string,
  title: string,
  body: string,
  overrides: Record<string, unknown> = {},
): Promise<{ readonly response: Response; readonly noteId: string }> {
  const noteId = randomUUID();
  const note = await encryptRevision(who, roomId, noteId, 1, title, body);
  const response = await who.browser.request('POST', `/rooms/${roomId}/notes`, {
    noteId,
    ...noteCiphertextToWire(note),
    expiresAt: null,
    ...overrides,
  });
  return { response, noteId };
}

/** Creates a note and expects 201; returns its ID. */
export async function createdNote(who: Identified, roomId: string, title: string, body: string): Promise<string> {
  const { response, noteId } = await createNote(who, roomId, title, body);
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return noteId;
}

/** The request body of an update from `expectedRevision` to the next revision. */
export async function updateBody(
  who: Identified,
  roomId: string,
  noteId: string,
  expectedRevision: number,
  title: string,
  body: string,
): Promise<Record<string, unknown>> {
  const note = await encryptRevision(who, roomId, noteId, expectedRevision + 1, title, body);
  return { expectedRevision, ...noteCiphertextToWire(note) };
}

/** POST /rooms/{roomId}/notes/{noteId}/update. */
export async function updateNote(
  who: Identified,
  roomId: string,
  noteId: string,
  expectedRevision: number,
  title: string,
  body: string,
): Promise<Response> {
  return who.browser.request(
    'POST',
    `/rooms/${roomId}/notes/${noteId}/update`,
    await updateBody(who, roomId, noteId, expectedRevision, title, body),
  );
}

export const wireOf = (view: NoteView): StoredNoteWire => ({ ...view, noteId: view.id });

/** Authenticates and decrypts a note view with the key version it names, as the browser does. */
export async function openView(who: Identified, roomId: string, view: NoteView | StoredNoteWire): Promise<OpenedNote> {
  const wire = 'noteId' in view ? view : wireOf(view);
  const key = (await openRoom(who, roomId)).find((k) => k.keyVersion === wire.keyVersion);
  if (key === undefined) throw new Error('no key for the note version');
  return openNote(key, storedNoteFromWire(roomId, wire));
}

/** GET one note and decrypt it. */
export async function readNote(who: Identified, roomId: string, noteId: string): Promise<OpenedNote> {
  const response = await who.browser.request('GET', `/rooms/${roomId}/notes/${noteId}`);
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  return openView(who, roomId, response.body['note'] as NoteView);
}
