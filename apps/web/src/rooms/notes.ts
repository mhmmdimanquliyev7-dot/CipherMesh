import {
  CryptoErrorCode,
  encryptNote,
  isCryptoError,
  noteCiphertextToWire,
  noteDocumentBytes,
  NOTES,
  openNote,
  storedNoteFromWire,
  type OpenedNote,
} from '@ciphermesh/crypto';
import {
  noteDeletedResponseSchema,
  noteListResponseSchema,
  noteResponseSchema,
  type NoteRecordView,
} from '@ciphermesh/validation';
import { api } from '../lib/api';
import { RoomKeyMissing, roomKeys } from './keys';

/**
 * Encrypted notes in this tab (Phase 8, CM-T042; DF-12). All cryptography is done by
 * @ciphermesh/crypto with room keys this browser verified (roomKeys, ADR-015 section 4); this
 * module sequences it with the API.
 *
 * - Save: the title and body are encrypted here as one message under a fresh NEK for the new
 *   revision, and the NEK is wrapped under the room's current RWK_v. The API receives only
 *   ciphertext, the wrapped NEK and the revision the editor started from (INV-01). A stale
 *   revision is refused with REVISION_CONFLICT; the editor keeps the text and can reload.
 * - Read: nothing is shown unless the wrapped NEK and the document authenticate under the stored
 *   room, note, key version and revision. A failure marks the note as damaged; no text is shown.
 * - Rollback (T-32, L-10): this tab remembers, in memory only, the highest revision it has seen of
 *   each note. A note served with a lower revision later is flagged. Without trusted state outside
 *   the tab, an older revision the tab never saw replaced cannot be noticed.
 * - Nothing is persisted: no title, body, NEK or room key goes into browser storage, caches or the
 *   URL. Decrypted text lives in React state and is gone when the page or the keys go away.
 */

/** A note as this tab can show it: server metadata, plus the decrypted text when available. */
export interface NoteEntry {
  readonly view: NoteRecordView;
  /** The authenticated note; undefined when this tab holds no key for its version, or it failed. */
  readonly opened?: OpenedNote;
  /** Why the note could not be opened although a key was held. */
  readonly problem?: 'damaged' | 'unsupported';
  /** The server served a lower revision than this tab saw earlier (T-32). */
  readonly rolledBack?: boolean;
}

export class NoteTooLong extends Error {
  readonly code = 'NOTE_TOO_LONG';
  constructor() {
    super('The note is longer than the limit');
    this.name = 'NoteTooLong';
  }
}

// ------------------------------------------------------------------- revision memory (T-32)

const highestSeen = new Map<string, number>();

/** Records a revision this tab saw and reports whether it is lower than one seen before. */
export function observeRevision(noteId: string, revision: number): boolean {
  const seen = highestSeen.get(noteId);
  if (seen !== undefined && revision < seen) return true;
  highestSeen.set(noteId, revision);
  return false;
}

/** For tests: forget every remembered revision. */
export function forgetRevisions(): void {
  highestSeen.clear();
}

// ------------------------------------------------------------------------------- limits

/** The size the note would have once serialized, against the 64 KiB limit (CP-28). */
export function noteFits(title: string, body: string): boolean {
  return noteDocumentBytes({ title, body }) <= NOTES.maxDocumentBytes;
}

export const NOTE_MAX_KIB = NOTES.maxDocumentBytes / 1024;
export const NOTE_TITLE_MAX = NOTES.maxTitleLength;

// ------------------------------------------------------------------------------ operations

/** Opens a note with the key version that wrapped its NEK, if this tab verified it. */
async function open(roomId: string, view: NoteRecordView): Promise<OpenedNote> {
  const key = roomKeys.version(roomId, view.keyVersion);
  if (key === undefined) throw new RoomKeyMissing();
  return openNote(key, storedNoteFromWire(roomId, { ...view, noteId: view.id }));
}

/** Decrypts a view into an entry; failures never expose text. */
export async function entryOf(roomId: string, view: NoteRecordView): Promise<NoteEntry> {
  const rolledBack = observeRevision(view.id, view.revision);
  const flag = rolledBack ? { rolledBack } : {};
  if (roomKeys.version(roomId, view.keyVersion) === undefined) return { view, ...flag };
  try {
    return { view, opened: await open(roomId, view), ...flag };
  } catch (error) {
    const unsupported = isCryptoError(error, CryptoErrorCode.NOTE_FORMAT_UNSUPPORTED);
    return { view, problem: unsupported ? 'unsupported' : 'damaged', ...flag };
  }
}

/** One page of the room's notes, decrypted where this tab can. */
export async function listNotes(
  roomId: string,
  cursor?: string,
): Promise<{ readonly entries: NoteEntry[]; readonly nextCursor: string | null }> {
  const page = await api(
    'GET',
    `/rooms/${roomId}/notes${cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`}`,
    noteListResponseSchema,
  );
  const entries: NoteEntry[] = [];
  for (const view of page.notes) entries.push(await entryOf(roomId, view));
  return { entries, nextCursor: page.nextCursor };
}

/** Fetches one note again (for example after a save conflict). */
export async function fetchNote(roomId: string, noteId: string): Promise<NoteEntry> {
  const { note } = await api('GET', `/rooms/${roomId}/notes/${noteId}`, noteResponseSchema);
  return entryOf(roomId, note);
}

function currentKey(roomId: string) {
  const key = roomKeys.current(roomId);
  if (key === undefined) throw new RoomKeyMissing();
  return key;
}

/** Encrypts and stores revision 1 of a new note under the room's newest verified key version. */
export async function createNote(
  roomId: string,
  title: string,
  body: string,
  expiresAt: string | null,
): Promise<NoteEntry> {
  if (!noteFits(title, body)) throw new NoteTooLong();
  const noteId = crypto.randomUUID();
  const encrypted = await encryptNote(currentKey(roomId), { noteId, revision: 1, title, body });
  const { note } = await api('POST', `/rooms/${roomId}/notes`, noteResponseSchema, {
    noteId,
    ...noteCiphertextToWire(encrypted),
    expiresAt,
  });
  return entryOf(roomId, note);
}

/**
 * Encrypts and stores the next revision of a note the editor read at `expectedRevision`. The API
 * refuses it with REVISION_CONFLICT when someone else saved first; nothing is overwritten.
 */
export async function saveNote(
  roomId: string,
  noteId: string,
  expectedRevision: number,
  title: string,
  body: string,
): Promise<NoteEntry> {
  if (!noteFits(title, body)) throw new NoteTooLong();
  const encrypted = await encryptNote(currentKey(roomId), {
    noteId,
    revision: expectedRevision + 1,
    title,
    body,
  });
  const { note } = await api('POST', `/rooms/${roomId}/notes/${noteId}/update`, noteResponseSchema, {
    expectedRevision,
    ...noteCiphertextToWire(encrypted),
  });
  return entryOf(roomId, note);
}

export async function deleteNote(roomId: string, noteId: string): Promise<void> {
  await api('POST', `/rooms/${roomId}/notes/${noteId}/delete`, noteDeletedResponseSchema, {});
}
