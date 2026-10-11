import { decrypt, encrypt, generateDataKey, unwrapDataKey, wrapDataKey, type Sealed } from './aead';
import { canonicalBytes } from './canonical';
import { contextBytes, type CanonicalBytes } from './contexts';
import { bytesEqual, isWellFormedUnicode, utf8Decode, wipe } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { AES_GCM, NOTES, SUITE } from './params';
import type { OpenedRoomKey } from './room-keys';
import type { Bytes } from './types';

/**
 * Encrypted notes (Phase 8, CM-T042; cryptographic-architecture section 6.2, DF-12).
 *
 *   NEK_r    = fresh random AES-256-GCM key for revision r (one per saved revision, INV-03)
 *   document = RFC 8785 {body, title, v: 1}, at most 64 KiB (D-08-01)
 *   content  = AES-256-GCM(NEK_r, document, AAD = cm.note.content {roomId, noteId, revision: r})
 *   wrapped  = AES-256-GCM wrap of NEK_r under RWK_v, AAD = cm.dek.wrap
 *              {roomId, keyVersion, itemType: 'note', itemId: noteId, revision: r}
 *
 * The title and the body are one message, so neither can be swapped or replayed without the
 * other. The revision is in both contexts: ciphertext or a wrapped NEK moved to another note,
 * room, key version or revision fails authentication (T-07). Every save makes a new NEK, so a NEK
 * encrypts exactly one message (CP-16) and IV reuse across edits is impossible by construction;
 * every IV is generated inside the AES-GCM wrapper (INV-02).
 *
 * The room key must have passed the Phase 6 verification rule: this module only accepts an
 * OpenedRoomKey from openRoomKey, whose RWK_v is a non-extractable wrapping key. The NEK leaves
 * this module only wrapped; when a note is opened it is unwrapped as a non-extractable,
 * decrypt-only key and dropped. Nothing is stored.
 *
 * Opening fails closed: the wrapped NEK and the document must authenticate, and the document must
 * be the canonical serialization of a valid version-1 note, before the title or body is returned.
 * What authentication cannot show: whether the server served the newest revision (T-32, L-10).
 * The revision a caller sees is authenticated, so the browser can notice a revision that goes
 * backwards during a session; it cannot notice an older revision it never saw replaced.
 */

/** The plaintext of a note. Untrusted text when opened: render as text only (T-12). */
export interface NoteContent {
  readonly title: string;
  readonly body: string;
}

/** What the author's browser sends to the API for one revision: ciphertext and the wrapped NEK. */
export interface EncryptedNote {
  readonly roomId: string;
  readonly noteId: string;
  readonly revision: number;
  readonly keyVersion: number;
  readonly suite: typeof SUITE;
  readonly wrappedNek: Sealed;
  readonly content: Sealed;
}

/** A note record as the API returned it, decoded. Every value is untrusted until openNote checks it. */
export interface StoredNote {
  readonly roomId: string;
  readonly noteId: string;
  readonly revision: number;
  readonly keyVersion: number;
  readonly suite: string;
  readonly wrappedNek: Sealed;
  readonly content: Sealed;
}

/** A note after authenticated decryption: the identifiers it was bound to, and its text. */
export interface OpenedNote extends NoteContent {
  readonly roomId: string;
  readonly noteId: string;
  readonly revision: number;
  readonly keyVersion: number;
}

const integrityFailed = (): CryptoError => new CryptoError(CryptoErrorCode.NOTE_INTEGRITY_FAILED);
const invalidInput = (): CryptoError => new CryptoError(CryptoErrorCode.INVALID_INPUT);

/** C0 and C1 controls and the bidirectional marks and overrides: never part of a title (T-11). */
// eslint-disable-next-line no-control-regex -- the class is the point: it rejects control characters
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]/;

/** A title: one line of 1 to 200 UTF-16 code units, well-formed, without control characters. */
export function isNoteTitle(title: unknown): title is string {
  return (
    typeof title === 'string' &&
    title.length >= 1 &&
    title.length <= NOTES.maxTitleLength &&
    isWellFormedUnicode(title) &&
    !CONTROL_CHARACTERS.test(title)
  );
}

/** A body: any well-formed text, including empty; the document size bounds its length. */
function isNoteBody(body: unknown): body is string {
  return typeof body === 'string' && isWellFormedUnicode(body);
}

function isRevision(revision: unknown): revision is number {
  return (
    typeof revision === 'number' && Number.isSafeInteger(revision) && revision >= 1 && revision <= NOTES.maxRevision
  );
}

function documentOf(content: NoteContent): Bytes {
  return canonicalBytes({ v: NOTES.formatVersion, title: content.title, body: content.body });
}

/**
 * The size in bytes of the note document that would be encrypted (at most NOTES.maxDocumentBytes),
 * so a form can say "too long" before encrypting. Returns Infinity for text that is not a note.
 */
export function noteDocumentBytes(content: NoteContent): number {
  if (!isNoteBody(content.body) || typeof content.title !== 'string' || !isWellFormedUnicode(content.title)) {
    return Number.POSITIVE_INFINITY;
  }
  const document = documentOf(content);
  wipe(document);
  return document.length;
}

function contentContext(roomId: string, noteId: string, revision: number): CanonicalBytes {
  return contextBytes('cm.note.content', { roomId, noteId, revision });
}

function wrapContext(roomId: string, keyVersion: number, noteId: string, revision: number): CanonicalBytes {
  return contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'note', itemId: noteId, revision });
}

/**
 * Encrypts one revision of a note in the browser with a fresh NEK under the given verified room
 * key version (normally the room's current one: the API refuses writes under any other, PC-16).
 * The caller chooses the note ID (UUIDv4, part of every context) and passes the revision this
 * save creates: 1 for a new note, the stored revision plus one for an edit.
 */
export async function encryptNote(
  roomKey: OpenedRoomKey,
  input: { readonly noteId: string; readonly revision: number } & NoteContent,
): Promise<EncryptedNote> {
  const { roomId, keyVersion } = roomKey;
  const { noteId, revision, title, body } = input;
  if (!isRevision(revision) || !isNoteTitle(title) || !isNoteBody(body)) throw invalidInput();
  // The contexts validate the identifiers; build them before any key exists.
  const contentAad = contentContext(roomId, noteId, revision);
  const wrapAad = wrapContext(roomId, keyVersion, noteId, revision);
  const document = documentOf({ title, body });
  try {
    if (document.length > NOTES.maxDocumentBytes) throw invalidInput();
    const nek = await generateDataKey();
    const content = await encrypt(nek, document, contentAad);
    const wrappedNek = await wrapDataKey(nek, roomKey.wrappingKey, wrapAad);
    return { roomId, noteId, revision, keyVersion, suite: SUITE, wrappedNek, content };
  } finally {
    wipe(document);
  }
}

const DOCUMENT_FIELDS = ['body', 'title', 'v'];

/** Parses a version-1 note document. Anything else is refused; nothing is guessed. */
function parseDocument(bytes: Bytes): NoteContent {
  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(bytes));
  } catch {
    throw integrityFailed();
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw integrityFailed();
  const record = value as Record<string, unknown>;
  if (record['v'] !== NOTES.formatVersion) {
    throw new CryptoError(
      typeof record['v'] === 'number' ? CryptoErrorCode.NOTE_FORMAT_UNSUPPORTED : CryptoErrorCode.NOTE_INTEGRITY_FAILED,
    );
  }
  const keys = Object.keys(record).sort();
  if (keys.length !== DOCUMENT_FIELDS.length || keys.some((key, i) => key !== DOCUMENT_FIELDS[i])) {
    throw integrityFailed();
  }
  const { title, body } = record;
  if (!isNoteTitle(title) || !isNoteBody(body)) throw integrityFailed();
  // Only the canonical serialization is a note: no duplicate keys, whitespace or other encodings
  // that two parsers could read differently.
  const canonical = documentOf({ title, body });
  const same = bytesEqual(canonical, bytes);
  wipe(canonical);
  if (!same) throw integrityFailed();
  return { title, body };
}

/**
 * Opens a stored note with the verified room key version that wrapped its NEK: unwraps the NEK as
 * a non-extractable decrypt-only key, authenticates the document under the stored revision and
 * returns the title and body only if every check passes. The caller picks the key version the
 * record names; a key of another room or version is refused.
 */
export async function openNote(roomKey: OpenedRoomKey, record: StoredNote): Promise<OpenedNote> {
  if (record.suite !== SUITE) throw new CryptoError(CryptoErrorCode.NOTE_FORMAT_UNSUPPORTED);
  if (roomKey.roomId !== record.roomId || roomKey.keyVersion !== record.keyVersion) throw invalidInput();
  if (
    !isRevision(record.revision) ||
    record.wrappedNek.ciphertext.length !== NOTES.wrappedNekBytes ||
    record.wrappedNek.iv.length !== AES_GCM.ivBytes ||
    record.content.iv.length !== AES_GCM.ivBytes ||
    record.content.ciphertext.length <= AES_GCM.tagBytes ||
    record.content.ciphertext.length > NOTES.maxDocumentBytes + AES_GCM.tagBytes
  ) {
    throw integrityFailed();
  }
  const { roomId, noteId, revision, keyVersion } = record;
  const contentAad = contentContext(roomId, noteId, revision);
  const nek = await unwrapDataKey(
    record.wrappedNek,
    roomKey.wrappingKey,
    wrapContext(roomId, keyVersion, noteId, revision),
  );
  const document = await decrypt(nek, record.content, contentAad);
  try {
    return { roomId, noteId, revision, keyVersion, ...parseDocument(document) };
  } finally {
    wipe(document);
  }
}
