import { fromBase64Url, toBase64Url } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import type { EncryptedNote, StoredNote } from './notes';
import { AES_GCM, NOTES } from './params';

/**
 * Wire format of encrypted notes (Phase 8, DF-12): binary values as unpadded base64url (CP-15).
 * The request carries one revision's ciphertext and wrapped NEK; the room comes from the path, the
 * note ID from the path or the creation body, and the revision is decided by the API (1 on
 * creation, the expected revision plus one on an update).
 */
export interface NoteCiphertextWire {
  readonly keyVersion: number;
  readonly suite: string;
  readonly wrappedNek: string;
  readonly nekIv: string;
  readonly ciphertext: string;
  readonly contentIv: string;
}

/** A stored note as the API returns it: the ciphertext fields plus its identifiers. */
export interface StoredNoteWire extends NoteCiphertextWire {
  readonly noteId: string;
  readonly revision: number;
}

const integrity = (): CryptoError => new CryptoError(CryptoErrorCode.NOTE_INTEGRITY_FAILED);

/** The ciphertext fields of a create or update request. */
export function noteCiphertextToWire(note: EncryptedNote): NoteCiphertextWire {
  return {
    keyVersion: note.keyVersion,
    suite: note.suite,
    wrappedNek: toBase64Url(note.wrappedNek.ciphertext),
    nekIv: toBase64Url(note.wrappedNek.iv),
    ciphertext: toBase64Url(note.content.ciphertext),
    contentIv: toBase64Url(note.content.iv),
  };
}

/**
 * Decodes a note record the API returned for the room in the request path. Malformed values are an
 * integrity failure: nothing the server sends is trusted before openNote authenticates it.
 */
export function storedNoteFromWire(roomId: string, wire: StoredNoteWire): StoredNote {
  try {
    const ciphertext = fromBase64Url(wire.ciphertext);
    if (ciphertext.length > NOTES.maxDocumentBytes + AES_GCM.tagBytes) throw integrity();
    return {
      roomId,
      noteId: wire.noteId,
      revision: wire.revision,
      keyVersion: wire.keyVersion,
      suite: wire.suite,
      wrappedNek: {
        iv: fromBase64Url(wire.nekIv, AES_GCM.ivBytes),
        ciphertext: fromBase64Url(wire.wrappedNek, NOTES.wrappedNekBytes),
      },
      content: { iv: fromBase64Url(wire.contentIv, AES_GCM.ivBytes), ciphertext },
    };
  } catch {
    throw integrity();
  }
}
