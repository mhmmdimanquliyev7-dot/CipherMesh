/**
 * Encrypted notes (Phase 8, CM-T042, DF-12). Constants shared by the API and the web client. The
 * sizes come from the parameter register (CP-28, decision D-08-01); tests compare them with it and
 * with the crypto package. The profile rules for notes (PC-08, PC-13) are in the versioned policy
 * catalogue (./policy.ts, CM-T046).
 */

/** AES-GCM tag length; a note's ciphertext is its document length plus this (CP-01). */
export const NOTE_TAG_BYTES = 16;

export const NOTE_LIMITS = Object.freeze({
  /**
   * CP-28: the largest note document (the RFC 8785 serialization of title and body). Its
   * ciphertext as base64url, with the other request fields, stays inside the 128 KiB body limit.
   */
  maxDocumentBytes: 64 * 1024,
  maxCiphertextBytes: 64 * 1024 + NOTE_TAG_BYTES,
  /** A document holds at least `{"body":"","title":"x","v":1}` (29 bytes); with the tag, more than 16. */
  minCiphertextBytes: NOTE_TAG_BYTES + 1,
  /** Largest title, in UTF-16 code units. */
  maxTitleLength: 200,
  /** Revisions start at 1 and end at the largest PostgreSQL integer. */
  maxRevision: 2_147_483_647,
  /**
   * D-08-01: notes that are not deleted, per room. Bounds the database space one room can take
   * (at most about 64 MiB of note ciphertext) and the work of listing it.
   */
  maxLiveNotesPerRoom: 1000,
});

/**
 * Largest page of a room's note list (OL-08). Smaller than the file list because each entry carries
 * its ciphertext (the title is encrypted together with the body), up to 64 KiB per note.
 */
export const NOTE_LIST_PAGE_SIZE = 20;
