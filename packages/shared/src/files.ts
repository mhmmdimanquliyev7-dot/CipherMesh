/**
 * Encrypted files (Phase 7, CM-T037 to CM-T041). Constants shared by the API and the web client.
 * Every value comes from the parameter register (docs/crypto/crypto-decisions.md); tests compare
 * them with it. The profile rules for files (PC-08, PC-12, PC-13) are in the versioned policy
 * catalogue (./policy.ts, CM-T046).
 */

const MINUTE = 60_000;
const MIB = 1024 * 1024;

/** AES-GCM tag length; a file's ciphertext is its plaintext length plus this (CP-01). */
export const FILE_TAG_BYTES = 16;

export const FILE_LIMITS = Object.freeze({
  /**
   * CP-19: largest file, encrypted in one AES-GCM operation in the browser. WebCrypto has no
   * streaming AES-GCM; larger files need the chunked design of OCD-09 and its own ADR.
   */
  maxPlaintextBytes: 50 * MIB,
  /** The largest ciphertext the API presigns an upload for: CP-19 plus the tag. */
  maxCiphertextBytes: 50 * MIB + FILE_TAG_BYTES,
  /** CP-20: a presigned upload (PUT) is valid for at most 5 minutes, for one size. */
  uploadUrlSeconds: 300,
  /** CP-20: a presigned download (GET) is valid for at most 60 seconds, as an attachment. */
  downloadUrlSeconds: 60,
  /**
   * Completion must arrive within this time of the upload request. A PUT that starts just before
   * its URL expires may take minutes on a slow link; anything later is abandoned and the worker
   * removes the row's object (DF-07).
   */
  completionWindowMs: 15 * MINUTE,
  /** Largest encrypted manifest accepted (name, type, size and plaintext hash, plus the tag). */
  maxManifestCiphertextBytes: 4096,
  /** Largest file name kept in a manifest, in UTF-16 code units. */
  maxNameLength: 255,
  /** Largest MIME type kept in a manifest. */
  maxTypeLength: 127,
});

/**
 * Upload quotas (CM-T041, decision D-07-01 in phase-07-traceability.md). The backlog requires
 * per-room and per-user quotas without fixing values; these bound storage use on the shared
 * bucket and the number of upload capabilities one account holds at a time (T-26). Bytes count
 * ciphertext of every file that is not DELETED, including uploads still pending.
 */
export const FILE_QUOTAS = Object.freeze({
  perRoomBytes: 1024 * MIB,
  perUserBytes: 2048 * MIB,
  /** Uploads one account may have in PENDING_UPLOAD at once, across all rooms. */
  pendingUploadsPerUser: 5,
});

/** Largest page of a room's file list (OL-08). */
export const FILE_LIST_PAGE_SIZE = 50;

/**
 * Image types a member may preview in the page after decryption (CM-T041, T-11): raster formats
 * only, shown through a blob: URL in an <img> element, which never runs scripts. SVG and HTML are
 * never rendered; everything else is only saved as an attachment.
 */
export const PREVIEWABLE_IMAGE_TYPES: readonly string[] = Object.freeze([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
]);
