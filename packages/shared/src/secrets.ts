/**
 * Recipient-bound secrets (Phase 9, CM-T043, CM-T044, DF-09). Constants shared by the API and the
 * web client. The size comes from the parameter register (CP-29, decision D-09-01) and the limits
 * from the Phase 9 decisions (phase-09-traceability.md); tests compare them with both documents
 * and with the crypto package. The lifetime and burn rules (PC-09, PC-10) are in the versioned
 * policy catalogue (./policy.ts, CM-T046).
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** AES-GCM tag length; a secret's payload ciphertext is its document length plus this (CP-01). */
export const SECRET_TAG_BYTES = 16;

export const SECRET_LIMITS = Object.freeze({
  /** CP-29: the largest secret document (the RFC 8785 serialization of the text). */
  maxDocumentBytes: 16 * 1024,
  maxCiphertextBytes: 16 * 1024 + SECRET_TAG_BYTES,
  /** A document holds at least `{"text":"x","v":1}` (18 bytes); with the tag, more than 16. */
  minCiphertextBytes: SECRET_TAG_BYTES + 1,
  /** RSA-OAEP-3072 output: the wrapped 32-byte SEK (CP-02). */
  wrappedSekBytes: 384,
  /**
   * D-09-03: the shortest lifetime a sender may choose. A secret that expires before the recipient
   * could reasonably open it only adds a row.
   */
  minLifetimeMs: 5 * MINUTE,
  /**
   * D-09-04: ACTIVE secrets one account has sent and that have not expired, across all rooms.
   * Bounds the database space one account can take (at most about 1.6 MiB of ciphertext) and the
   * worker's sweep.
   */
  maxActiveSentPerAccount: 100,
});

/** Largest page of a room's secret list (OL-08). Entries are metadata only, never ciphertext. */
export const SECRET_LIST_PAGE_SIZE = 50;

/** The longest lifetime any profile allows (PC-09, STANDARD); the database refuses anything longer. */
export const SECRET_MAX_LIFETIME_MS = 7 * DAY;

/**
 * Secret states as the API reports them (data-model 4.13). An ACTIVE secret past its expiry is
 * reported as EXPIRED before the worker marks it (INV-14).
 */
export const SECRET_STATUSES = ['ACTIVE', 'REVEALED', 'EXPIRED', 'REVOKED'] as const;
export type SecretStatus = (typeof SECRET_STATUSES)[number];
