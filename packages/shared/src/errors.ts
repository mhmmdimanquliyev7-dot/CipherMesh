/**
 * Stable API error codes. Clients branch on `code`, never on the message.
 * Codes are added here when a phase implements the behaviour that returns them;
 * docs/security/authorization-model.md section 7 lists the planned codes.
 */
export const ErrorCode = {
  NOT_FOUND: 'NOT_FOUND',
  INVALID_JSON: 'INVALID_JSON',
  PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE',
  UNSUPPORTED_MEDIA_TYPE: 'UNSUPPORTED_MEDIA_TYPE',
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  ORIGIN_REJECTED: 'ORIGIN_REJECTED',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  // Authentication (Phase 3, authorization-model.md section 7)
  UNAUTHENTICATED: 'UNAUTHENTICATED',
  REAUTH_REQUIRED: 'REAUTH_REQUIRED',
  STEP_UP_REQUIRED: 'STEP_UP_REQUIRED',
  MFA_REQUIRED: 'MFA_REQUIRED',
  FORBIDDEN: 'FORBIDDEN',
  RATE_LIMITED: 'RATE_LIMITED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  INVALID_CODE: 'INVALID_CODE',
  EMAIL_UNAVAILABLE: 'EMAIL_UNAVAILABLE',
  PASSWORD_REJECTED: 'PASSWORD_REJECTED',
  MFA_STATE_CONFLICT: 'MFA_STATE_CONFLICT',
  // Vault and public-key directory (Phase 4). Unlock failures never reach the API: unlocking is
  // local, so there is no server-side code for a wrong Vault Passphrase.
  VAULT_NOT_FOUND: 'VAULT_NOT_FOUND',
  VAULT_ALREADY_EXISTS: 'VAULT_ALREADY_EXISTS',
  VAULT_SETUP_REQUIRED: 'VAULT_SETUP_REQUIRED',
  VAULT_CONFLICT: 'VAULT_CONFLICT',
  INVALID_VAULT_FORMAT: 'INVALID_VAULT_FORMAT',
  IDENTITY_REJECTED: 'IDENTITY_REJECTED',
  VAULT_SIGNATURE_INVALID: 'VAULT_SIGNATURE_INVALID',
  // Rooms (Phase 5). Room IDs are chosen by the creating browser because they enter the room's
  // cryptographic contexts from Phase 6 on (DF-05); an ID that was ever used is refused.
  ROOM_ID_UNAVAILABLE: 'ROOM_ID_UNAVAILABLE',
  // Cryptographic membership (Phase 6, authorization-model.md section 7). The API checks shapes,
  // signatures and identity bindings; it never sees room key material (INV-01, INV-04).
  /** Invitations (and their approval and acceptance) while the room is REKEY_REQUIRED or REKEYING (PC-16). */
  REKEY_REQUIRED: 'REKEY_REQUIRED',
  /** A signed room statement (genesis, key version, membership grant) does not verify or does not match. */
  ROOM_STATEMENT_INVALID: 'ROOM_STATEMENT_INVALID',
  /** The envelopes of a request do not form the set the room and its profile require (PC-07). */
  ENVELOPE_SET_INVALID: 'ENVELOPE_SET_INVALID',
  /** The identity key a request names is not the user's current ACTIVE identity. */
  IDENTITY_KEY_CHANGED: 'IDENTITY_KEY_CHANGED',
  ALREADY_MEMBER: 'ALREADY_MEMBER',
  /** The invitee already has an open invitation to this room. */
  INVITATION_PENDING: 'INVITATION_PENDING',
  /** The invitation is not in a state that allows the action (awaiting approval, closed, invalid). */
  INVITATION_NOT_OPEN: 'INVITATION_NOT_OPEN',
  INVITATION_EXPIRED: 'INVITATION_EXPIRED',
  /** RESTRICTED invitations need a confirmed invitee fingerprint (PC-05). */
  FINGERPRINT_REQUIRED: 'FINGERPRINT_REQUIRED',
  /** The confirmed fingerprint differs from the invitee's current identity fingerprint (PC-05, T-25). */
  FINGERPRINT_MISMATCH: 'FINGERPRINT_MISMATCH',
  // Encrypted files (Phase 7, authorization-model.md section 7, DF-07, DF-08). The API sees only
  // ciphertext, the wrapped FEK and the encrypted manifest (INV-01, INV-16).
  /** A content write names a key version other than the room's current one (PC-16). */
  KEY_VERSION_STALE: 'KEY_VERSION_STALE',
  /** The client-chosen file ID was used before; file IDs enter the file's AAD (CD-08). */
  FILE_ID_UNAVAILABLE: 'FILE_ID_UNAVAILABLE',
  /** The expiry is missing where the profile requires one, or later than it allows (PC-08). */
  EXPIRY_NOT_ALLOWED: 'EXPIRY_NOT_ALLOWED',
  /** The room or account storage quota, or the limit on pending uploads, would be exceeded. */
  FILE_QUOTA_EXCEEDED: 'FILE_QUOTA_EXCEEDED',
  /** Completion before the ciphertext reached storage; the upload can still be retried. */
  UPLOAD_INCOMPLETE: 'UPLOAD_INCOMPLETE',
  /** The stored object differs from the announced size; the upload was cancelled. */
  UPLOAD_SIZE_MISMATCH: 'UPLOAD_SIZE_MISMATCH',
  /** Completion after the completion window; the upload was abandoned. */
  UPLOAD_EXPIRED: 'UPLOAD_EXPIRED',
  /** The file is not waiting for completion (already completed, cancelled or deleted). */
  FILE_NOT_PENDING: 'FILE_NOT_PENDING',
  /** Object storage is not configured or did not answer; nothing was changed. */
  STORAGE_UNAVAILABLE: 'STORAGE_UNAVAILABLE',
  // Encrypted notes (Phase 8, DF-12). The API sees only the note ciphertext and the wrapped NEK.
  /** The client-chosen note ID was used before; note IDs enter the note's AAD (CD-08). */
  NOTE_ID_UNAVAILABLE: 'NOTE_ID_UNAVAILABLE',
  /** An update named a revision that is no longer the stored one: someone else saved first. */
  REVISION_CONFLICT: 'REVISION_CONFLICT',
  /** The room holds the most notes D-08-01 allows, or the note reached the last revision. */
  NOTE_LIMIT_REACHED: 'NOTE_LIMIT_REACHED',
  // Recipient-bound secrets (Phase 9, DF-09). The API sees only the payload ciphertext and the
  // wrapped SEK (INV-01, INV-17). Callers who are not the recipient get NOT_FOUND (OL-06).
  /** The client-chosen secret ID was used before; secret IDs enter both contexts of the secret (CD-08). */
  SECRET_ID_UNAVAILABLE: 'SECRET_ID_UNAVAILABLE',
  /** The recipient is not an ACTIVE member with that ACTIVE identity key, or is the sender. */
  SECRET_RECIPIENT_INVALID: 'SECRET_RECIPIENT_INVALID',
  /** Burn-after-reading is mandatory in this room's profile (PC-10). */
  BURN_REQUIRED: 'BURN_REQUIRED',
  /** The sender has the most ACTIVE secrets D-09-04 allows. */
  SECRET_LIMIT_REACHED: 'SECRET_LIMIT_REACHED',
  /**
   * For the recipient or sender only: the secret was already revealed and burned, expired or was
   * revoked, or the recipient's identity key changed since it was sent. Nothing was released.
   */
  SECRET_UNAVAILABLE: 'SECRET_UNAVAILABLE',
  // Security policies (Phase 10, CM-T046 to CM-T048).
  /**
   * The room's stored policy version is not one this server can evaluate. The room is refused
   * rather than served under another version or a weaker profile (fail closed).
   */
  POLICY_UNSUPPORTED: 'POLICY_UNSUPPORTED',
  /** A profile change named a current profile that is no longer the stored one (stale request). */
  PROFILE_CHANGED: 'PROFILE_CHANGED',
  // Key rotation (Phase 11, ADR-013 section "Idempotency and replay", authorization-model section 7).
  /** Another member's rekey operation holds a valid lease (one live operation per room, CP-25). */
  REKEY_IN_PROGRESS: 'REKEY_IN_PROGRESS',
  /** The operation is ABANDONED, SUPERSEDED, CANCELLED or STALE, or its lease or snapshot ended. */
  REKEY_OPERATION_CLOSED: 'REKEY_OPERATION_CLOSED',
  /** A repeated finalize of a COMPLETED operation carries a different payload. */
  REKEY_PAYLOAD_MISMATCH: 'REKEY_PAYLOAD_MISMATCH',
  /** The envelope set differs from the server's recipient snapshot (missing, extra or duplicate). */
  REKEY_RECIPIENTS_MISMATCH: 'REKEY_RECIPIENTS_MISMATCH',
  /** Only the member who started a rekey operation can finalize it (OL-13). */
  REKEY_NOT_STARTER: 'REKEY_NOT_STARTER',
  /** The room has no key version to rotate (created before Phase 6, L-43). */
  ROOM_KEY_UNAVAILABLE: 'ROOM_KEY_UNAVAILABLE',
  /** AZ-14: the member already holds the current key version under their current identity. */
  RESHARE_NOT_NEEDED: 'RESHARE_NOT_NEEDED',
  // Operational ISMS (ADR-016, docs/security/isms-operations.md).
  /** A risk, control, clause, evidence item, policy, user or record named in the request is unknown. */
  ISMS_REFERENCE_UNKNOWN: 'ISMS_REFERENCE_UNKNOWN',
  /** The transition does not exist for this record, or not from its current status. */
  ISMS_TRANSITION_NOT_ALLOWED: 'ISMS_TRANSITION_NOT_ALLOWED',
  /** A documented condition of the transition is not met; `issues` name which (path "condition"). */
  ISMS_CONDITION_NOT_MET: 'ISMS_CONDITION_NOT_MET',
  /** The record changed since the caller read it (optimistic concurrency). */
  ISMS_VERSION_CONFLICT: 'ISMS_VERSION_CONFLICT',
  /** An attached verification output is too large or contains secret material (INV-10). */
  ISMS_ATTACHMENT_REJECTED: 'ISMS_ATTACHMENT_REJECTED',
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

/** A validation problem: where it is and what kind. Never the rejected value (INV-10). */
export interface ValidationIssue {
  readonly path: string;
  readonly code: string;
}

/** The only error shape the API returns. */
export interface ApiErrorBody {
  readonly error: {
    readonly code: ErrorCode;
    readonly message: string;
    readonly requestId: string;
    readonly issues?: readonly ValidationIssue[];
  };
}

const CODES: ReadonlySet<string> = new Set(Object.values(ErrorCode));

export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === 'string' && CODES.has(value);
}
