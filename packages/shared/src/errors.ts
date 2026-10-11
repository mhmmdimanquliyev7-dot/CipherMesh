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
