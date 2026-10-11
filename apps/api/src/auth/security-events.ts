import type { Logger } from '../logging/logger';

/**
 * Authentication, vault and room security events (Phase 3, extended in Phases 4, 5 and 6).
 *
 * Every security-relevant authentication action goes through this single module with a name from
 * a fixed catalogue and allowlisted detail fields. In Phase 3 the sink is the structured
 * application log (redacted like every log line). Events are NOT written to `audit_events` yet:
 * INV-09 requires audit rows to be hash-chained, and the chain arrives in Phase 12 (ADR-009,
 * CM-T054). Rows inserted now could never be chained later, because the table is append-only.
 * Phase 12 replaces the sink with the ledger writer inside the same transactions; the catalogue
 * and call sites stay. Failed and successful logins are additionally stored in login_attempts.
 *
 * Never put passwords, codes, secrets, tokens, cookies or digests in details (INV-10).
 */
export const SECURITY_EVENTS = [
  'USER_REGISTERED',
  'LOGIN_SUCCEEDED',
  'LOGIN_FAILED',
  'LOGIN_THROTTLED',
  'MFA_CHALLENGE_FAILED',
  'LOGOUT',
  'SESSION_REVOKED',
  'SESSIONS_REVOKED',
  'SESSION_EVICTED',
  'PASSWORD_CHANGED',
  'MFA_ENROLLMENT_STARTED',
  'MFA_ENABLED',
  'MFA_DISABLED',
  'RECOVERY_CODE_USED',
  'RECOVERY_CODES_REGENERATED',
  'STEP_UP_COMPLETED',
  'STEP_UP_FAILED',
  'ACCOUNT_DISABLED',
  'ACCOUNT_ENABLED',
  'PLATFORM_ROLE_CHANGED',
  // Vault and public-key directory (Phase 4). Unlock attempts are local and never reported: the
  // server learns nothing about Vault Passphrase guesses (DF-04).
  'VAULT_CREATED',
  'VAULT_REWRAPPED',
  'VAULT_RESET',
  'VAULT_REJECTED',
  'DIRECTORY_LOOKUP_THROTTLED',
  // Room authorization (Phase 5): every denied room-scoped request, with the action ID and the
  // reason code only. No room name and no request field (authorization model section 7).
  'ROOM_ACCESS_DENIED',
  // Room lifecycle and membership administration (Phase 5, PC-13 BASELINE events; names from
  // ADR-013 where it defines them). Details carry the room ID and roles or reason codes, never
  // the room name, which members may have filled with sensitive text despite the warning (T-28).
  'ROOM_CREATED',
  'ROOM_RENAMED',
  'ROOM_DELETED',
  'MEMBER_ROLE_CHANGED',
  'MEMBER_REMOVED',
  'MEMBER_SUSPENDED',
  'OWNERSHIP_TRANSFERRED',
  'REKEY_REQUIRED',
  // Cryptographic membership (Phase 6, PC-13 BASELINE). Details carry identifiers, roles, key
  // versions and reason codes only: never an envelope, commitment, signature, fingerprint or
  // Room Safety Code (INV-10, INV-18).
  'INVITATION_CREATED',
  'INVITATION_APPROVED',
  'INVITATION_REVOKED',
  'INVITATION_DECLINED',
  'INVITATION_INVALIDATED',
  'MEMBER_JOINED',
  /** A signed room statement failed the API's verification and nothing was stored. */
  'ROOM_STATEMENT_REJECTED',
  /** A member's browser refused a room key version and reported it (AZ-29). */
  'ROOM_KEY_REJECTED',
  /** A member's statement that they compared the Room Safety Code of a version (AZ-30). */
  'SAFETY_CODE_CONFIRMED',
  'SAFETY_CODE_MISMATCH_REPORTED',
  // Encrypted files (Phase 7; PC-13: uploads and deletions at BASELINE, download-URL issuance at
  // EXTENDED and FULL). Details carry the room and file IDs, the key version, the ciphertext size
  // and reason codes only: never a presigned URL, an object key, a wrapped FEK or a manifest.
  'FILE_UPLOADED',
  'FILE_UPLOAD_CANCELLED',
  'FILE_DOWNLOAD_ISSUED',
  'FILE_DELETED',
  // Encrypted notes (Phase 8; PC-13: creation, updates and deletions at BASELINE, reads at EXTENDED
  // and FULL). Details carry the room and note IDs, the revision, the key version and counts only:
  // never a title, body, ciphertext or wrapped NEK.
  'NOTE_CREATED',
  'NOTE_UPDATED',
  'NOTE_READ',
  'NOTE_DELETED',
] as const;
export type SecurityEventName = (typeof SECURITY_EVENTS)[number];

export interface SecurityEvent {
  readonly name: SecurityEventName;
  readonly outcome: 'SUCCESS' | 'DENIED' | 'FAILURE';
  /** The authenticated actor, if any (a pseudonymous user ID). */
  readonly actorUserId?: string;
  /** The account the event is about, when different from the actor or before authentication. */
  readonly targetUserId?: string;
  readonly requestId?: string;
  /** Allowlisted, non-secret facts: reason codes, counts, revoked session counts. */
  readonly details?: Readonly<Record<string, string | number | boolean>>;
}

export interface SecurityEventSink {
  record(event: SecurityEvent): void;
}

export function logSecurityEventSink(logger: Logger): SecurityEventSink {
  return {
    record: (event) => {
      logger.info('security event', {
        event: event.name,
        outcome: event.outcome,
        ...(event.actorUserId === undefined ? {} : { actorUserId: event.actorUserId }),
        ...(event.targetUserId === undefined ? {} : { targetUserId: event.targetUserId }),
        ...(event.requestId === undefined ? {} : { requestId: event.requestId }),
        ...(event.details === undefined ? {} : { details: event.details }),
      });
    },
  };
}
