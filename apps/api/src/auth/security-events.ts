import type { Logger } from '../logging/logger';

/**
 * Authentication security events (Phase 3).
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
