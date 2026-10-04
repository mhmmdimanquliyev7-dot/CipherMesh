import type { AuthStore, SessionRecord } from '../db/auth-store';
import { digestToken, isWellFormedToken, issueToken } from './tokens';

/**
 * Opaque server-side sessions (ADR-008, session-and-csrf.md, CM-T016, CM-T017).
 * Timers come from CP-08 and section 3 of the session design. The server decides validity on
 * every request from the database row; cookie expiry is only a convenience for the browser.
 */
export const SESSION_POLICY = Object.freeze({
  idleMs: 30 * 60_000,
  absoluteMs: 12 * 60 * 60_000,
  touchIntervalMs: 60_000,
  maxActive: 10,
  preAuthMs: 5 * 60_000,
  preAuthAttempts: 5,
  stepUpMs: 15 * 60_000,
  /** Profile downgrades need a fresher step-up (security-policy-profiles.md). */
  stepUpStrictMs: 5 * 60_000,
});

export interface RequestMeta {
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly requestId: string;
}

/** The authenticated caller, derived only from the validated session row (never from input). */
export interface Actor {
  readonly sessionId: string;
  readonly userId: string;
  readonly user: SessionRecord['user'];
  readonly session: Pick<
    SessionRecord,
    'createdAt' | 'authenticatedAt' | 'mfaVerifiedAt' | 'stepUpAt' | 'idleExpiresAt' | 'absoluteExpiresAt'
  >;
}

export interface IssuedSession {
  readonly token: string;
  readonly sessionId: string;
  readonly maxAgeSeconds: number;
  readonly evicted: number;
}

const idleExpiry = (now: Date, absolute: Date): Date =>
  new Date(Math.min(now.getTime() + SESSION_POLICY.idleMs, absolute.getTime()));

const remainingSeconds = (until: Date, now: Date): number =>
  Math.max(0, Math.floor((until.getTime() - now.getTime()) / 1000));

/**
 * Creates a fresh session with a new random token. Any token the client presented is ignored, so
 * a planted session identifier is never promoted (session fixation, T-08).
 */
export async function issueSession(
  store: AuthStore,
  input: { userId: string; authenticatedAt: Date; mfaVerifiedAt: Date | null; meta: RequestMeta; now: Date },
): Promise<IssuedSession> {
  const { token, digest } = issueToken();
  // The absolute lifetime counts from the password authentication, not from the MFA step.
  const absoluteExpiresAt = new Date(input.authenticatedAt.getTime() + SESSION_POLICY.absoluteMs);
  const created = await store.createSession(
    {
      userId: input.userId,
      tokenDigest: digest,
      now: input.now,
      idleExpiresAt: idleExpiry(input.now, absoluteExpiresAt),
      absoluteExpiresAt,
      authenticatedAt: input.authenticatedAt,
      mfaVerifiedAt: input.mfaVerifiedAt,
      ipAddress: input.meta.ip,
      userAgent: input.meta.userAgent,
    },
    SESSION_POLICY.maxActive,
  );
  return {
    token,
    sessionId: created.id,
    maxAgeSeconds: remainingSeconds(absoluteExpiresAt, input.now),
    evicted: created.evicted,
  };
}

export type ResolveFailure = 'missing' | 'unknown' | 'revoked' | 'expired' | 'disabled';

/**
 * Resolves the session cookie. Rejects unknown, revoked, idle-expired, absolutely expired and
 * disabled-account sessions even if the browser still holds the cookie. Disabling an account takes
 * effect on the next request, independently of the revocation that accompanies it.
 */
export async function resolveSession(
  store: AuthStore,
  token: string | undefined,
  now: Date,
): Promise<{ actor: Actor } | { failure: ResolveFailure }> {
  if (token === undefined) return { failure: 'missing' };
  if (!isWellFormedToken(token)) return { failure: 'unknown' };
  const record = await store.findSessionByDigest(digestToken(token));
  if (record === null) return { failure: 'unknown' };
  if (record.revokedAt !== null) return { failure: 'revoked' };
  if (record.idleExpiresAt <= now || record.absoluteExpiresAt <= now) return { failure: 'expired' };
  if (record.user.status !== 'ACTIVE') return { failure: 'disabled' };

  let idleExpiresAt = record.idleExpiresAt;
  if (now.getTime() - record.lastSeenAt.getTime() >= SESSION_POLICY.touchIntervalMs) {
    idleExpiresAt = idleExpiry(now, record.absoluteExpiresAt);
    await store.touchSession(record.id, now, idleExpiresAt);
  }
  return {
    actor: {
      sessionId: record.id,
      userId: record.userId,
      user: record.user,
      session: {
        createdAt: record.createdAt,
        authenticatedAt: record.authenticatedAt,
        mfaVerifiedAt: record.mfaVerifiedAt,
        stepUpAt: record.stepUpAt,
        idleExpiresAt,
        absoluteExpiresAt: record.absoluteExpiresAt,
      },
    },
  };
}

/** Replaces the session token (rotation). The old token stops working immediately. */
export async function rotateSession(
  store: AuthStore,
  actor: Actor,
  now: Date,
  changes: { stepUpAt?: Date; mfaVerifiedAt?: Date; authenticatedAt?: Date } = {},
): Promise<IssuedSession | undefined> {
  const { token, digest } = issueToken();
  const rotated = await store.rotateSession(actor.sessionId, digest, now, {
    ...changes,
    idleExpiresAt: idleExpiry(now, actor.session.absoluteExpiresAt),
  });
  if (!rotated) return undefined;
  return {
    token,
    sessionId: actor.sessionId,
    maxAgeSeconds: remainingSeconds(actor.session.absoluteExpiresAt, now),
    evicted: 0,
  };
}

// --------------------------------------------------------------------------------------- gates

export type GateFailure = 'REAUTH_REQUIRED' | 'STEP_UP_REQUIRED';

/** PC-02 foundation: the last password authentication must be recent enough. */
export function requireRecentAuthentication(actor: Actor, maxAgeMs: number, now: Date): GateFailure | undefined {
  return now.getTime() - actor.session.authenticatedAt.getTime() <= maxAgeMs ? undefined : 'REAUTH_REQUIRED';
}

/** PC-03 and CM-T021: a step-up (password, plus TOTP when enabled) within the window. */
export function requireStepUp(actor: Actor, windowMs: number, now: Date): GateFailure | undefined {
  const at = actor.session.stepUpAt;
  return at !== null && now.getTime() - at.getTime() <= windowMs && at <= now ? undefined : 'STEP_UP_REQUIRED';
}
