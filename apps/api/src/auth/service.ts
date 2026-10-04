import { ErrorCode } from '@ciphermesh/shared';
import type { AuthStore } from '../db/auth-store';
import { HttpError } from '../http/errors';
import { backoffSeconds, BusyError, FixedWindowLimiter } from './limits';
import { checkNewPassword, normalizePassword, type PasswordHasher } from './password';
import { canonicalRecoveryCode, generateRecoveryCodes, recoveryCodeDigest } from './recovery-codes';
import type { SecurityEventSink } from './security-events';
import {
  issueSession,
  rotateSession,
  SESSION_POLICY,
  type Actor,
  type IssuedSession,
  type RequestMeta,
} from './sessions';
import { digestToken, isWellFormedToken, issueToken } from './tokens';
import { generateTotpSecret, totpEnrollment, verifyTotp } from './totp';
import type { TotpSecretBox } from './totp-secret-box';

/**
 * Authentication workflows (CM-T015 to CM-T022). HTTP routes call these functions; they never
 * touch the database directly. Every function derives the user from the validated session or
 * pre-authentication state, never from client-supplied identifiers.
 * Design: docs/security/authentication-security.md.
 */
export interface AuthDependencies {
  readonly store: AuthStore;
  readonly transaction: <T>(fn: (store: AuthStore) => Promise<T>) => Promise<T>;
  readonly hasher: PasswordHasher;
  readonly totpBox: TotpSecretBox;
  readonly identifierHmac: (normalizedIdentifier: string) => Buffer;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
  readonly limits: AuthRateLimits;
}

/** Per-client-address limits in front of the account backoff (CM-T018). */
export interface AuthRateLimits {
  readonly register: FixedWindowLimiter;
  readonly login: FixedWindowLimiter;
  readonly mfa: FixedWindowLimiter;
  /** Password or code re-verification by an authenticated user (step-up, password change, MFA). */
  readonly reverify: FixedWindowLimiter;
}

export function defaultRateLimits(now: () => number = Date.now): AuthRateLimits {
  return {
    register: new FixedWindowLimiter(10, 60 * 60_000, 10_000, now),
    login: new FixedWindowLimiter(20, 10 * 60_000, 10_000, now),
    mfa: new FixedWindowLimiter(20, 10 * 60_000, 10_000, now),
    reverify: new FixedWindowLimiter(10, 15 * 60_000, 10_000, now),
  };
}

/** Window in which failures of an unknown identifier count toward its backoff. */
const UNKNOWN_IDENTIFIER_WINDOW_MS = 24 * 60 * 60_000;

const invalidCredentials = (): HttpError =>
  new HttpError(401, ErrorCode.INVALID_CREDENTIALS, 'The email address or password is incorrect');
const invalidCode = (): HttpError => new HttpError(401, ErrorCode.INVALID_CODE, 'The code is not valid');
const unauthenticated = (): HttpError => new HttpError(401, ErrorCode.UNAUTHENTICATED, 'Authentication required');
const rateLimited = (seconds: number): HttpError =>
  new HttpError(429, ErrorCode.RATE_LIMITED, 'Too many attempts. Try again later', undefined, {
    'retry-after': String(seconds),
  });
const busy = (): HttpError =>
  new HttpError(503, ErrorCode.SERVICE_UNAVAILABLE, 'Service busy. Try again shortly', undefined, {
    'retry-after': '1',
  });

/** The password hasher refuses work when its queue is full; that becomes a 503, not a crash. */
async function withHashing<T>(task: () => Promise<T>): Promise<T> {
  try {
    return await task();
  } catch (error) {
    if (error instanceof BusyError) throw busy();
    throw error;
  }
}

function limit(limiter: FixedWindowLimiter, key: string): void {
  const decision = limiter.consume(key);
  if (!decision.allowed) throw rateLimited(decision.retryAfterSeconds);
}

const addressKey = (meta: RequestMeta): string => meta.ip ?? 'unknown';

export type LoginOutcome =
  | { readonly kind: 'session'; readonly session: IssuedSession }
  | { readonly kind: 'mfa_required'; readonly preAuthToken: string; readonly maxAgeSeconds: number };

export function createAuthService(deps: AuthDependencies) {
  const { store, hasher, events, clock, limits } = deps;

  /** Records a failed password or code for an account and applies the progressive backoff. */
  async function accountFailure(userId: string, now: Date): Promise<void> {
    const failures = await store.recordPasswordFailure(userId);
    const delay = backoffSeconds(failures);
    if (delay > 0) await store.setThrottle(userId, new Date(now.getTime() + delay * 1000));
  }

  /** Verifies a TOTP code against the stored secret and consumes its time step (no replay). */
  async function checkTotp(userId: string, code: string, now: Date): Promise<boolean> {
    const state = await store.getMfaState(userId);
    if (state?.secretSealed == null || state.keyId === null) return false;
    const secret = deps.totpBox.open(userId, state.keyId, state.secretSealed);
    try {
      const step = verifyTotp(secret, code, now.getTime());
      return step !== undefined && (await store.claimTotpStep(userId, step));
    } finally {
      secret.fill(0);
    }
  }

  /** Password re-verification for an authenticated user (step-up, password change). */
  async function reverify(actor: Actor, password: string, code: string | undefined, now: Date): Promise<boolean> {
    limit(limits.reverify, actor.userId);
    const account = await store.findAccountById(actor.userId);
    const normalized = normalizePassword(password);
    if (account === null || normalized === undefined) return false;
    const { valid } = await withHashing(() => hasher.verify(normalized, account.passwordHash));
    if (!valid) return false;
    if (!account.mfaEnabled) return true;
    return code !== undefined && (await checkTotp(actor.userId, code, now));
  }

  async function startSession(
    tx: AuthStore,
    userId: string,
    authenticatedAt: Date,
    mfaVerifiedAt: Date | null,
    meta: RequestMeta,
    now: Date,
  ): Promise<IssuedSession> {
    await tx.recordLoginSuccess(userId, now);
    await tx.recordLoginAttempt({
      userId,
      identifierHmac: null,
      outcome: 'SUCCESS',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
      now,
    });
    return issueSession(tx, { userId, authenticatedAt, mfaVerifiedAt, meta, now });
  }

  return {
    // -------------------------------------------------------------------------- registration

    /** CM-T015. Creates the account only; no session, no keys (the vault is Phase 4). */
    async register(input: { email: string; displayName: string; password: string }, meta: RequestMeta) {
      limit(limits.register, addressKey(meta));
      const check = checkNewPassword(input.password, input);
      if (!check.ok) {
        throw new HttpError(
          400,
          ErrorCode.PASSWORD_REJECTED,
          'The password does not meet the policy',
          check.problems.map((code) => ({ path: 'password', code })),
        );
      }
      const passwordHash = await withHashing(() => hasher.hash(check.normalized));
      const now = clock();
      const created = await store.createUser({ ...input, passwordHash, now });
      if (created === 'EMAIL_TAKEN') {
        // Accepted residual risk: registration reveals that an address is taken (T-15, DF-01).
        throw new HttpError(409, ErrorCode.EMAIL_UNAVAILABLE, 'This email address cannot be used');
      }
      events.record({
        name: 'USER_REGISTERED',
        outcome: 'SUCCESS',
        targetUserId: created.id,
        requestId: meta.requestId,
      });
    },

    // ---------------------------------------------------------------------------------- login

    /** CM-T016 and DF-01. One generic error; unknown accounts cost the same Argon2id work. */
    async login(input: { email: string; password: string }, meta: RequestMeta): Promise<LoginOutcome> {
      limit(limits.login, addressKey(meta));
      const now = clock();
      const normalized = normalizePassword(input.password) ?? '';
      const account = await store.findLoginAccount(input.email);

      if (account === null) {
        const identifierHmac = deps.identifierHmac(input.email);
        const recent = await store.unknownIdentifierFailures(
          identifierHmac,
          new Date(now.getTime() - UNKNOWN_IDENTIFIER_WINDOW_MS),
        );
        const delay = backoffSeconds(recent.count);
        if (recent.last !== null && delay > 0 && recent.last.getTime() + delay * 1000 > now.getTime()) {
          // No login_attempts row for refused requests: they cost no Argon2id work, so writing a row
          // would let a distributed flood grow the table at network speed. The event is logged.
          events.record({ name: 'LOGIN_THROTTLED', outcome: 'DENIED', requestId: meta.requestId });
          throw rateLimited(Math.ceil((recent.last.getTime() + delay * 1000 - now.getTime()) / 1000));
        }
        await withHashing(() => hasher.verifyDummy(normalized));
        await store.recordLoginAttempt({
          userId: null,
          identifierHmac,
          outcome: 'BAD_CREDENTIALS',
          ...attemptMeta(meta, now),
        });
        events.record({
          name: 'LOGIN_FAILED',
          outcome: 'DENIED',
          requestId: meta.requestId,
          details: { reason: 'credentials' },
        });
        throw invalidCredentials();
      }

      if (account.throttledUntil !== null && account.throttledUntil > now) {
        // As above: refused without a database write, so writes stay bounded by Argon2id throughput.
        events.record({
          name: 'LOGIN_THROTTLED',
          outcome: 'DENIED',
          targetUserId: account.id,
          requestId: meta.requestId,
        });
        throw rateLimited(Math.ceil((account.throttledUntil.getTime() - now.getTime()) / 1000));
      }

      const { valid, needsRehash } = await withHashing(() => hasher.verify(normalized, account.passwordHash));
      if (!valid) {
        await accountFailure(account.id, now);
        await store.recordLoginAttempt({
          userId: account.id,
          identifierHmac: null,
          outcome: 'BAD_CREDENTIALS',
          ...attemptMeta(meta, now),
        });
        events.record({
          name: 'LOGIN_FAILED',
          outcome: 'DENIED',
          targetUserId: account.id,
          requestId: meta.requestId,
          details: { reason: 'credentials' },
        });
        throw invalidCredentials();
      }

      if (account.status !== 'ACTIVE') {
        // The same answer as a wrong password: account state is not disclosed (section 9).
        await store.recordLoginAttempt({
          userId: account.id,
          identifierHmac: null,
          outcome: 'DISABLED',
          ...attemptMeta(meta, now),
        });
        events.record({
          name: 'LOGIN_FAILED',
          outcome: 'DENIED',
          targetUserId: account.id,
          requestId: meta.requestId,
          details: { reason: 'disabled' },
        });
        throw invalidCredentials();
      }

      if (needsRehash) {
        // CP-05: upgrade stored hashes to the current parameters at the next successful login.
        await store.updatePasswordHash(account.id, await withHashing(() => hasher.hash(normalized)), null);
      }

      if (account.mfaEnabled) {
        // No session yet: only a short-lived, single-use pre-authentication state (DF-01).
        const { token, digest } = issueToken();
        await store.createChallenge({
          userId: account.id,
          tokenDigest: digest,
          now,
          expiresAt: new Date(now.getTime() + SESSION_POLICY.preAuthMs),
        });
        return { kind: 'mfa_required', preAuthToken: token, maxAgeSeconds: SESSION_POLICY.preAuthMs / 1000 };
      }

      const session = await deps.transaction((tx) => startSession(tx, account.id, now, null, meta, now));
      events.record({
        name: 'LOGIN_SUCCEEDED',
        outcome: 'SUCCESS',
        actorUserId: account.id,
        requestId: meta.requestId,
        details: { mfa: false },
      });
      if (session.evicted > 0) {
        events.record({
          name: 'SESSION_EVICTED',
          outcome: 'SUCCESS',
          actorUserId: account.id,
          requestId: meta.requestId,
          details: { count: session.evicted },
        });
      }
      return { kind: 'session', session };
    },

    /**
     * Completes a login that requires MFA, with a TOTP code or a recovery code (DF-01, CM-T019).
     * The pre-authentication state allows at most five attempts and is consumed by success.
     */
    async completeMfa(
      preAuthToken: string | undefined,
      factor: { kind: 'totp'; code: string } | { kind: 'recovery'; code: string },
      meta: RequestMeta,
    ): Promise<{ session: IssuedSession; recoveryCodesRemaining?: number }> {
      limit(limits.mfa, addressKey(meta));
      const now = clock();
      if (preAuthToken === undefined || !isWellFormedToken(preAuthToken)) throw unauthenticated();
      const challenge = await store.findChallenge(digestToken(preAuthToken));
      if (challenge === null || challenge.consumedAt !== null || challenge.expiresAt <= now) throw unauthenticated();

      const account = await store.findAccountById(challenge.userId);
      if (account?.status !== 'ACTIVE' || !account.mfaEnabled) throw unauthenticated();
      if (account.throttledUntil !== null && account.throttledUntil > now) {
        throw rateLimited(Math.ceil((account.throttledUntil.getTime() - now.getTime()) / 1000));
      }
      if (!(await store.spendChallengeAttempt(challenge.id, now, SESSION_POLICY.preAuthAttempts))) {
        throw unauthenticated();
      }

      const canonical = factor.kind === 'recovery' ? canonicalRecoveryCode(factor.code) : undefined;
      const accepted =
        factor.kind === 'totp'
          ? await checkTotp(account.id, factor.code, now)
          : canonical !== undefined &&
            (await store.consumeRecoveryCode(account.id, recoveryCodeDigest(canonical), now));
      if (!accepted) {
        await accountFailure(account.id, now);
        await store.recordLoginAttempt({
          userId: account.id,
          identifierHmac: null,
          outcome: 'MFA_FAILED',
          ...attemptMeta(meta, now),
        });
        events.record({
          name: 'MFA_CHALLENGE_FAILED',
          outcome: 'DENIED',
          targetUserId: account.id,
          requestId: meta.requestId,
          details: { factor: factor.kind },
        });
        throw invalidCode();
      }

      const result = await deps.transaction(async (tx) => {
        // Single use: a concurrent completion of the same state loses here.
        if (!(await tx.consumeChallenge(challenge.id, now))) throw unauthenticated();
        const session = await startSession(tx, account.id, challenge.createdAt, now, meta, now);
        // session-and-csrf.md section 4: a recovery-code login revokes the other sessions.
        const revoked =
          factor.kind === 'recovery'
            ? await tx.revokeUserSessions(account.id, 'RECOVERY_CODE_USED', now, session.sessionId)
            : 0;
        const remaining = factor.kind === 'recovery' ? await tx.unusedRecoveryCodeCount(account.id) : undefined;
        return { session, revoked, remaining };
      });

      events.record({
        name: 'LOGIN_SUCCEEDED',
        outcome: 'SUCCESS',
        actorUserId: account.id,
        requestId: meta.requestId,
        details: { mfa: true, factor: factor.kind },
      });
      if (factor.kind === 'recovery') {
        events.record({
          name: 'RECOVERY_CODE_USED',
          outcome: 'SUCCESS',
          actorUserId: account.id,
          requestId: meta.requestId,
          details: { remaining: result.remaining ?? 0, sessionsRevoked: result.revoked },
        });
      }
      return result.remaining === undefined
        ? { session: result.session }
        : { session: result.session, recoveryCodesRemaining: result.remaining };
    },

    // ------------------------------------------------------------------------------- sessions

    async logout(actor: Actor, meta: RequestMeta): Promise<void> {
      await store.revokeSession(actor.sessionId, actor.userId, 'LOGOUT', clock());
      events.record({ name: 'LOGOUT', outcome: 'SUCCESS', actorUserId: actor.userId, requestId: meta.requestId });
    },

    async listSessions(actor: Actor) {
      const sessions = await store.listActiveSessions(actor.userId, clock());
      return sessions.map((s) => ({ ...s, current: s.id === actor.sessionId }));
    },

    /** Revokes one of the caller's own sessions; another user's session ID behaves as unknown. */
    async revokeSession(actor: Actor, sessionId: string, meta: RequestMeta): Promise<{ current: boolean }> {
      const count = await store.revokeSession(sessionId, actor.userId, 'REVOKED_BY_USER', clock());
      if (count === 0) throw new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
      events.record({
        name: 'SESSION_REVOKED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
      });
      return { current: sessionId === actor.sessionId };
    },

    async revokeOtherSessions(actor: Actor, meta: RequestMeta): Promise<void> {
      const count = await store.revokeUserSessions(actor.userId, 'REVOKED_BY_USER', clock(), actor.sessionId);
      events.record({
        name: 'SESSIONS_REVOKED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { count },
      });
    },

    // --------------------------------------------------------------------------------- step-up

    /** CM-T021: password, plus a TOTP code when MFA is enabled. Rotates the session token. */
    async stepUp(actor: Actor, input: { password: string; code?: string | undefined }, meta: RequestMeta) {
      const now = clock();
      if (!(await reverify(actor, input.password, input.code, now))) {
        events.record({
          name: 'STEP_UP_FAILED',
          outcome: 'DENIED',
          actorUserId: actor.userId,
          requestId: meta.requestId,
        });
        throw invalidCredentials();
      }
      const rotated = await rotateSession(store, actor, now, { stepUpAt: now });
      if (rotated === undefined) throw unauthenticated();
      events.record({
        name: 'STEP_UP_COMPLETED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
      });
      return { session: rotated, stepUpAt: now };
    },

    // ---------------------------------------------------------------------------- password change

    /** session-and-csrf.md section 7: rotates this session and revokes all others. */
    async changePassword(
      actor: Actor,
      input: { currentPassword: string; newPassword: string; code?: string | undefined },
      meta: RequestMeta,
    ): Promise<IssuedSession> {
      const now = clock();
      if (!(await reverify(actor, input.currentPassword, input.code, now))) throw invalidCredentials();
      const check = checkNewPassword(input.newPassword, {
        email: actor.user.email,
        displayName: actor.user.displayName,
      });
      if (!check.ok) {
        throw new HttpError(
          400,
          ErrorCode.PASSWORD_REJECTED,
          'The password does not meet the policy',
          check.problems.map((code) => ({ path: 'newPassword', code })),
        );
      }
      const passwordHash = await withHashing(() => hasher.hash(check.normalized));
      const result = await deps.transaction(async (tx) => {
        await tx.updatePasswordHash(actor.userId, passwordHash, now);
        const revoked = await tx.revokeUserSessions(actor.userId, 'PASSWORD_CHANGED', now, actor.sessionId);
        const rotated = await rotateSession(tx, actor, now, { authenticatedAt: now });
        if (rotated === undefined) throw unauthenticated();
        return { rotated, revoked };
      });
      events.record({
        name: 'PASSWORD_CHANGED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { sessionsRevoked: result.revoked },
      });
      return result.rotated;
    },

    // ------------------------------------------------------------------------------------- MFA

    /** DF-02 step 1. Requires a recent step-up (route gate). Nothing is enabled yet. */
    async startTotpEnrollment(actor: Actor, meta: RequestMeta): Promise<{ uri: string; base32: string }> {
      const secret = generateTotpSecret();
      try {
        const sealed = deps.totpBox.seal(actor.userId, secret);
        if (!(await store.setPendingTotp(actor.userId, sealed, deps.totpBox.keyId))) {
          throw new HttpError(409, ErrorCode.MFA_STATE_CONFLICT, 'Multi-factor authentication is already enabled');
        }
        events.record({
          name: 'MFA_ENROLLMENT_STARTED',
          outcome: 'SUCCESS',
          actorUserId: actor.userId,
          requestId: meta.requestId,
        });
        return totpEnrollment(secret, actor.user.email);
      } finally {
        secret.fill(0);
      }
    },

    /**
     * DF-02 step 2: MFA becomes active only after a valid code proves the authenticator holds the
     * secret. Issues ten recovery codes, rotates this session and revokes the others.
     */
    async confirmTotpEnrollment(actor: Actor, code: string, meta: RequestMeta) {
      limit(limits.reverify, actor.userId);
      const now = clock();
      const state = await store.getMfaState(actor.userId);
      if (state === null || state.mfaEnabled || state.secretSealed === null) {
        throw new HttpError(409, ErrorCode.MFA_STATE_CONFLICT, 'No enrollment is pending');
      }
      if (!(await checkTotp(actor.userId, code, now))) throw invalidCode();
      const recovery = generateRecoveryCodes();
      const result = await deps.transaction(async (tx) => {
        if (!(await tx.enableMfa(actor.userId, recovery.digests, now))) {
          throw new HttpError(409, ErrorCode.MFA_STATE_CONFLICT, 'No enrollment is pending');
        }
        const revoked = await tx.revokeUserSessions(actor.userId, 'MFA_CHANGED', now, actor.sessionId);
        const rotated = await rotateSession(tx, actor, now, { mfaVerifiedAt: now });
        if (rotated === undefined) throw unauthenticated();
        return { rotated, revoked };
      });
      events.record({
        name: 'MFA_ENABLED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { sessionsRevoked: result.revoked },
      });
      return { session: result.rotated, recoveryCodes: recovery.codes };
    },

    /** Requires a recent step-up (route gate). Platform administrators must keep MFA. */
    async disableTotp(actor: Actor, meta: RequestMeta): Promise<IssuedSession> {
      if (actor.user.platformRole === 'PLATFORM_ADMIN') {
        throw new HttpError(403, ErrorCode.FORBIDDEN, 'Platform administrators must keep multi-factor authentication');
      }
      const now = clock();
      const result = await deps.transaction(async (tx) => {
        if (!(await tx.disableMfa(actor.userId))) {
          throw new HttpError(409, ErrorCode.MFA_STATE_CONFLICT, 'Multi-factor authentication is not enabled');
        }
        const revoked = await tx.revokeUserSessions(actor.userId, 'MFA_CHANGED', now, actor.sessionId);
        const rotated = await rotateSession(tx, actor, now);
        if (rotated === undefined) throw unauthenticated();
        return { rotated, revoked };
      });
      events.record({
        name: 'MFA_DISABLED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { sessionsRevoked: result.revoked },
      });
      return result.rotated;
    },

    /** Requires a recent step-up (route gate). All previous codes stop working. */
    async regenerateRecoveryCodes(actor: Actor, meta: RequestMeta): Promise<string[]> {
      const state = await store.getMfaState(actor.userId);
      if (state?.mfaEnabled !== true) {
        throw new HttpError(409, ErrorCode.MFA_STATE_CONFLICT, 'Multi-factor authentication is not enabled');
      }
      const recovery = generateRecoveryCodes();
      await deps.transaction((tx) => tx.replaceRecoveryCodes(actor.userId, recovery.digests, clock()));
      events.record({
        name: 'RECOVERY_CODES_REGENERATED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
      });
      return recovery.codes;
    },
  };
}

function attemptMeta(meta: RequestMeta, now: Date) {
  return { ipAddress: meta.ip, userAgent: meta.userAgent, now };
}

export type AuthService = ReturnType<typeof createAuthService>;
