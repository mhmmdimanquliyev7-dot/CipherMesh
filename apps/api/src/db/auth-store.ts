import { Prisma, type PrismaClient } from '../generated/prisma/client';
import type { SessionRevokeReason } from '../generated/prisma/enums';

/**
 * Data access for authentication (Phase 3). The only module that touches the users, sessions,
 * auth_challenges, login_attempts and recovery_codes tables. Every one-time operation (recovery
 * code use, TOTP time step, challenge attempt, challenge consumption, session rotation) is a single
 * conditional UPDATE whose row count decides the outcome, so concurrent requests cannot both win.
 * Results are explicit projections: callers never receive a whole Prisma row.
 */
type Db = PrismaClient | Prisma.TransactionClient;

export type { SessionRevokeReason };

export interface LoginAccount {
  readonly id: string;
  readonly passwordHash: string;
  readonly status: 'ACTIVE' | 'DISABLED';
  readonly mfaEnabled: boolean;
  readonly failedLoginCount: number;
  readonly throttledUntil: Date | null;
}

export interface SessionUser {
  readonly id: string;
  readonly email: string;
  readonly displayName: string;
  readonly status: 'ACTIVE' | 'DISABLED';
  readonly platformRole: 'USER' | 'PLATFORM_ADMIN';
  readonly mfaEnabled: boolean;
}

export interface SessionRecord {
  readonly id: string;
  readonly userId: string;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly idleExpiresAt: Date;
  readonly absoluteExpiresAt: Date;
  readonly authenticatedAt: Date;
  readonly mfaVerifiedAt: Date | null;
  readonly stepUpAt: Date | null;
  readonly revokedAt: Date | null;
  readonly user: SessionUser;
}

export interface NewSession {
  readonly userId: string;
  readonly tokenDigest: Buffer;
  readonly now: Date;
  readonly idleExpiresAt: Date;
  readonly absoluteExpiresAt: Date;
  readonly authenticatedAt: Date;
  readonly mfaVerifiedAt: Date | null;
  readonly ipAddress: string | null;
  readonly userAgent: string | null;
}

export interface ChallengeRecord {
  readonly id: string;
  readonly userId: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly attempts: number;
  readonly consumedAt: Date | null;
}

export interface MfaState {
  readonly mfaEnabled: boolean;
  readonly secretSealed: Uint8Array | null;
  readonly keyId: string | null;
}

const sessionSelect = {
  id: true,
  userId: true,
  createdAt: true,
  lastSeenAt: true,
  idleExpiresAt: true,
  absoluteExpiresAt: true,
  authenticatedAt: true,
  mfaVerifiedAt: true,
  stepUpAt: true,
  revokedAt: true,
  user: { select: { id: true, email: true, displayName: true, status: true, platformRole: true, mfaEnabled: true } },
} as const;

const activeSessionWhere = (userId: string, now: Date): Prisma.SessionWhereInput => ({
  userId,
  revokedAt: null,
  idleExpiresAt: { gt: now },
  absoluteExpiresAt: { gt: now },
});

export function createAuthStore(db: Db) {
  return {
    // ---------------------------------------------------------------------------------- accounts

    /** Inserts the account. A concurrent duplicate loses on the unique index, not on a pre-check. */
    async createUser(input: {
      email: string;
      displayName: string;
      passwordHash: string;
      now: Date;
    }): Promise<{ id: string } | 'EMAIL_TAKEN'> {
      try {
        return await db.user.create({
          data: {
            email: input.email,
            displayName: input.displayName,
            passwordHash: input.passwordHash,
            passwordChangedAt: input.now,
            createdAt: input.now,
            updatedAt: input.now,
          },
          select: { id: true },
        });
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') return 'EMAIL_TAKEN';
        throw error;
      }
    },

    async findLoginAccount(email: string): Promise<LoginAccount | null> {
      return db.user.findUnique({
        where: { email },
        select: {
          id: true,
          passwordHash: true,
          status: true,
          mfaEnabled: true,
          failedLoginCount: true,
          throttledUntil: true,
        },
      });
    },

    async findAccountById(userId: string): Promise<(LoginAccount & { email: string; displayName: string }) | null> {
      return db.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          email: true,
          displayName: true,
          passwordHash: true,
          status: true,
          mfaEnabled: true,
          failedLoginCount: true,
          throttledUntil: true,
        },
      });
    },

    /** Increments the consecutive-failure count and returns the new value. */
    async recordPasswordFailure(userId: string): Promise<number> {
      const row = await db.user.update({
        where: { id: userId },
        data: { failedLoginCount: { increment: 1 } },
        select: { failedLoginCount: true },
      });
      return row.failedLoginCount;
    },

    async setThrottle(userId: string, until: Date | null): Promise<void> {
      await db.user.update({ where: { id: userId }, data: { throttledUntil: until } });
    },

    async recordLoginSuccess(userId: string, now: Date): Promise<void> {
      await db.user.update({
        where: { id: userId },
        data: { failedLoginCount: 0, throttledUntil: null, lastLoginAt: now },
      });
    },

    async updatePasswordHash(userId: string, passwordHash: string, changedAt: Date | null): Promise<void> {
      await db.user.update({
        where: { id: userId },
        data: changedAt === null ? { passwordHash } : { passwordHash, passwordChangedAt: changedAt },
      });
    },

    // ---------------------------------------------------------------------------- login attempts

    async recordLoginAttempt(entry: {
      userId: string | null;
      identifierHmac: Buffer | null;
      outcome: 'SUCCESS' | 'BAD_CREDENTIALS' | 'MFA_FAILED' | 'THROTTLED' | 'DISABLED';
      ipAddress: string | null;
      userAgent: string | null;
      now: Date;
    }): Promise<void> {
      await db.loginAttempt.create({
        data: {
          userId: entry.userId,
          identifierHmac: entry.identifierHmac === null ? null : new Uint8Array(entry.identifierHmac),
          outcome: entry.outcome,
          ipAddress: entry.ipAddress,
          userAgent: entry.userAgent,
          occurredAt: entry.now,
        },
      });
    },

    /** Failures for an unknown identifier within the window, and the latest one. */
    async unknownIdentifierFailures(
      identifierHmac: Buffer,
      since: Date,
    ): Promise<{ count: number; last: Date | null }> {
      const where = {
        identifierHmac: new Uint8Array(identifierHmac),
        occurredAt: { gte: since },
        outcome: { in: ['BAD_CREDENTIALS' as const] },
      };
      const [count, last] = await Promise.all([
        db.loginAttempt.count({ where }),
        db.loginAttempt.findFirst({ where, orderBy: { occurredAt: 'desc' }, select: { occurredAt: true } }),
      ]);
      return { count, last: last?.occurredAt ?? null };
    },

    // ---------------------------------------------------------------------------------- sessions

    /**
     * Creates a session and enforces the per-user limit (CP-08) under a row lock on the user, so
     * concurrent logins cannot exceed it. Returns how many least-recently-used sessions were evicted.
     */
    async createSession(input: NewSession, maxActive: number): Promise<{ id: string; evicted: number }> {
      await db.$queryRaw`SELECT id FROM users WHERE id = ${input.userId}::uuid FOR UPDATE`;
      const active = await db.session.findMany({
        where: activeSessionWhere(input.userId, input.now),
        orderBy: { lastSeenAt: 'asc' },
        select: { id: true },
      });
      const excess = active.length - (maxActive - 1);
      const evict = excess > 0 ? active.slice(0, excess).map((s) => s.id) : [];
      if (evict.length > 0) {
        await db.session.updateMany({
          where: { id: { in: evict }, revokedAt: null },
          data: { revokedAt: input.now, revokeReason: 'SESSION_LIMIT' },
        });
      }
      const created = await db.session.create({
        data: {
          userId: input.userId,
          tokenDigest: new Uint8Array(input.tokenDigest),
          createdAt: input.now,
          lastSeenAt: input.now,
          idleExpiresAt: input.idleExpiresAt,
          absoluteExpiresAt: input.absoluteExpiresAt,
          authenticatedAt: input.authenticatedAt,
          mfaVerifiedAt: input.mfaVerifiedAt,
          ipAddress: input.ipAddress,
          userAgent: input.userAgent,
        },
        select: { id: true },
      });
      return { id: created.id, evicted: evict.length };
    },

    async findSessionByDigest(tokenDigest: Buffer): Promise<SessionRecord | null> {
      return db.session.findUnique({ where: { tokenDigest: new Uint8Array(tokenDigest) }, select: sessionSelect });
    },

    /** Records activity; at most once a minute per session (session-and-csrf.md section 3). */
    async touchSession(sessionId: string, now: Date, idleExpiresAt: Date): Promise<void> {
      await db.session.updateMany({
        where: { id: sessionId, revokedAt: null },
        data: { lastSeenAt: now, idleExpiresAt },
      });
    },

    /** Replaces the token digest. Fails if the session was revoked meanwhile. */
    async rotateSession(
      sessionId: string,
      newDigest: Buffer,
      now: Date,
      changes: { stepUpAt?: Date; mfaVerifiedAt?: Date; authenticatedAt?: Date; idleExpiresAt: Date },
    ): Promise<boolean> {
      const result = await db.session.updateMany({
        where: { id: sessionId, revokedAt: null },
        data: { tokenDigest: new Uint8Array(newDigest), rotatedAt: now, lastSeenAt: now, ...changes },
      });
      return result.count === 1;
    },

    async revokeSession(sessionId: string, userId: string, reason: SessionRevokeReason, now: Date): Promise<number> {
      const result = await db.session.updateMany({
        where: { id: sessionId, userId, revokedAt: null },
        data: { revokedAt: now, revokeReason: reason },
      });
      return result.count;
    },

    /** Revokes every unrevoked session of the user, optionally keeping one. Returns the count. */
    async revokeUserSessions(
      userId: string,
      reason: SessionRevokeReason,
      now: Date,
      exceptSessionId?: string,
    ): Promise<number> {
      const result = await db.session.updateMany({
        where: { userId, revokedAt: null, ...(exceptSessionId === undefined ? {} : { id: { not: exceptSessionId } }) },
        data: { revokedAt: now, revokeReason: reason },
      });
      return result.count;
    },

    async listActiveSessions(userId: string, now: Date) {
      return db.session.findMany({
        where: activeSessionWhere(userId, now),
        orderBy: { lastSeenAt: 'desc' },
        select: { id: true, createdAt: true, lastSeenAt: true, userAgent: true, ipAddress: true },
      });
    },

    // ------------------------------------------------------------------- pre-authentication state

    async createChallenge(input: { userId: string; tokenDigest: Buffer; now: Date; expiresAt: Date }): Promise<void> {
      await db.authChallenge.create({
        data: {
          userId: input.userId,
          tokenDigest: new Uint8Array(input.tokenDigest),
          purpose: 'LOGIN_MFA',
          createdAt: input.now,
          expiresAt: input.expiresAt,
        },
      });
    },

    async findChallenge(tokenDigest: Buffer): Promise<ChallengeRecord | null> {
      return db.authChallenge.findUnique({
        where: { tokenDigest: new Uint8Array(tokenDigest) },
        select: { id: true, userId: true, createdAt: true, expiresAt: true, attempts: true, consumedAt: true },
      });
    },

    /** Spends one of the five attempts atomically. False when none is left or the state is dead. */
    async spendChallengeAttempt(challengeId: string, now: Date, maxAttempts: number): Promise<boolean> {
      const result = await db.authChallenge.updateMany({
        where: { id: challengeId, consumedAt: null, expiresAt: { gt: now }, attempts: { lt: maxAttempts } },
        data: { attempts: { increment: 1 } },
      });
      return result.count === 1;
    },

    /** Single use: only one caller can consume the challenge. */
    async consumeChallenge(challengeId: string, now: Date): Promise<boolean> {
      const result = await db.authChallenge.updateMany({
        where: { id: challengeId, consumedAt: null, expiresAt: { gt: now } },
        data: { consumedAt: now },
      });
      return result.count === 1;
    },

    // ----------------------------------------------------------------------------------------- MFA

    async getMfaState(userId: string): Promise<MfaState | null> {
      const row = await db.user.findUnique({
        where: { id: userId },
        select: { mfaEnabled: true, mfaTotpSecretEnc: true, mfaTotpKeyId: true },
      });
      return row === null
        ? null
        : { mfaEnabled: row.mfaEnabled, secretSealed: row.mfaTotpSecretEnc, keyId: row.mfaTotpKeyId };
    },

    /** Stores a pending (not yet confirmed) secret. Refused while MFA is enabled. */
    async setPendingTotp(userId: string, sealed: Buffer, keyId: string): Promise<boolean> {
      const result = await db.user.updateMany({
        where: { id: userId, mfaEnabled: false },
        data: { mfaTotpSecretEnc: new Uint8Array(sealed), mfaTotpKeyId: keyId, mfaLastUsedStep: null },
      });
      return result.count === 1;
    },

    /** Replay protection: accepts each TOTP time step at most once per account. */
    async claimTotpStep(userId: string, step: number): Promise<boolean> {
      const result = await db.user.updateMany({
        where: { id: userId, OR: [{ mfaLastUsedStep: null }, { mfaLastUsedStep: { lt: BigInt(step) } }] },
        data: { mfaLastUsedStep: BigInt(step) },
      });
      return result.count === 1;
    },

    /** Turns MFA on (only from the pending state) and stores fresh recovery-code digests. */
    async enableMfa(userId: string, recoveryDigests: readonly Buffer[], now: Date): Promise<boolean> {
      const result = await db.user.updateMany({
        where: { id: userId, mfaEnabled: false, mfaTotpSecretEnc: { not: null } },
        data: { mfaEnabled: true },
      });
      if (result.count !== 1) return false;
      await replaceCodes(db, userId, recoveryDigests, now);
      return true;
    },

    async disableMfa(userId: string): Promise<boolean> {
      const result = await db.user.updateMany({
        where: { id: userId, mfaEnabled: true },
        data: { mfaEnabled: false, mfaTotpSecretEnc: null, mfaTotpKeyId: null, mfaLastUsedStep: null },
      });
      await db.recoveryCode.deleteMany({ where: { userId } });
      return result.count === 1;
    },

    async replaceRecoveryCodes(userId: string, digests: readonly Buffer[], now: Date): Promise<void> {
      await replaceCodes(db, userId, digests, now);
    },

    /** Marks one unused code as used. Exactly one concurrent caller can succeed. */
    async consumeRecoveryCode(userId: string, digest: Buffer, now: Date): Promise<boolean> {
      const result = await db.recoveryCode.updateMany({
        where: { userId, codeDigest: new Uint8Array(digest), usedAt: null },
        data: { usedAt: now },
      });
      return result.count === 1;
    },

    async unusedRecoveryCodeCount(userId: string): Promise<number> {
      return db.recoveryCode.count({ where: { userId, usedAt: null } });
    },

    // ------------------------------------------------------------------------------ administration

    async findUserStatus(
      userId: string,
    ): Promise<{ id: string; status: 'ACTIVE' | 'DISABLED'; platformRole: 'USER' | 'PLATFORM_ADMIN' } | null> {
      return db.user.findUnique({ where: { id: userId }, select: { id: true, status: true, platformRole: true } });
    },

    async findUserByEmail(email: string): Promise<{ id: string; mfaEnabled: boolean; platformRole: string } | null> {
      return db.user.findUnique({ where: { email }, select: { id: true, mfaEnabled: true, platformRole: true } });
    },

    async setUserStatus(userId: string, status: 'ACTIVE' | 'DISABLED'): Promise<boolean> {
      const result = await db.user.updateMany({ where: { id: userId, status: { not: status } }, data: { status } });
      return result.count === 1;
    },

    async setPlatformRole(userId: string, role: 'USER' | 'PLATFORM_ADMIN'): Promise<boolean> {
      const result = await db.user.updateMany({
        where: { id: userId, platformRole: { not: role } },
        data: { platformRole: role },
      });
      return result.count === 1;
    },

    /** Active platform administrators, counted under a lock so two admins cannot disable each other. */
    async lockActiveAdmins(): Promise<string[]> {
      const rows = await db.$queryRaw<{ id: string }[]>`
        SELECT id FROM users WHERE platform_role = 'PLATFORM_ADMIN' AND status = 'ACTIVE' FOR UPDATE`;
      return rows.map((row) => row.id);
    },
  };
}

async function replaceCodes(db: Db, userId: string, digests: readonly Buffer[], now: Date): Promise<void> {
  await db.recoveryCode.deleteMany({ where: { userId } });
  await db.recoveryCode.createMany({
    data: digests.map((digest) => ({ userId, codeDigest: new Uint8Array(digest), createdAt: now })),
  });
}

export type AuthStore = ReturnType<typeof createAuthStore>;

/** Runs `fn` with a store bound to one database transaction. */
export async function inAuthTransaction<T>(prisma: PrismaClient, fn: (store: AuthStore) => Promise<T>): Promise<T> {
  return prisma.$transaction((tx) => fn(createAuthStore(tx)), { isolationLevel: 'ReadCommitted' });
}

/** The store and a transaction runner for the authentication services (no Prisma outside db/). */
export function authDataAccess(prisma: PrismaClient): {
  store: AuthStore;
  transaction: <T>(fn: (store: AuthStore) => Promise<T>) => Promise<T>;
} {
  return { store: createAuthStore(prisma), transaction: (fn) => inAuthTransaction(prisma, fn) };
}
