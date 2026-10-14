import type { Prisma, PrismaClient } from '../generated/prisma/client';

/**
 * Aggregate queries of the platform security dashboard (Phase 14, CM-T061, CM-T062;
 * docs/architecture/security-dashboard.md). Every query is a COUNT or a SUM over metadata columns,
 * or reads the oldest lock time of a locked room: none selects a room name, a user, content,
 * ciphertext or a key column, and no result carries an identifier. The API role already reads these tables for its own routes; no grant
 * changes. Values are computed on request (the design allows a cache of at most 60 seconds; there
 * is none).
 */

const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;

const ROTATION_REASONS = [
  'MEMBER_REMOVED',
  'MEMBER_LEFT',
  'MEMBER_SUSPENDED',
  'MEMBER_DELETED',
  'IDENTITY_KEY_COMPROMISED',
  'CRYPTOPERIOD_EXPIRED',
  'WRAP_LIMIT_REACHED',
  'MANUAL',
  'POLICY_CHANGE',
] as const;

const PROFILES = ['STANDARD', 'CONFIDENTIAL', 'RESTRICTED'] as const;

export type MetricValues = Readonly<Record<string, number>>;

/** Values per AVAILABLE metric ID (SD-xx), keyed as in the shared catalogue. */
export type DashboardAggregates = Readonly<Record<string, MetricValues>>;

export interface DashboardStore {
  aggregates(now: Date): Promise<DashboardAggregates>;
}

export function createDashboardStore(prisma: PrismaClient): DashboardStore {
  return {
    async aggregates(now) {
      const at = now.getTime();
      const since = (ms: number): Date => new Date(at - ms);
      const until = (ms: number): Date => new Date(at + ms);
      const activeUser = { status: 'ACTIVE', deletedAt: null } satisfies Prisma.UserWhereInput;
      const lockedRoom: Prisma.RoomWhereInput = { status: 'ACTIVE', keyState: { in: ['REKEY_REQUIRED', 'REKEYING'] } };
      const rotation: Prisma.RoomKeyVersionWhereInput = {
        createdAt: { gte: since(30 * DAY) },
        NOT: { reasons: { has: 'INITIAL' } },
      };

      const [
        files,
        rooms,
        profiles,
        secrets24h,
        secrets7d,
        failed24h,
        failed7d,
        sources,
        throttled,
        activeUsers,
        withMfa,
        blockedMembers,
        rotations,
        rotationReasons,
        lockedRooms,
        oldestLock,
        abandoned7d,
        sessions,
        withVault,
        pendingApproval,
      ] = await Promise.all([
        prisma.encryptedFile.aggregate({
          where: { status: 'AVAILABLE' },
          _count: { _all: true },
          _sum: { ciphertextSize: true },
        }),
        prisma.room.count({ where: { status: 'ACTIVE' } }),
        prisma.room.groupBy({ by: ['securityProfile'], where: { status: 'ACTIVE' }, _count: { _all: true } }),
        prisma.secret.count({ where: { status: 'ACTIVE', expiresAt: { gt: now, lte: until(DAY) } } }),
        prisma.secret.count({ where: { status: 'ACTIVE', expiresAt: { gt: now, lte: until(7 * DAY) } } }),
        prisma.loginAttempt.count({ where: { outcome: { not: 'SUCCESS' }, occurredAt: { gte: since(DAY) } } }),
        prisma.loginAttempt.count({ where: { outcome: { not: 'SUCCESS' }, occurredAt: { gte: since(7 * DAY) } } }),
        // Reviewed raw SQL: a parameterized tagged template; COUNT(DISTINCT) avoids loading addresses.
        prisma.$queryRaw<{ n: number }[]>`
          SELECT count(DISTINCT ip_address)::int AS n
          FROM login_attempts
          WHERE outcome <> 'SUCCESS' AND occurred_at >= ${since(7 * DAY)}`,
        prisma.user.count({ where: { ...activeUser, throttledUntil: { gt: now } } }),
        prisma.user.count({ where: activeUser }),
        prisma.user.count({ where: { ...activeUser, mfaEnabled: true } }),
        prisma.user.count({
          where: {
            ...activeUser,
            mfaEnabled: false,
            memberships: {
              some: {
                status: 'ACTIVE',
                room: { status: 'ACTIVE', securityProfile: { in: ['CONFIDENTIAL', 'RESTRICTED'] } },
              },
            },
          },
        }),
        prisma.roomKeyVersion.count({ where: rotation }),
        Promise.all(
          ROTATION_REASONS.map((reason) =>
            prisma.roomKeyVersion.count({ where: { ...rotation, reasons: { has: reason } } }),
          ),
        ),
        prisma.room.count({ where: lockedRoom }),
        prisma.room.findFirst({
          where: { AND: [lockedRoom, { rekeyRequiredSince: { not: null } }] },
          orderBy: { rekeyRequiredSince: 'asc' },
          select: { rekeyRequiredSince: true },
        }),
        prisma.rekeyOperation.count({ where: { status: 'ABANDONED', closedAt: { gte: since(7 * DAY) } } }),
        prisma.session.count({
          where: { revokedAt: null, idleExpiresAt: { gt: now }, absoluteExpiresAt: { gt: now } },
        }),
        prisma.user.count({ where: { ...activeUser, keyPairs: { some: { status: 'ACTIVE' } } } }),
        prisma.invitation.count({ where: { status: 'PENDING_APPROVAL' } }),
      ]);

      const oldest = oldestLock?.rekeyRequiredSince ?? null;
      return {
        'SD-01': { files: files._count._all, ciphertextBytes: Number(files._sum.ciphertextSize ?? 0n) },
        'SD-02': { rooms },
        'SD-03': Object.fromEntries(
          PROFILES.map((profile) => [
            profile,
            profiles.find((row) => row.securityProfile === profile)?._count._all ?? 0,
          ]),
        ),
        'SD-04': { within24h: secrets24h, within7d: secrets7d },
        'SD-05': {
          failed24h,
          failed7d,
          sources7d: sources[0]?.n ?? 0,
          throttledAccounts: throttled,
        },
        'SD-06': { withMfa, activeUsers, blockedMembers },
        'SD-07': {
          total: rotations,
          ...Object.fromEntries(ROTATION_REASONS.map((reason, index) => [reason, rotationReasons[index] ?? 0])),
        },
        'SD-08': {
          lockedRooms,
          oldestLockHours: oldest === null ? 0 : Math.max(0, Math.floor((at - oldest.getTime()) / HOUR)),
          abandoned7d,
        },
        'SD-09': { sessions },
        'SD-13': { withVault, activeUsers },
        'SD-14': { pendingApproval },
      };
    },
  };
}
