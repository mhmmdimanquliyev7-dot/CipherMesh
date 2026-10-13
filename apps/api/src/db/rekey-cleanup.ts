import { resolveRoomPolicy, REKEY_RULES } from '@ciphermesh/shared';
import type { PrismaClient } from '../generated/prisma/client';
import type { RoomKeyState, SecurityProfile } from '../generated/prisma/enums';

/**
 * Rekey maintenance, run by the worker as cm_worker (Phase 11, CM-T050, CM-T052; ADR-013 step 6,
 * key-lifecycle 1.3, 1.5 and 1.7, data-model section 5). Every step locks the room row first, as
 * every room transaction does, and re-reads what it changes on that locked state.
 *
 * 1. Abandoned operations: a PENDING operation past its lease becomes ABANDONED and a REKEYING
 *    room returns to REKEY_REQUIRED, so a crashed browser never strands a room (L-24 remains when
 *    no OWNER or ADMIN is available). The next start does the same; this covers idle rooms.
 * 2. Cryptoperiods (PC-14, R6): when the current version of a CONFIDENTIAL or RESTRICTED room is
 *    older than its profile's cryptoperiod, an ACTIVE room enters REKEY_REQUIRED with
 *    CRYPTOPERIOD_EXPIRED (a PENDING MANUAL operation becomes STALE: it cannot coexist with a write
 *    lock); a room already locked only records the reason, and its rekey resolves it. The profile
 *    comes from the catalogue version the room stores; an unknown version is skipped and counted,
 *    never evaluated under another version.
 * 3. Destruction (key-lifecycle 1.7): a RETIRED version that no live file or note names any more
 *    loses all of its envelopes and becomes DESTROYED; its commitment and signed statement stay.
 *    Backups keep envelopes until their retention ends (L-12).
 * 4. Retention: closed operations are purged 90 days after closing; the key version they activated
 *    keeps its row (created_by_operation_id becomes NULL).
 * Nothing here sees key material: the server holds none (INV-01, INV-04).
 */
export interface RekeyMaintenanceResult {
  readonly operationsAbandoned: number;
  readonly cryptoperiodsExpired: number;
  readonly unknownPolicyVersions: number;
  readonly keyVersionsDestroyed: number;
  readonly envelopesDeleted: number;
  readonly operationsPurged: number;
}

const TRANSACTION = { isolationLevel: 'ReadCommitted' as const };

export async function runRekeyMaintenance(prisma: PrismaClient, now: Date): Promise<RekeyMaintenanceResult> {
  // 1. Abandoned operations.
  let operationsAbandoned = 0;
  const expired = await prisma.rekeyOperation.findMany({
    where: { status: 'PENDING', leaseExpiresAt: { lte: now } },
    select: { id: true, roomId: true },
    orderBy: { roomId: 'asc' },
  });
  for (const candidate of expired) {
    operationsAbandoned += await prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM rooms WHERE id = ${candidate.roomId}::uuid FOR UPDATE`;
      const closed = await tx.$queryRaw<{ mode: string }[]>`
        UPDATE rekey_operations SET status = 'ABANDONED', closed_at = ${now}, closed_reason = 'LEASE_EXPIRED'
         WHERE id = ${candidate.id}::uuid AND room_id = ${candidate.roomId}::uuid
           AND status = 'PENDING' AND lease_expires_at <= ${now}
        RETURNING mode::text AS mode`;
      if (closed[0]?.mode === 'MANDATORY') {
        await tx.$executeRaw`
          UPDATE rooms SET key_state = 'REKEY_REQUIRED', updated_at = ${now}
           WHERE id = ${candidate.roomId}::uuid AND key_state = 'REKEYING'`;
      }
      return closed.length;
    }, TRANSACTION);
  }

  // 2. Cryptoperiods.
  let cryptoperiodsExpired = 0;
  let unknownPolicyVersions = 0;
  const rooms = await prisma.$queryRaw<
    { id: string; security_profile: SecurityProfile; policy_version: number; created_at: Date }[]
  >`
    SELECT r.id::text AS id, r.security_profile::text AS security_profile, r.policy_version, v.created_at
      FROM rooms r
      JOIN room_key_versions v ON v.room_id = r.id AND v.version = r.current_key_version
     WHERE r.status = 'ACTIVE' AND NOT ('CRYPTOPERIOD_EXPIRED' = ANY (r.rekey_reasons))
     ORDER BY r.id`;
  for (const room of rooms) {
    const policy = resolveRoomPolicy(room.security_profile, room.policy_version);
    if (policy === undefined) {
      unknownPolicyVersions += 1;
      continue;
    }
    if (policy.cryptoperiodMs === null || room.created_at.getTime() + policy.cryptoperiodMs > now.getTime()) continue;
    cryptoperiodsExpired += await prisma.$transaction(async (tx) => {
      const locked = await tx.$queryRaw<{ key_state: RoomKeyState }[]>`
        SELECT key_state::text AS key_state FROM rooms
         WHERE id = ${room.id}::uuid AND status = 'ACTIVE' AND NOT ('CRYPTOPERIOD_EXPIRED' = ANY (rekey_reasons))
           FOR UPDATE`;
      const state = locked[0]?.key_state;
      if (state === undefined) return 0;
      if (state === 'ACTIVE') {
        await tx.$executeRaw`
          UPDATE rekey_operations SET status = 'STALE', closed_at = ${now}, closed_reason = 'CRYPTOPERIOD_EXPIRED'
           WHERE room_id = ${room.id}::uuid AND status = 'PENDING'`;
        await tx.$executeRaw`
          UPDATE rooms SET key_state = 'REKEY_REQUIRED', rekey_reasons = ARRAY['CRYPTOPERIOD_EXPIRED']::"RekeyReason"[],
                 rekey_required_since = ${now}, membership_epoch = membership_epoch + 1, updated_at = ${now}
           WHERE id = ${room.id}::uuid`;
      } else {
        await tx.$executeRaw`
          UPDATE rooms SET rekey_reasons = array_append(rekey_reasons, 'CRYPTOPERIOD_EXPIRED'::"RekeyReason"),
                 updated_at = ${now}
           WHERE id = ${room.id}::uuid`;
      }
      return 1;
    }, TRANSACTION);
  }

  // 3. Destruction of unreferenced RETIRED versions.
  let keyVersionsDestroyed = 0;
  let envelopesDeleted = 0;
  const retired = await prisma.roomKeyVersion.findMany({
    where: {
      status: 'RETIRED',
      room: { status: 'ACTIVE' },
      files: { none: { status: { not: 'DELETED' } } },
      notes: { none: { deletedAt: null } },
    },
    select: { roomId: true, version: true },
    orderBy: [{ roomId: 'asc' }, { version: 'asc' }],
  });
  for (const version of retired) {
    const outcome = await prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM rooms WHERE id = ${version.roomId}::uuid FOR UPDATE`;
      // Re-checked on the locked room: a file or note created meanwhile keeps the version.
      const destroyed = await tx.roomKeyVersion.updateMany({
        where: {
          roomId: version.roomId,
          version: version.version,
          status: 'RETIRED',
          files: { none: { status: { not: 'DELETED' } } },
          notes: { none: { deletedAt: null } },
        },
        data: { status: 'DESTROYED', destroyedAt: now },
      });
      if (destroyed.count !== 1) return { versions: 0, envelopes: 0 };
      const envelopes = await tx.keyEnvelope.deleteMany({
        where: { roomId: version.roomId, keyVersion: version.version },
      });
      return { versions: 1, envelopes: envelopes.count };
    }, TRANSACTION);
    keyVersionsDestroyed += outcome.versions;
    envelopesDeleted += outcome.envelopes;
  }

  // 4. Retention of closed operations.
  const purged = await prisma.rekeyOperation.deleteMany({
    where: { status: { not: 'PENDING' }, closedAt: { lt: new Date(now.getTime() - REKEY_RULES.closedRetentionMs) } },
  });

  return {
    operationsAbandoned,
    cryptoperiodsExpired,
    unknownPolicyVersions,
    keyVersionsDestroyed,
    envelopesDeleted,
    operationsPurged: purged.count,
  };
}
