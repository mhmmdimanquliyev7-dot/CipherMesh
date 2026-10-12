import { isUuidV4 } from '@ciphermesh/shared';
import { Prisma, type PrismaClient } from '../generated/prisma/client';
import type {
  MembershipStatus,
  RekeyReason,
  RoomKeyState,
  RoomRole,
  RoomStatus,
  SecurityProfile,
} from '../generated/prisma/enums';
import { createAuthStore, type AuthStore } from './auth-store';
import { fileStoreFunctions } from './file-store';
import { invitationStoreFunctions } from './invitation-store';
import { noteStoreFunctions } from './note-store';
import { policyStoreFunctions } from './policy-store';
import { roomKeyStoreFunctions } from './room-key-store';
import { secretStoreFunctions } from './secret-store';

/**
 * Data access for rooms and memberships (Phase 5, CM-T030, CM-T031). The only module that writes
 * `rooms` and `room_members`; the authorization lookup lives in room-access-store.ts.
 *
 * - Every read is constrained by room ID AND the caller's ACTIVE membership inside the query
 *   (INV-06, OL-08); nothing is filtered after loading. Projections are explicit and carry no
 *   key material.
 * - Writes run inside transactions that first lock the room row (`lockRoom`) and then the
 *   membership rows they read (`lockMembership`), so every membership change in a room is
 *   serialized and the service can re-check its authorization on locked state. Account
 *   suspension locks the affected rooms in ID order before their memberships: the same order, so
 *   the two kinds of transaction cannot deadlock.
 * - Writes are conditional on the state that was checked, and report whether they applied.
 * - Losing a member deletes that member's envelopes, increments the membership epoch and sets
 *   REKEY_REQUIRED in the same transaction (INV-07, ADR-013).
 * - Phase 6: a room is created with key version 1, its signed genesis and key-version statements
 *   and the creator's envelope, all produced by the creator's browser (DF-05). The store writes
 *   what the service verified; it never creates key material, envelopes or signatures. The room
 *   key and invitation functions (room-key-store.ts, invitation-store.ts) are part of the same
 *   store, so one transaction can lock and write rooms, memberships, invitations and envelopes.
 */
type Db = PrismaClient | Prisma.TransactionClient;

export interface RoomSummaryRecord {
  readonly id: string;
  readonly name: string;
  readonly securityProfile: SecurityProfile;
  readonly keyState: RoomKeyState;
  readonly createdAt: Date;
  /** The caller's own role. */
  readonly role: RoomRole;
}

export interface RoomDetailRecord extends RoomSummaryRecord {
  readonly policyVersion: number;
  readonly updatedAt: Date;
}

export interface MemberRecord {
  readonly userId: string;
  readonly displayName: string;
  readonly role: RoomRole;
  readonly status: 'ACTIVE' | 'SUSPENDED';
  readonly joinedAt: Date;
}

export interface LockedRoom {
  readonly id: string;
  readonly status: RoomStatus;
  readonly keyState: RoomKeyState;
  readonly securityProfile: SecurityProfile;
  readonly policyVersion: number;
  readonly currentKeyVersion: number;
}

export interface LockedMembership {
  readonly membershipId: string;
  readonly roomId: string;
  readonly userId: string;
  readonly role: RoomRole;
  readonly status: MembershipStatus;
}

export interface NewRoom {
  readonly roomId: string;
  readonly name: string;
  readonly securityProfile: SecurityProfile;
  readonly policyVersion: number;
  readonly creatorId: string;
  readonly now: Date;
  /** Key version 1 as the creator's browser produced it (CM-T033); verified by the service. */
  readonly keys: {
    readonly creatorKeyId: string;
    readonly genesisSignature: Uint8Array;
    readonly commitment: Uint8Array;
    readonly keyVersionSignature: Uint8Array;
    readonly envelope: Uint8Array;
  };
}

/** A membership grant signed by the OWNER (ADMIN grant or ownership transfer, ADR-015). */
export interface MemberGrant {
  readonly subjectKeyId: string;
  readonly role: RoomRole;
  readonly grantorUserId: string;
  readonly grantorKeyId: string;
  readonly signature: Uint8Array;
}

const grantColumns = (grant: MemberGrant) => ({
  subjectKeyId: grant.subjectKeyId,
  grantRole: grant.role,
  grantorUserId: grant.grantorUserId,
  grantorKeyId: grant.grantorKeyId,
  grantSignature: new Uint8Array(grant.signature),
});

export interface SuspendedRoom {
  readonly roomId: string;
  /** True when this suspension moved the room from ACTIVE to REKEY_REQUIRED. */
  readonly rekeyNewlyRequired: boolean;
}

/** A keyset position: the sort timestamp and the ID of the last item returned. */
export interface ListPosition {
  readonly at: Date;
  readonly id: string;
}

/** The client-chosen room ID was used before (DF-05). Raised inside the creating transaction. */
export class RoomIdUnavailableError extends Error {
  constructor() {
    super('Room ID unavailable');
    this.name = 'RoomIdUnavailableError';
  }
}

export function createRoomStore(db: Db) {
  const secrets = secretStoreFunctions(db);
  /** Moves an ACTIVE room to REKEY_REQUIRED (reasons accumulate) and increments its epoch. */
  async function requireRekey(roomId: string, reason: RekeyReason, now: Date): Promise<void> {
    await db.$executeRaw`
      UPDATE rooms SET
        key_state = 'REKEY_REQUIRED',
        rekey_reasons = CASE WHEN ${reason}::"RekeyReason" = ANY (rekey_reasons) THEN rekey_reasons
                             ELSE array_append(rekey_reasons, ${reason}::"RekeyReason") END,
        rekey_required_since = COALESCE(rekey_required_since, ${now}),
        membership_epoch = membership_epoch + 1,
        updated_at = ${now}
      WHERE id = ${roomId}::uuid`;
  }

  return {
    ...roomKeyStoreFunctions(db),
    ...invitationStoreFunctions(db),
    ...fileStoreFunctions(db, requireRekey),
    ...noteStoreFunctions(db),
    ...secretStoreFunctions(db),
    ...policyStoreFunctions(db),

    // ---------------------------------------------------------------------------------- creation

    /** Locks the user row against concurrent disabling and reports whether the account is ACTIVE. */
    async lockActiveUser(userId: string): Promise<boolean> {
      const rows = await db.$queryRaw<{ status: string }[]>`
        SELECT status::text AS status FROM users WHERE id = ${userId}::uuid FOR SHARE`;
      return rows[0]?.status === 'ACTIVE';
    },

    /**
     * The room with its signed genesis, the OWNER membership (whose authority is the genesis, so it
     * carries no grant), key version 1 with its signed statement (recipient list: the creator) and
     * the creator's ACTIVE envelope (DF-05). One transaction with the caller's other checks.
     */
    async insertRoomWithOwner(room: NewRoom): Promise<void> {
      try {
        await db.room.create({
          data: {
            id: room.roomId,
            name: room.name,
            securityProfile: room.securityProfile,
            policyVersion: room.policyVersion,
            createdById: room.creatorId,
            creatorKeyId: room.keys.creatorKeyId,
            genesisSignature: new Uint8Array(room.keys.genesisSignature),
            currentKeyVersion: 1,
            createdAt: room.now,
            updatedAt: room.now,
            members: { create: { userId: room.creatorId, role: 'OWNER', firstKeyVersion: 1, joinedAt: room.now } },
          },
          select: { id: true },
        });
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          throw new RoomIdUnavailableError();
        }
        throw error;
      }
      await db.roomKeyVersion.create({
        data: {
          roomId: room.roomId,
          version: 1,
          status: 'ACTIVE',
          commitment: new Uint8Array(room.keys.commitment),
          algorithmSuite: 'CM1',
          reasons: ['INITIAL'],
          createdById: room.creatorId,
          createdByKeyId: room.keys.creatorKeyId,
          previousCommitment: null,
          recipientUserIds: [room.creatorId],
          recipientKeyIds: [room.keys.creatorKeyId],
          statementSignature: new Uint8Array(room.keys.keyVersionSignature),
          createdAt: room.now,
        },
        select: { id: true },
      });
      await db.keyEnvelope.create({
        data: {
          roomId: room.roomId,
          keyVersion: 1,
          recipientUserId: room.creatorId,
          recipientKeyId: room.keys.creatorKeyId,
          status: 'ACTIVE',
          wrappedKey: new Uint8Array(room.keys.envelope),
          algorithm: 'RSA-OAEP-3072-SHA256',
          createdById: room.creatorId,
          createdAt: room.now,
        },
        select: { id: true },
      });
    },

    // ------------------------------------------------------------------------------------ reads

    /** The caller's ACTIVE memberships in ACTIVE rooms, newest room first (SS-06, OL-08). */
    async listRoomsForUser(
      userId: string,
      after: ListPosition | undefined,
      take: number,
    ): Promise<RoomSummaryRecord[]> {
      const rows = await db.roomMember.findMany({
        where: {
          userId,
          status: 'ACTIVE',
          room: { status: 'ACTIVE' },
          ...(after === undefined
            ? {}
            : {
                OR: [
                  { room: { createdAt: { lt: after.at } } },
                  { room: { createdAt: after.at }, roomId: { lt: after.id } },
                ],
              }),
        },
        orderBy: [{ room: { createdAt: 'desc' } }, { roomId: 'desc' }],
        take,
        select: {
          role: true,
          room: { select: { id: true, name: true, securityProfile: true, keyState: true, createdAt: true } },
        },
      });
      return rows.map(({ role, room }) => ({ ...room, role }));
    },

    /** The room as seen by an ACTIVE member (AZ-01), or null. */
    async findRoomForMember(roomId: string, userId: string): Promise<RoomDetailRecord | null> {
      if (!isUuidV4(roomId) || !isUuidV4(userId)) return null;
      const row = await db.roomMember.findFirst({
        where: { roomId, userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },
        select: {
          role: true,
          room: {
            select: {
              id: true,
              name: true,
              securityProfile: true,
              policyVersion: true,
              keyState: true,
              createdAt: true,
              updatedAt: true,
            },
          },
        },
      });
      return row === null ? null : { ...row.room, role: row.role };
    },

    /** ACTIVE and SUSPENDED members, oldest first, visible only to an ACTIVE member (AZ-01). */
    async listMembers(
      roomId: string,
      viewerId: string,
      after: ListPosition | undefined,
      take: number,
    ): Promise<MemberRecord[]> {
      const rows = await db.roomMember.findMany({
        where: {
          roomId,
          status: { in: ['ACTIVE', 'SUSPENDED'] },
          room: { status: 'ACTIVE', members: { some: { userId: viewerId, status: 'ACTIVE' } } },
          ...(after === undefined
            ? {}
            : { OR: [{ joinedAt: { gt: after.at } }, { joinedAt: after.at, userId: { gt: after.id } }] }),
        },
        orderBy: [{ joinedAt: 'asc' }, { userId: 'asc' }],
        take,
        select: { userId: true, role: true, status: true, joinedAt: true, user: { select: { displayName: true } } },
      });
      return rows.map((row) => ({
        userId: row.userId,
        displayName: row.user.displayName,
        role: row.role,
        status: row.status === 'SUSPENDED' ? 'SUSPENDED' : 'ACTIVE',
        joinedAt: row.joinedAt,
      }));
    },

    // ------------------------------------------------------------------------ locks (transaction)

    /** Locks the room row; every membership change in the room takes this lock first. */
    async lockRoom(roomId: string): Promise<LockedRoom | null> {
      if (!isUuidV4(roomId)) return null;
      const rows = await db.$queryRaw<
        {
          id: string;
          status: RoomStatus;
          key_state: RoomKeyState;
          security_profile: SecurityProfile;
          policy_version: number;
          current_key_version: number;
        }[]
      >`
        SELECT id::text AS id, status::text AS status, key_state::text AS key_state,
               security_profile::text AS security_profile, policy_version, current_key_version
          FROM rooms WHERE id = ${roomId}::uuid FOR UPDATE`;
      const row = rows[0];
      return row === undefined
        ? null
        : {
            id: row.id,
            status: row.status,
            keyState: row.key_state,
            securityProfile: row.security_profile,
            policyVersion: row.policy_version,
            currentKeyVersion: row.current_key_version,
          };
    },

    /** Locks the current (ACTIVE or SUSPENDED) membership of a user in the room, or returns null. */
    async lockMembership(roomId: string, userId: string): Promise<LockedMembership | null> {
      const rows = await db.$queryRaw<
        { id: string; room_id: string; user_id: string; role: RoomRole; status: MembershipStatus }[]
      >`
        SELECT id::text AS id, room_id::text AS room_id, user_id::text AS user_id, role::text AS role,
               status::text AS status
          FROM room_members
         WHERE room_id = ${roomId}::uuid AND user_id = ${userId}::uuid AND status IN ('ACTIVE', 'SUSPENDED')
           FOR UPDATE`;
      const row = rows[0];
      // The room and user come from the row, so the decision's own check would catch a wrong row.
      return row === undefined
        ? null
        : { membershipId: row.id, roomId: row.room_id, userId: row.user_id, role: row.role, status: row.status };
    },

    // ----------------------------------------------------------------- writes (conditional, in tx)

    async renameRoom(roomId: string, name: string, now: Date): Promise<boolean> {
      const result = await db.room.updateMany({
        where: { id: roomId, status: 'ACTIVE' },
        data: { name, updatedAt: now },
      });
      return result.count === 1;
    },

    /** AZ-04: the room refuses every request from now on; the worker finishes the deletion. */
    async markRoomDeleting(roomId: string, now: Date): Promise<boolean> {
      const result = await db.room.updateMany({
        where: { id: roomId, status: 'ACTIVE' },
        data: { status: 'DELETING', deletedAt: now, updatedAt: now },
      });
      return result.count === 1;
    },

    /**
     * Changes a role only if the membership is still ACTIVE with the role that was checked. An ADMIN
     * grant replaces the membership's stored grant with the OWNER's signed one (ADR-015); other
     * changes keep the stored grant, which a demotion cannot revoke (L-46).
     */
    async setMemberRole(membership: LockedMembership, role: RoomRole, grant?: MemberGrant): Promise<boolean> {
      const result = await db.roomMember.updateMany({
        where: { id: membership.membershipId, roomId: membership.roomId, role: membership.role, status: 'ACTIVE' },
        data: { role, ...(grant === undefined ? {} : grantColumns(grant)) },
      });
      return result.count === 1;
    },

    async incrementMembershipEpoch(roomId: string, now: Date): Promise<void> {
      await db.room.update({
        where: { id: roomId },
        data: { membershipEpoch: { increment: 1 }, updatedAt: now },
        select: { id: true },
      });
    },

    /**
     * Removes a member (AZ-09) with the full member-loss transaction of INV-07: status REMOVED,
     * the member's envelopes deleted, the epoch incremented and the room REKEY_REQUIRED. Since
     * Phase 9 the ACTIVE secrets addressed to the member in the room are revoked too (D-09-06).
     */
    async removeMember(membership: LockedMembership, removedById: string, now: Date): Promise<boolean> {
      const result = await db.roomMember.updateMany({
        where: {
          id: membership.membershipId,
          roomId: membership.roomId,
          status: { in: ['ACTIVE', 'SUSPENDED'] },
        },
        data: { status: 'REMOVED', removedAt: now, removedById, removalReason: 'REMOVED_BY_ADMIN' },
      });
      if (result.count !== 1) return false;
      await db.keyEnvelope.deleteMany({ where: { roomId: membership.roomId, recipientUserId: membership.userId } });
      await secrets.revokeSecretsToMember([membership.roomId], membership.userId, now);
      await requireRekey(membership.roomId, 'MEMBER_REMOVED', now);
      return true;
    },

    /**
     * Account disabled (PA-03, key-lifecycle R3): every ACTIVE membership of the user becomes
     * SUSPENDED, the user's envelopes in those rooms are deleted, and each affected ACTIVE room
     * enters REKEY_REQUIRED with MEMBER_SUSPENDED (and, since Phase 9, the ACTIVE secrets addressed
     * to the user there are revoked). The rooms are locked first, in ID order. The
     * caller has already updated the user row, so a room creation by the same user either
     * finished before (and is suspended here) or sees the disabled account and stops.
     */
    async suspendMemberships(userId: string, suspendedById: string, now: Date): Promise<SuspendedRoom[]> {
      const rooms = await db.$queryRaw<{ id: string; status: RoomStatus; key_state: RoomKeyState }[]>`
        SELECT r.id::text AS id, r.status::text AS status, r.key_state::text AS key_state
          FROM rooms r
         WHERE r.id IN (SELECT m.room_id FROM room_members m WHERE m.user_id = ${userId}::uuid AND m.status = 'ACTIVE')
         ORDER BY r.id
           FOR UPDATE OF r`;
      if (rooms.length === 0) return [];
      const roomIds = rooms.map((room) => room.id);
      await db.roomMember.updateMany({
        where: { userId, status: 'ACTIVE', roomId: { in: roomIds } },
        data: { status: 'SUSPENDED', removedAt: now, removedById: suspendedById, removalReason: 'ACCOUNT_DISABLED' },
      });
      await db.keyEnvelope.deleteMany({ where: { recipientUserId: userId, roomId: { in: roomIds } } });
      // Phase 9 (D-09-06): the secrets addressed to the user in those rooms are revoked as well.
      await secrets.revokeSecretsToMember(roomIds, userId, now);
      const suspended: SuspendedRoom[] = [];
      for (const room of rooms) {
        // A room that is being deleted gets no new key version, so it needs no rekey.
        if (room.status === 'ACTIVE') await requireRekey(room.id, 'MEMBER_SUSPENDED', now);
        suspended.push({
          roomId: room.id,
          rekeyNewlyRequired: room.status === 'ACTIVE' && room.key_state === 'ACTIVE',
        });
      }
      return suspended;
    },

    /**
     * Ownership transfer (AZ-05): the OWNER becomes an ADMIN and the target ADMIN becomes OWNER.
     * The demotion runs first, so the partial unique index (one ACTIVE OWNER per room) holds at
     * every statement; both updates are conditional on the checked roles.
     */
    async transferOwnership(owner: LockedMembership, target: LockedMembership, grant: MemberGrant): Promise<boolean> {
      const demoted = await db.roomMember.updateMany({
        where: { id: owner.membershipId, roomId: owner.roomId, role: 'OWNER', status: 'ACTIVE' },
        data: { role: 'ADMIN' },
      });
      if (demoted.count !== 1) return false;
      // The new OWNER's authority is the outgoing OWNER's signed OWNER grant (ADR-015 section 4).
      const promoted = await db.roomMember.updateMany({
        where: { id: target.membershipId, roomId: target.roomId, role: 'ADMIN', status: 'ACTIVE' },
        data: { role: 'OWNER', ...grantColumns(grant) },
      });
      return promoted.count === 1;
    },
  };
}

export type RoomStore = ReturnType<typeof createRoomStore>;

/** The store and a transaction runner for the room service. */
export function roomDataAccess(prisma: PrismaClient): {
  store: RoomStore;
  transaction: <T>(fn: (store: RoomStore) => Promise<T>) => Promise<T>;
} {
  return {
    store: createRoomStore(prisma),
    transaction: (fn) => prisma.$transaction((tx) => fn(createRoomStore(tx)), { isolationLevel: 'ReadCommitted' }),
  };
}

/** Stores bound to one transaction: an account change and its room consequences commit together. */
export interface AccountTransactionStores {
  readonly auth: AuthStore;
  readonly rooms: RoomStore;
}

export function accountDataAccess(prisma: PrismaClient): {
  transaction: <T>(fn: (stores: AccountTransactionStores) => Promise<T>) => Promise<T>;
} {
  return {
    transaction: (fn) =>
      prisma.$transaction((tx) => fn({ auth: createAuthStore(tx), rooms: createRoomStore(tx) }), {
        isolationLevel: 'ReadCommitted',
      }),
  };
}
