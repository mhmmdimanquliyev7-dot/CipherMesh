import { isUuidV4 } from '@ciphermesh/shared';
import type { Prisma, PrismaClient } from '../generated/prisma/client';
import type { MembershipStatus, RoomKeyState, RoomRole, RoomStatus, SecurityProfile } from '../generated/prisma/enums';

/**
 * Membership lookup for room authorization (CM-T029, OL-01). The central room authorizer runs this
 * query on every room-scoped request, so authorization always uses the membership as it is stored
 * now: nothing is cached between requests, and a role change or removal takes effect on the next
 * request.
 *
 * The boundary is enforced in the query itself, not afterwards in memory: the row must match both
 * the addressed room and the session user, be ACTIVE and belong to an ACTIVE room. A membership in
 * room A can therefore never be returned for room B (T-06), and SUSPENDED, REMOVED and LEFT rows
 * or DELETING rooms yield nothing (404). The decision function re-checks all of this anyway.
 * (room_id, user_id) is unique among ACTIVE and SUSPENDED rows, so at most one row matches.
 *
 * The projection holds identifiers, the role and states only: no room name, no key material.
 */
type Db = PrismaClient | Prisma.TransactionClient;

export interface RoomMembershipRecord {
  readonly membershipId: string;
  readonly roomId: string;
  readonly userId: string;
  readonly role: RoomRole;
  readonly status: MembershipStatus;
  readonly room: {
    readonly status: RoomStatus;
    readonly keyState: RoomKeyState;
    readonly securityProfile: SecurityProfile;
  };
}

export function createRoomAccessStore(db: Db) {
  return {
    /** The ACTIVE membership of `userId` in the ACTIVE room `roomId`, or null. */
    async findActiveMembership(roomId: string, userId: string): Promise<RoomMembershipRecord | null> {
      // Malformed identifiers name no room; they never reach PostgreSQL as uuid casts.
      if (!isUuidV4(roomId) || !isUuidV4(userId)) return null;
      const row = await db.roomMember.findFirst({
        where: { roomId, userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },
        select: {
          id: true,
          roomId: true,
          userId: true,
          role: true,
          status: true,
          room: { select: { status: true, keyState: true, securityProfile: true } },
        },
      });
      if (row === null) return null;
      return {
        membershipId: row.id,
        roomId: row.roomId,
        userId: row.userId,
        role: row.role,
        status: row.status,
        room: { status: row.room.status, keyState: row.room.keyState, securityProfile: row.room.securityProfile },
      };
    },
  };
}

export type RoomAccessStore = ReturnType<typeof createRoomAccessStore>;
