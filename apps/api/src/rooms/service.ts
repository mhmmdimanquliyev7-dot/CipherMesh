import {
  ErrorCode,
  PROFILE_ACCESS_REQUIREMENTS,
  type AssignableRoomRole,
  type RoomActionId,
  type RoomMembershipFacts,
  type RoomRole,
  type SecurityProfile,
} from '@ciphermesh/shared';
import type { SecurityEventSink } from '../auth/security-events';
import { requireRecentAuthentication, type Actor, type RequestMeta } from '../auth/sessions';
import { reauthorizeRoomAction, roomDenial, type RoomAccess } from '../authorization/rooms';
import {
  RoomIdUnavailableError,
  type ListPosition,
  type LockedMembership,
  type LockedRoom,
  type MemberRecord,
  type RoomDetailRecord,
  type RoomStore,
  type RoomSummaryRecord,
} from '../db/room-store';
import { HttpError } from '../http/errors';

/**
 * Room lifecycle and membership administration (Phase 5, CM-T030, CM-T031).
 *
 * Authorization happens twice for every change. The route registry's central gate decides when
 * the request arrives (INV-05). Inside the writing transaction, the service locks the room row
 * and the memberships involved and runs the same decision again on that locked state
 * (`reauthorizeRoomAction`), so a concurrent role change, removal, transfer or deletion cannot
 * slip between the check and the write. Writes are conditional on the checked state.
 *
 * Nothing here creates, stores or sees key material. Rooms created in Phase 5 have no key version
 * or envelope yet (CM-T033 adds them to creation); losing a member sets REKEY_REQUIRED, and the
 * rekey itself belongs to the rekey state machine (ADR-013, CM-T050, CM-T051). Events go to the
 * security-event sink (the log until the Phase 12 ledger, L-33) after the transaction commits.
 */

/**
 * Version of the code-defined policy catalogue recorded on each room (data-model 4.6). Version 1
 * is the profile table of security-policy-profiles.md as approved in Phase 0.5; the versioned
 * catalogue itself arrives with CM-T046.
 */
export const ROOM_POLICY_VERSION = 1;

export interface RoomServiceDependencies {
  readonly store: RoomStore;
  readonly transaction: <T>(fn: (store: RoomStore) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

export interface NewRoomInput {
  readonly roomId: string;
  readonly name: string;
  readonly securityProfile: SecurityProfile;
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
const unauthenticated = (): HttpError => new HttpError(401, ErrorCode.UNAUTHENTICATED, 'Authentication required');

/**
 * The facts of a locked actor membership in a locked room, for the decision. Room and user come
 * from the membership row itself, so the decision rejects a row of another room or user.
 */
const factsOf = (room: LockedRoom | null, member: LockedMembership | null): RoomMembershipFacts | null =>
  room === null || member === null
    ? null
    : {
        roomId: member.roomId,
        userId: member.userId,
        role: member.role,
        status: member.status,
        roomStatus: room.status,
      };

export function createRoomService(deps: RoomServiceDependencies) {
  const { store, transaction, events, clock } = deps;

  interface Locked {
    readonly room: LockedRoom;
    readonly actor: LockedMembership;
    readonly target: LockedMembership | undefined;
  }

  /**
   * Locks the room, the actor's membership and, for target actions, the target's membership (in
   * this order, which every room transaction uses), then decides again on the locked state.
   */
  async function lockAndReauthorize(
    tx: RoomStore,
    actor: Actor,
    access: RoomAccess,
    meta: RequestMeta,
    action: RoomActionId,
    target?: { readonly userId: string; readonly requestedRole?: RoomRole; readonly includeSuspended: boolean },
  ): Promise<Locked> {
    const request = { actorUserId: actor.userId, requestId: meta.requestId };
    const room = await tx.lockRoom(access.roomId);
    const actorMembership = room === null ? null : await tx.lockMembership(access.roomId, actor.userId);
    let targetMembership: LockedMembership | undefined;
    if (target !== undefined) {
      const found = room === null ? null : await tx.lockMembership(access.roomId, target.userId);
      if (found === null || (!target.includeSuspended && found.status !== 'ACTIVE')) {
        throw roomDenial(events, { ...request, action }, 'RESOURCE_NOT_FOUND');
      }
      targetMembership = found;
    }
    reauthorizeRoomAction(events, request, {
      actorUserId: actor.userId,
      roomId: access.roomId,
      membership: factsOf(room, actorMembership),
      action,
      ...(targetMembership === undefined
        ? {}
        : {
            resource: {
              roomId: targetMembership.roomId,
              roles: [targetMembership.role, ...(target?.requestedRole === undefined ? [] : [target.requestedRole])],
            },
          }),
    });
    // The decision denies a missing room or membership; these guards only narrow the types.
    if (room === null || actorMembership === null) throw notFound();
    return { room, actor: actorMembership, target: targetMembership };
  }

  /** Records REKEY_REQUIRED only when this change moved the room out of ACTIVE. */
  function recordRekeyRequired(actor: Actor, meta: RequestMeta, roomId: string, reason: string): void {
    events.record({
      name: 'REKEY_REQUIRED',
      outcome: 'SUCCESS',
      actorUserId: actor.userId,
      requestId: meta.requestId,
      details: { roomId, reason },
    });
  }

  return {
    /**
     * SS-04. The creator needs an ACTIVE account and an ACTIVE vault, and must meet the chosen
     * profile's access requirements (PC-01 MFA-verified session, PC-02 recent password
     * authentication). The room and the OWNER membership are written in one transaction.
     */
    async createRoom(actor: Actor, input: NewRoomInput, meta: RequestMeta): Promise<RoomSummaryRecord> {
      const now = clock();
      const requirement = PROFILE_ACCESS_REQUIREMENTS[input.securityProfile];
      if (requirement.mfaVerifiedSession && actor.session.mfaVerifiedAt === null) {
        throw new HttpError(403, ErrorCode.MFA_REQUIRED, 'This security profile requires a session verified with MFA');
      }
      if (requireRecentAuthentication(actor, requirement.maxAuthenticationAgeMs, now) !== undefined) {
        throw new HttpError(
          401,
          ErrorCode.REAUTH_REQUIRED,
          'Sign in again to create a room with this security profile',
        );
      }
      try {
        await transaction(async (tx) => {
          // Locks the user row: an account disabled meanwhile is refused here, or its suspension
          // waits for this transaction and then includes the new membership (PA-03).
          if (!(await tx.lockActiveUser(actor.userId))) throw unauthenticated();
          if (!(await tx.hasActiveIdentity(actor.userId))) {
            throw new HttpError(403, ErrorCode.VAULT_SETUP_REQUIRED, 'Set up your vault before creating a room');
          }
          await tx.insertRoomWithOwner({
            roomId: input.roomId,
            name: input.name,
            securityProfile: input.securityProfile,
            policyVersion: ROOM_POLICY_VERSION,
            creatorId: actor.userId,
            now,
          });
        });
      } catch (error) {
        if (error instanceof RoomIdUnavailableError) {
          throw new HttpError(409, ErrorCode.ROOM_ID_UNAVAILABLE, 'This room identifier cannot be used');
        }
        throw error;
      }
      events.record({
        name: 'ROOM_CREATED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId: input.roomId, securityProfile: input.securityProfile },
      });
      return {
        id: input.roomId,
        name: input.name,
        securityProfile: input.securityProfile,
        keyState: 'ACTIVE',
        createdAt: now,
        role: 'OWNER',
      };
    },

    /** SS-06. The caller's own ACTIVE memberships only, filtered in the query (OL-08). */
    listRooms(actor: Actor, after: ListPosition | undefined, take: number): Promise<RoomSummaryRecord[]> {
      return store.listRoomsForUser(actor.userId, after, take);
    },

    /** AZ-01. Read again with the membership in the query, so a concurrent removal yields 404. */
    async getRoom(actor: Actor, access: RoomAccess): Promise<RoomDetailRecord> {
      const room = await store.findRoomForMember(access.roomId, actor.userId);
      if (room === null) throw notFound();
      return room;
    },

    /** AZ-01. Members of this room, visible only to an ACTIVE member of it. */
    listMembers(
      actor: Actor,
      access: RoomAccess,
      after: ListPosition | undefined,
      take: number,
    ): Promise<MemberRecord[]> {
      return store.listMembers(access.roomId, actor.userId, after, take);
    },

    /** AZ-02. */
    async renameRoom(
      actor: Actor,
      access: RoomAccess,
      name: string,
      meta: RequestMeta,
    ): Promise<{ id: string; name: string; updatedAt: Date }> {
      const now = clock();
      await transaction(async (tx) => {
        await lockAndReauthorize(tx, actor, access, meta, 'AZ-02');
        if (!(await tx.renameRoom(access.roomId, name, now))) throw notFound();
      });
      events.record({
        name: 'ROOM_RENAMED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId: access.roomId },
      });
      return { id: access.roomId, name, updatedAt: now };
    },

    /** AZ-04, step-up required by the route. The room is DELETING from now on (data-model 5). */
    async deleteRoom(actor: Actor, access: RoomAccess, meta: RequestMeta): Promise<void> {
      const now = clock();
      await transaction(async (tx) => {
        await lockAndReauthorize(tx, actor, access, meta, 'AZ-04');
        if (!(await tx.markRoomDeleting(access.roomId, now))) throw notFound();
      });
      events.record({
        name: 'ROOM_DELETED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId: access.roomId },
      });
    },

    /** AZ-10. OWNER among ADMIN, MEMBER and VIEWER; ADMIN between MEMBER and VIEWER. */
    async changeMemberRole(
      actor: Actor,
      access: RoomAccess,
      targetUserId: string,
      role: AssignableRoomRole,
      meta: RequestMeta,
    ): Promise<{ userId: string; role: RoomRole }> {
      const now = clock();
      const changed = await transaction(async (tx) => {
        const locked = await lockAndReauthorize(tx, actor, access, meta, 'AZ-10', {
          userId: targetUserId,
          requestedRole: role,
          includeSuspended: false,
        });
        const target = locked.target;
        if (target === undefined) throw notFound();
        if (target.role === role) return undefined;
        if (!(await tx.setMemberRole(target, role))) throw notFound();
        await tx.incrementMembershipEpoch(access.roomId, now);
        return { from: target.role };
      });
      if (changed !== undefined) {
        events.record({
          name: 'MEMBER_ROLE_CHANGED',
          outcome: 'SUCCESS',
          actorUserId: actor.userId,
          targetUserId,
          requestId: meta.requestId,
          details: { roomId: access.roomId, from: changed.from, to: role },
        });
      }
      return { userId: targetUserId, role };
    },

    /**
     * AZ-09. OWNER removes ADMIN, MEMBER or VIEWER; ADMIN removes MEMBER or VIEWER; the OWNER is
     * never removed this way. The member-loss transaction (INV-07) leaves the room REKEY_REQUIRED.
     */
    async removeMember(actor: Actor, access: RoomAccess, targetUserId: string, meta: RequestMeta): Promise<void> {
      const now = clock();
      const wasActive = await transaction(async (tx) => {
        const locked = await lockAndReauthorize(tx, actor, access, meta, 'AZ-09', {
          userId: targetUserId,
          includeSuspended: true,
        });
        if (locked.target === undefined || !(await tx.removeMember(locked.target, actor.userId, now))) {
          throw notFound();
        }
        return locked.room.keyState === 'ACTIVE';
      });
      events.record({
        name: 'MEMBER_REMOVED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        targetUserId,
        requestId: meta.requestId,
        details: { roomId: access.roomId },
      });
      if (wasActive) recordRekeyRequired(actor, meta, access.roomId, 'MEMBER_REMOVED');
    },

    /**
     * AZ-05, step-up required by the route. Only the OWNER, only to a current ADMIN of the same
     * room. The former OWNER becomes an ADMIN; exactly one ACTIVE OWNER exists before and after
     * (enforced by the transaction and by the database's partial unique index).
     */
    async transferOwnership(actor: Actor, access: RoomAccess, targetUserId: string, meta: RequestMeta): Promise<void> {
      const now = clock();
      await transaction(async (tx) => {
        const locked = await lockAndReauthorize(tx, actor, access, meta, 'AZ-05', {
          userId: targetUserId,
          includeSuspended: false,
        });
        if (locked.target === undefined || !(await tx.transferOwnership(locked.actor, locked.target))) {
          throw notFound();
        }
        await tx.incrementMembershipEpoch(access.roomId, now);
      });
      events.record({
        name: 'OWNERSHIP_TRANSFERRED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        targetUserId,
        requestId: meta.requestId,
        details: { roomId: access.roomId },
      });
    },
  };
}

export type RoomService = ReturnType<typeof createRoomService>;
