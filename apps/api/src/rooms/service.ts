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
  type MemberGrant,
  type MemberRecord,
  type RoomDetailRecord,
  type RoomStore,
  type RoomSummaryRecord,
} from '../db/room-store';
import { HttpError } from '../http/errors';
import { decodeExact, verifiedIdentity, verifyGrant, verifyRoomCreation } from './statements';

/**
 * Room lifecycle and membership administration (Phase 5, CM-T030, CM-T031).
 *
 * Authorization happens twice for every change. The route registry's central gate decides when
 * the request arrives (INV-05). Inside the writing transaction, the service locks the room row
 * and the memberships involved and runs the same decision again on that locked state
 * (`reauthorizeRoomAction`), so a concurrent role change, removal, transfer or deletion cannot
 * slip between the check and the write. Writes are conditional on the checked state.
 *
 * Nothing here creates or sees key material. Since Phase 6 (CM-T033) a room is created with key
 * version 1 made in the creator's browser: the API verifies the signed genesis and key-version
 * statements under the creator's ACTIVE identity and stores them with the creator's envelope in
 * the creating transaction (DF-05). Granting ADMIN and transferring ownership carry the OWNER's
 * signed membership grant, verified the same way (ADR-015 section 4). Losing a member sets
 * REKEY_REQUIRED; the rekey belongs to the rekey state machine (ADR-013, CM-T050, CM-T051). Events
 * go to the security-event sink (the log until the Phase 12 ledger, L-33) after commit.
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
  /** Key version 1 in wire form (base64url), validated for shape by the route schema. */
  readonly keys: {
    readonly creatorKeyId: string;
    readonly commitment: string;
    readonly envelope: string;
    readonly genesisSignature: string;
    readonly keyVersionSignature: string;
  };
}

/** A signed membership grant in wire form (AZ-05, AZ-10). */
export interface GrantProofInput {
  readonly subjectKeyId: string;
  readonly signature: string;
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
const unauthenticated = (): HttpError => new HttpError(401, ErrorCode.UNAUTHENTICATED, 'Authentication required');
export const statementInvalid = (): HttpError =>
  new HttpError(422, ErrorCode.ROOM_STATEMENT_INVALID, 'The signed room statement could not be verified');
export const identityKeyChanged = (): HttpError =>
  new HttpError(409, ErrorCode.IDENTITY_KEY_CHANGED, 'The identity key is not the current identity of that user');
export const vaultSetupRequired = (): HttpError =>
  new HttpError(403, ErrorCode.VAULT_SETUP_REQUIRED, 'Set up your vault first');

/**
 * The facts of a locked actor membership in a locked room, for the decision. Room and user come
 * from the membership row itself, so the decision rejects a row of another room or user.
 */
export const factsOf = (room: LockedRoom | null, member: LockedMembership | null): RoomMembershipFacts | null =>
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

  /** A signed statement that failed verification: recorded, then refused with nothing stored. */
  function rejectStatement(actor: Actor, meta: RequestMeta, roomId: string, statement: string): HttpError {
    events.record({
      name: 'ROOM_STATEMENT_REJECTED',
      outcome: 'DENIED',
      actorUserId: actor.userId,
      requestId: meta.requestId,
      details: { roomId, statement },
    });
    return statementInvalid();
  }

  /**
   * Verifies a grant the caller (the OWNER) signed for the target's ACTIVE identity, before any
   * lock is taken. The transaction re-checks that both identities are still ACTIVE.
   */
  async function verifiedOwnerGrant(
    actor: Actor,
    meta: RequestMeta,
    roomId: string,
    targetUserId: string,
    role: 'ADMIN' | 'OWNER',
    proof: GrantProofInput,
  ): Promise<MemberGrant> {
    const signature = decodeExact(proof.signature, 64);
    const grantor = await store.findActiveIdentity(actor.userId);
    if (grantor === null) throw vaultSetupRequired();
    const subject = await store.findActiveIdentity(targetUserId);
    if (subject === null || subject.keyId !== proof.subjectKeyId) throw identityKeyChanged();
    const verified = await verifiedIdentity(grantor);
    const valid =
      signature !== undefined &&
      verified !== undefined &&
      (await verifyGrant(verified, {
        roomId,
        subjectUserId: targetUserId,
        subjectKeyId: subject.keyId,
        role,
        signature,
      }));
    if (!valid) throw rejectStatement(actor, meta, roomId, 'MEMBERSHIP_GRANT');
    return { subjectKeyId: subject.keyId, role, grantorUserId: actor.userId, grantorKeyId: grantor.keyId, signature };
  }

  /** Inside the transaction: both identities of a grant are still the ACTIVE ones (vault reset race). */
  async function lockGrantIdentities(tx: RoomStore, targetUserId: string, grant: MemberGrant): Promise<void> {
    if (
      !(await tx.lockActiveIdentity(grant.grantorUserId, grant.grantorKeyId)) ||
      !(await tx.lockActiveIdentity(targetUserId, grant.subjectKeyId))
    ) {
      throw identityKeyChanged();
    }
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
     * SS-04, CM-T033. The creator needs an ACTIVE account and an ACTIVE vault, and must meet the
     * chosen profile's access requirements (PC-01 MFA-verified session, PC-02 recent password
     * authentication). Key version 1 must be signed by the creator's ACTIVE identity: the genesis
     * statement and the version-1 statement (commitment, recipients = the creator) verify under its
     * signing key, and the envelope is addressed to that identity. The room, the OWNER membership,
     * key version 1 and the envelope are written in one transaction; a refused part stores nothing.
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
      const identity = await store.findActiveIdentity(actor.userId);
      if (identity === null) {
        throw new HttpError(403, ErrorCode.VAULT_SETUP_REQUIRED, 'Set up your vault before creating a room');
      }
      if (identity.keyId !== input.keys.creatorKeyId) throw identityKeyChanged();
      const commitment = decodeExact(input.keys.commitment, 32);
      const envelope = decodeExact(input.keys.envelope, 384);
      const genesisSignature = decodeExact(input.keys.genesisSignature, 64);
      const keyVersionSignature = decodeExact(input.keys.keyVersionSignature, 64);
      const creator = await verifiedIdentity(identity);
      if (
        commitment === undefined ||
        envelope === undefined ||
        genesisSignature === undefined ||
        keyVersionSignature === undefined ||
        creator === undefined ||
        !(await verifyRoomCreation(creator, {
          roomId: input.roomId,
          commitment,
          genesisSignature,
          keyVersionSignature,
        }))
      ) {
        throw rejectStatement(actor, meta, input.roomId, 'GENESIS_AND_KEY_VERSION');
      }
      try {
        await transaction(async (tx) => {
          // Locks the user row: an account disabled meanwhile is refused here, or its suspension
          // waits for this transaction and then includes the new membership (PA-03).
          if (!(await tx.lockActiveUser(actor.userId))) throw unauthenticated();
          // Locks the identity: a vault reset meanwhile is refused here or waits (key-lifecycle 3).
          if (!(await tx.lockActiveIdentity(actor.userId, identity.keyId))) throw identityKeyChanged();
          await tx.insertRoomWithOwner({
            roomId: input.roomId,
            name: input.name,
            securityProfile: input.securityProfile,
            policyVersion: ROOM_POLICY_VERSION,
            creatorId: actor.userId,
            now,
            keys: { creatorKeyId: identity.keyId, genesisSignature, commitment, keyVersionSignature, envelope },
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
        details: { roomId: input.roomId, securityProfile: input.securityProfile, keyVersion: 1 },
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

    /**
     * AZ-10. OWNER among ADMIN, MEMBER and VIEWER; ADMIN between MEMBER and VIEWER. Granting ADMIN
     * (OWNER only, by the matrix) carries the OWNER's signed grant for the member's ACTIVE identity
     * (ADR-015 section 4), which becomes the membership's stored grant.
     */
    async changeMemberRole(
      actor: Actor,
      access: RoomAccess,
      targetUserId: string,
      role: AssignableRoomRole,
      proof: GrantProofInput | undefined,
      meta: RequestMeta,
    ): Promise<{ userId: string; role: RoomRole }> {
      const now = clock();
      if ((role === 'ADMIN') !== (proof !== undefined)) throw statementInvalid();
      const grant =
        proof === undefined
          ? undefined
          : await verifiedOwnerGrant(actor, meta, access.roomId, targetUserId, 'ADMIN', proof);
      const changed = await transaction(async (tx) => {
        const locked = await lockAndReauthorize(tx, actor, access, meta, 'AZ-10', {
          userId: targetUserId,
          requestedRole: role,
          includeSuspended: false,
        });
        const target = locked.target;
        if (target === undefined) throw notFound();
        if (target.role === role) return undefined;
        if (grant !== undefined) await lockGrantIdentities(tx, targetUserId, grant);
        if (!(await tx.setMemberRole(target, role, grant))) throw notFound();
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
     * (enforced by the transaction and by the database's partial unique index). The OWNER signs a
     * grant of the OWNER role for the new owner's ACTIVE identity (ADR-015 section 4).
     */
    async transferOwnership(
      actor: Actor,
      access: RoomAccess,
      targetUserId: string,
      proof: GrantProofInput,
      meta: RequestMeta,
    ): Promise<void> {
      const now = clock();
      const grant = await verifiedOwnerGrant(actor, meta, access.roomId, targetUserId, 'OWNER', proof);
      await transaction(async (tx) => {
        const locked = await lockAndReauthorize(tx, actor, access, meta, 'AZ-05', {
          userId: targetUserId,
          includeSuspended: false,
        });
        if (locked.target === undefined) throw notFound();
        await lockGrantIdentities(tx, targetUserId, grant);
        if (!(await tx.transferOwnership(locked.actor, locked.target, grant))) {
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
