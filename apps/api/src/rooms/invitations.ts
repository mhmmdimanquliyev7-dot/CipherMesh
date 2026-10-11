import {
  decideRoomAction,
  ErrorCode,
  INVITATION_RULES,
  PROFILE_ACCESS_REQUIREMENTS,
  type AssignableRoomRole,
  type RoomActionId,
  type RoomResourceFacts,
} from '@ciphermesh/shared';
import type { SecurityEventSink } from '../auth/security-events';
import {
  requireRecentAuthentication,
  requireStepUp,
  SESSION_POLICY,
  type Actor,
  type RequestMeta,
} from '../auth/sessions';
import { reauthorizeRoomAction, roomDenial, type RoomAccess } from '../authorization/rooms';
import {
  InvitationPendingError,
  type InvitationRecord,
  type OwnInvitationRecord,
  type RoomInvitationRecord,
} from '../db/invitation-store';
import type { ListPosition, LockedMembership, LockedRoom, RoomStore } from '../db/room-store';
import { HttpError } from '../http/errors';
import { factsOf, identityKeyChanged, statementInvalid, vaultSetupRequired } from './service';
import { decodeExact, verifiedIdentity, verifyGrant } from './statements';

/**
 * Invitations with pre-wrapped key envelopes (Phase 6, CM-T034, CM-T035, DF-06).
 *
 * The inviter's browser verifies the room key it holds, wraps it to the invitee's verified
 * identity and signs a membership grant; the API stores the grant and the PENDING envelopes after
 * checking:
 *   - the matrix (AZ-06 role ceilings; AZ-07 OWNER approval; AZ-08 revocation), on locked state;
 *   - PC-16: no invitation, approval or acceptance while the room is REKEY_REQUIRED or REKEYING;
 *   - PC-03: in RESTRICTED rooms, inviting and approving need a recent step-up;
 *   - PC-05: the confirmed fingerprint equals the invitee's current one, required in RESTRICTED;
 *   - PC-06: the server sets the expiry; PC-04: an ADMIN's invitation in a CONFIDENTIAL or
 *     RESTRICTED room waits for the OWNER's approval (approver differs from inviter);
 *   - PC-07: the envelope set covers the current key version, older retained versions only where
 *     the profile allows history;
 *   - the invitee's and the inviter's identities are their current ACTIVE ones, and the grant
 *     verifies under the inviter's signing key for exactly this invitee key and role (ADR-015).
 *
 * Acceptance (SS-03) locks, in this order, the invitee's user row (an account disable cannot miss
 * the new membership, PA-03), the invitee's identity row (a vault reset cannot race it), the room,
 * the invitation and the memberships, then re-checks everything on that locked state. PENDING
 * envelopes are never served; they become ACTIVE only in the acceptance transaction. The browser
 * still verifies every statement before it uses the key: an accepted invitation is not trusted
 * merely because the API accepted it.
 */

export interface InvitationServiceDependencies {
  readonly store: RoomStore;
  readonly transaction: <T>(fn: (store: RoomStore) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

export interface NewInvitationInput {
  readonly inviteeUserId: string;
  readonly inviteeKeyId: string;
  readonly role: AssignableRoomRole;
  readonly confirmedFingerprint: string | null;
  readonly grantSignature: string;
  readonly envelopes: readonly { readonly keyVersion: number; readonly wrappedKey: string }[];
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
const unauthenticated = (): HttpError => new HttpError(401, ErrorCode.UNAUTHENTICATED, 'Authentication required');
const rekeyRequired = (): HttpError =>
  new HttpError(409, ErrorCode.REKEY_REQUIRED, 'The room key must be rotated before membership can change this way');
const notOpen = (): HttpError =>
  new HttpError(409, ErrorCode.INVITATION_NOT_OPEN, 'This invitation cannot be used for this action');
const expired = (): HttpError => new HttpError(409, ErrorCode.INVITATION_EXPIRED, 'This invitation has expired');
/** PC-03: in RESTRICTED rooms, inviting and approving need a step-up within the last 15 minutes. */
function requireRestrictedStepUp(actor: Actor, room: LockedRoom, now: Date): void {
  if (room.securityProfile === 'RESTRICTED' && requireStepUp(actor, SESSION_POLICY.stepUpMs, now) !== undefined) {
    throw new HttpError(401, ErrorCode.STEP_UP_REQUIRED, 'Confirm your identity to continue');
  }
}
const envelopeSetInvalid = (): HttpError =>
  new HttpError(422, ErrorCode.ENVELOPE_SET_INVALID, 'The key envelopes do not match what this room requires');

export function createInvitationService(deps: InvitationServiceDependencies) {
  const { store, transaction, events, clock } = deps;

  /** Locks the room and the actor's membership (in that order) and decides again on that state. */
  async function lockAndReauthorize(
    tx: RoomStore,
    actor: Actor,
    roomId: string,
    meta: RequestMeta,
    action: RoomActionId,
    resource?: (room: LockedRoom) => Promise<RoomResourceFacts | null>,
  ): Promise<{ readonly room: LockedRoom; readonly member: LockedMembership }> {
    const request = { actorUserId: actor.userId, requestId: meta.requestId };
    const room = await tx.lockRoom(roomId);
    const member = room === null ? null : await tx.lockMembership(roomId, actor.userId);
    let facts: RoomResourceFacts | undefined;
    if (room !== null && member !== null && resource !== undefined) {
      const loaded = await resource(room);
      if (loaded === null) throw roomDenial(events, { ...request, action }, 'RESOURCE_NOT_FOUND');
      facts = loaded;
    }
    reauthorizeRoomAction(events, request, {
      actorUserId: actor.userId,
      roomId,
      membership: factsOf(room, member),
      action,
      ...(facts === undefined ? {} : { resource: facts }),
    });
    if (room === null || member === null) throw notFound();
    return { room, member };
  }

  function record(
    name: 'INVITATION_CREATED' | 'INVITATION_APPROVED' | 'INVITATION_REVOKED' | 'INVITATION_DECLINED' | 'MEMBER_JOINED',
    actor: Actor,
    meta: RequestMeta,
    details: Readonly<Record<string, string | number | boolean>>,
    targetUserId?: string,
  ): void {
    events.record({
      name,
      outcome: 'SUCCESS',
      actorUserId: actor.userId,
      requestId: meta.requestId,
      ...(targetUserId === undefined ? {} : { targetUserId }),
      details,
    });
  }

  return {
    /** AZ-06 (CM-T034). */
    async createInvitation(
      actor: Actor,
      access: RoomAccess,
      input: NewInvitationInput,
      meta: RequestMeta,
    ): Promise<RoomInvitationRecord> {
      const now = clock();
      const roomId = access.roomId;
      const signature = decodeExact(input.grantSignature, 64);
      const envelopes = input.envelopes.map((e) => ({
        keyVersion: e.keyVersion,
        wrappedKey: decodeExact(e.wrappedKey, 384),
      }));
      const decoded = envelopes.flatMap((e) =>
        e.wrappedKey === undefined ? [] : [{ ...e, wrappedKey: e.wrappedKey }],
      );
      if (decoded.length !== envelopes.length) throw envelopeSetInvalid();
      // The invitee as the directory shows it: an ACTIVE account with an ACTIVE identity (SS-05).
      const invitee = await store.findActiveIdentity(input.inviteeUserId);
      if (invitee === null) throw notFound();
      if (invitee.keyId !== input.inviteeKeyId) throw identityKeyChanged();
      const inviter = await store.findActiveIdentity(actor.userId);
      if (inviter === null) throw vaultSetupRequired();
      const grantor = await verifiedIdentity(inviter);
      const grantValid =
        signature !== undefined &&
        grantor !== undefined &&
        (await verifyGrant(grantor, {
          roomId,
          subjectUserId: invitee.userId,
          subjectKeyId: invitee.keyId,
          role: input.role,
          signature,
        }));
      if (!grantValid) {
        events.record({
          name: 'ROOM_STATEMENT_REJECTED',
          outcome: 'DENIED',
          actorUserId: actor.userId,
          requestId: meta.requestId,
          details: { roomId, statement: 'MEMBERSHIP_GRANT' },
        });
        throw statementInvalid();
      }

      let created: InvitationRecord;
      try {
        created = await transaction(async (tx) => {
          const { room, member } = await lockAndReauthorize(tx, actor, roomId, meta, 'AZ-06', (locked) =>
            Promise.resolve({ roomId: locked.id, roles: [input.role] }),
          );
          requireRestrictedStepUp(actor, room, now);
          if (room.keyState !== 'ACTIVE') throw rekeyRequired();
          if ((await tx.lockMembership(roomId, invitee.userId)) !== null) {
            throw new HttpError(409, ErrorCode.ALREADY_MEMBER, 'This user is already a member of the room');
          }
          if (!(await tx.lockActiveIdentity(invitee.userId, invitee.keyId))) throw identityKeyChanged();
          if (!(await tx.lockActiveIdentity(actor.userId, inviter.keyId))) throw identityKeyChanged();
          const rules = INVITATION_RULES[room.securityProfile];
          // PC-05: the human comparison itself cannot be proven (L-18); the value must match.
          if (rules.fingerprintConfirmation === 'required' && input.confirmedFingerprint === null) {
            throw new HttpError(
              422,
              ErrorCode.FINGERPRINT_REQUIRED,
              'This room requires confirming the invitee fingerprint',
            );
          }
          if (input.confirmedFingerprint !== null && input.confirmedFingerprint !== invitee.publicKeyFingerprint) {
            throw new HttpError(
              409,
              ErrorCode.FINGERPRINT_MISMATCH,
              "The confirmed fingerprint is not the invitee's current fingerprint",
            );
          }
          // PC-07: the current version always; older retained versions only where history is shared.
          const shareable = new Set(await tx.shareableKeyVersions(roomId));
          const requested = decoded.map((e) => e.keyVersion);
          const valid =
            new Set(requested).size === requested.length &&
            requested.includes(room.currentKeyVersion) &&
            requested.every((v) => shareable.has(v) && v <= room.currentKeyVersion) &&
            (rules.keyHistory === 'all-retained' || requested.length === 1);
          if (!valid) throw envelopeSetInvalid();
          const status = member.role === 'ADMIN' && rules.adminInvitationNeedsApproval ? 'PENDING_APPROVAL' : 'PENDING';
          return tx.insertInvitation({
            roomId,
            inviteeUserId: invitee.userId,
            inviteeKeyId: invitee.keyId,
            invitedById: actor.userId,
            grantorKeyId: inviter.keyId,
            grantSignature: signature,
            role: input.role,
            status,
            confirmedFingerprint: input.confirmedFingerprint,
            expiresAt: new Date(now.getTime() + rules.validityMs),
            envelopes: decoded,
            now,
          });
        });
      } catch (error) {
        if (error instanceof InvitationPendingError) {
          throw new HttpError(
            409,
            ErrorCode.INVITATION_PENDING,
            'This user already has an open invitation to the room',
          );
        }
        throw error;
      }
      record(
        'INVITATION_CREATED',
        actor,
        meta,
        { roomId, invitationId: created.id, role: created.role, status: created.status, keyVersions: decoded.length },
        invitee.userId,
      );
      const view = await store.findRoomInvitationView(roomId, created.id);
      if (view === null) throw notFound();
      return view;
    },

    /** AZ-31 (OL-11): the room's open invitations, for the OWNER and ADMINs. */
    listRoomInvitations(
      actor: Actor,
      access: RoomAccess,
      after: ListPosition | undefined,
      take: number,
    ): Promise<RoomInvitationRecord[]> {
      return store.listRoomInvitations(access.roomId, actor.userId, clock(), after, take);
    },

    /** AZ-07 (PC-04): the OWNER approves an ADMIN's invitation; never the inviter themselves. */
    async approveInvitation(actor: Actor, access: RoomAccess, invitationId: string, meta: RequestMeta): Promise<void> {
      const now = clock();
      await transaction(async (tx) => {
        const { room } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-07');
        requireRestrictedStepUp(actor, room, now);
        const invitation = await tx.lockInvitation(room.id, invitationId);
        if (invitation === null) throw notFound();
        if (invitation.status !== 'PENDING_APPROVAL' || invitation.invitedById === actor.userId) throw notOpen();
        if (invitation.expiresAt <= now) throw expired();
        if (room.keyState !== 'ACTIVE') throw rekeyRequired();
        if (!(await tx.approveInvitation(invitation, actor.userId, now))) throw notOpen();
      });
      record('INVITATION_APPROVED', actor, meta, { roomId: access.roomId, invitationId });
    },

    /** AZ-08: the OWNER revokes any open invitation, an ADMIN only their own. Allowed while locked. */
    async revokeInvitation(actor: Actor, access: RoomAccess, invitationId: string, meta: RequestMeta): Promise<void> {
      const now = clock();
      await transaction(async (tx) => {
        let invitation: InvitationRecord | null = null;
        await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-08', async (room) => {
          invitation = await tx.lockInvitation(room.id, invitationId);
          return invitation === null ? null : { roomId: invitation.roomId, createdById: invitation.invitedById };
        });
        const locked = invitation as InvitationRecord | null;
        if (locked === null) throw notFound();
        if (!(await tx.closeInvitation(locked, 'REVOKED', now))) throw notOpen();
      });
      record('INVITATION_REVOKED', actor, meta, { roomId: access.roomId, invitationId });
    },

    /** SS-03: the caller's own open invitations (OL-11). */
    listOwnInvitations(actor: Actor, after: ListPosition | undefined, take: number): Promise<OwnInvitationRecord[]> {
      return store.listOwnInvitations(actor.userId, clock(), after, take);
    },

    /** SS-03 (CM-T035): accepts the caller's own PENDING invitation. */
    async acceptInvitation(
      actor: Actor,
      invitationId: string,
      meta: RequestMeta,
    ): Promise<{ readonly roomId: string; readonly role: AssignableRoomRole }> {
      const now = clock();
      const found = await store.findOwnInvitation(invitationId, actor.userId);
      if (found === null) throw notFound();
      const accepted = await transaction(async (tx) => {
        // 1. The user row: a concurrent account disable either finished (refused here) or waits
        //    and then suspends the membership this transaction creates (PA-03, Phase 5 handoff).
        if (!(await tx.lockActiveUser(actor.userId))) throw unauthenticated();
        // 2. The identity the envelopes are wrapped for must still be the caller's ACTIVE one.
        if (!(await tx.lockActiveIdentity(actor.userId, found.inviteeKeyId))) throw identityKeyChanged();
        // 3. The room, then the invitation, re-read under lock.
        const room = await tx.lockRoom(found.roomId);
        if (room === null || room.status !== 'ACTIVE') throw notFound();
        const invitation = await tx.lockInvitation(room.id, invitationId);
        if (invitation === null || invitation.inviteeUserId !== actor.userId) throw notFound();
        if (invitation.status !== 'PENDING') throw notOpen();
        if (invitation.expiresAt <= now) throw expired();
        // Joining needs the room's access requirements, as creating it does (PC-01, PC-02).
        const requirement = PROFILE_ACCESS_REQUIREMENTS[room.securityProfile];
        if (requirement.mfaVerifiedSession && actor.session.mfaVerifiedAt === null) {
          throw new HttpError(
            403,
            ErrorCode.MFA_REQUIRED,
            'This security profile requires a session verified with MFA',
          );
        }
        if (requireRecentAuthentication(actor, requirement.maxAuthenticationAgeMs, now) !== undefined) {
          throw new HttpError(
            401,
            ErrorCode.REAUTH_REQUIRED,
            'Sign in again to join a room with this security profile',
          );
        }
        if (room.keyState !== 'ACTIVE') throw rekeyRequired();
        // 4. Memberships: the caller is not a member yet, and the inviter may still grant this role.
        if ((await tx.lockMembership(room.id, actor.userId)) !== null) {
          throw new HttpError(409, ErrorCode.ALREADY_MEMBER, 'You are already a member of this room');
        }
        const inviter = await tx.lockMembership(room.id, invitation.invitedById);
        const inviterMayGrant = decideRoomAction({
          actorUserId: invitation.invitedById,
          roomId: room.id,
          membership: factsOf(room, inviter),
          action: 'AZ-06',
          resource: { roomId: room.id, roles: [invitation.role] },
        }).allowed;
        if (!inviterMayGrant) throw notOpen();
        // 5. The invitation still carries an envelope for the current key version.
        const versions = await tx.pendingEnvelopeVersions(invitation);
        if (!versions.includes(room.currentKeyVersion)) throw notOpen();
        if (!(await tx.acceptInvitation(invitation, Math.min(...versions), now))) throw notOpen();
        return { roomId: room.id, role: invitation.role };
      });
      record('MEMBER_JOINED', actor, meta, { roomId: accepted.roomId, invitationId, role: accepted.role });
      return accepted;
    },

    /** SS-03: declines the caller's own open invitation; its PENDING envelopes are deleted. */
    async declineInvitation(actor: Actor, invitationId: string, meta: RequestMeta): Promise<void> {
      const now = clock();
      const found = await store.findOwnInvitation(invitationId, actor.userId);
      if (found === null) throw notFound();
      await transaction(async (tx) => {
        const room = await tx.lockRoom(found.roomId);
        if (room === null) throw notFound();
        const invitation = await tx.lockInvitation(room.id, invitationId);
        if (invitation === null || invitation.inviteeUserId !== actor.userId) throw notFound();
        if (!(await tx.closeInvitation(invitation, 'DECLINED', now))) throw notOpen();
      });
      record('INVITATION_DECLINED', actor, meta, { roomId: found.roomId, invitationId });
    },
  };
}

export type InvitationService = ReturnType<typeof createInvitationService>;
