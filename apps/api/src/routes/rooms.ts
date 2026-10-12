import { toBase64Url } from '@ciphermesh/crypto/identity';
import {
  INVITATION_LIST_PAGE_SIZE,
  MEMBER_LIST_PAGE_SIZE,
  ROOM_LIST_PAGE_SIZE,
  type RoomResourceFacts,
} from '@ciphermesh/shared';
import {
  emptyBodySchema,
  emptyQuerySchema,
  envelopesResponseSchema,
  formatListCursor,
  invitationApprovedResponseSchema,
  invitationClosedResponseSchema,
  invitationCreatedResponseSchema,
  invitationCreateRequestSchema,
  invitationParamsSchema,
  keyReportRequestSchema,
  keyVersionsResponseSchema,
  listQuerySchema,
  memberIdentityResponseSchema,
  memberListResponseSchema,
  memberRemovedResponseSchema,
  memberRoleChangedResponseSchema,
  memberRoleChangeRequestSchema,
  ownershipTransferredResponseSchema,
  ownershipTransferRequestSchema,
  parseListCursor,
  profileChangedResponseSchema,
  profileChangeRequestSchema,
  recordedResponseSchema,
  roomInvitationListResponseSchema,
  roomCreateRequestSchema,
  roomDeletedResponseSchema,
  roomDetailResponseSchema,
  roomListResponseSchema,
  roomMemberParamsSchema,
  roomParamsSchema,
  roomRenamedResponseSchema,
  roomRenameRequestSchema,
  roomSummarySchema,
  safetyCodeRecordRequestSchema,
} from '@ciphermesh/validation';
import type { RoomInvitationRecord } from '../db/invitation-store';
import type { RoomAccessStore } from '../db/room-access-store';
import type { RoomStore, RoomSummaryRecord } from '../db/room-store';
import type { InvitationService } from '../rooms/invitations';
import type { RoomKeyService } from '../rooms/keys';
import type { RoomService } from '../rooms/service';
import { identityToWire } from '../rooms/statements';
import { actorOf, defineRoute, roomOf, type AnyRoute } from './registry';

/**
 * Room routes (Phase 5, CM-T030, CM-T031). Creation and listing are self-service actions
 * (SS-04, SS-06) over the caller's own account. Every route below /rooms/:roomId is a room route:
 * the registry authorizes it centrally against the caller's database-loaded membership before
 * the handler runs (OL-01, INV-05), and the actions whose cells depend on the target member
 * (AZ-05, AZ-09, AZ-10) load that member by room ID and user ID (OL-02). Handlers never decide
 * authorization themselves; the service re-checks on locked state when it writes.
 *
 * Phase 6 (CM-T033 to CM-T036, CM-T085) adds the cryptographic membership routes: key version 1
 * at creation, the signed statements and the caller's own envelopes, invitations, signed grants
 * for ADMIN and ownership, key reports and Safety Code records. No route accepts or returns room
 * key material: envelopes are RSA-OAEP ciphertext for one recipient, everything else is public.
 */

const iso = (date: Date): string => date.toISOString();

const b64 = (value: Uint8Array): string => toBase64Url(value);

const invitationView = (invitation: RoomInvitationRecord) => ({
  id: invitation.id,
  invitee: invitation.invitee,
  invitedBy: invitation.invitedBy,
  role: invitation.role,
  status: invitation.status,
  fingerprintConfirmed: invitation.fingerprintConfirmed,
  approvedByUserId: invitation.approvedByUserId,
  expiresAt: iso(invitation.expiresAt),
  createdAt: iso(invitation.createdAt),
});

const summary = (room: RoomSummaryRecord) => ({
  id: room.id,
  name: room.name,
  securityProfile: room.securityProfile,
  role: room.role,
  keyState: room.keyState,
  createdAt: iso(room.createdAt),
});

/** Reads one page plus one item, so the presence of a next page needs no count query. */
function page<T>(items: readonly T[], size: number, keyOf: (item: T) => { at: Date; id: string }) {
  const visible = items.slice(0, size);
  const last = visible.at(-1);
  const next = items.length > size && last !== undefined ? keyOf(last) : undefined;
  return { visible, nextCursor: next === undefined ? null : formatListCursor(next.at, next.id) };
}

export function roomRoutes(
  rooms: RoomService,
  access: RoomAccessStore,
  keys: RoomKeyService,
  invitations: InvitationService,
  store: RoomStore,
): readonly AnyRoute[] {
  /** The stored role of the target member, plus the requested role for role changes (OL-02). */
  const targetFacts =
    (includeSuspended: boolean) =>
    async (
      roomId: string,
      userId: string,
      requestedRole?: RoomResourceFacts['roles'],
    ): Promise<RoomResourceFacts | null> => {
      const target = await access.findTargetMember(roomId, userId, includeSuspended);
      return target === null ? null : { roomId: target.roomId, roles: [target.role, ...(requestedRole ?? [])] };
    };
  const activeTarget = targetFacts(false);
  const currentTarget = targetFacts(true);

  return [
    defineRoute({
      method: 'POST',
      path: '/rooms',
      action: 'SS-04-ROOM-CREATE',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: roomCreateRequestSchema,
      response: roomSummarySchema,
      handler: async (ctx) => ({
        status: 201,
        body: summary(await rooms.createRoom(actorOf(ctx), ctx.body, ctx.request)),
      }),
    }),
    defineRoute({
      method: 'GET',
      path: '/rooms',
      action: 'SS-06-ROOM-LIST',
      access: { kind: 'authenticated' },
      query: listQuerySchema,
      body: undefined,
      response: roomListResponseSchema,
      handler: async (ctx) => {
        const after = ctx.query.cursor === undefined ? undefined : parseListCursor(ctx.query.cursor);
        const items = await rooms.listRooms(actorOf(ctx), after, ROOM_LIST_PAGE_SIZE + 1);
        const { visible, nextCursor } = page(items, ROOM_LIST_PAGE_SIZE, (room) => ({
          at: room.createdAt,
          id: room.id,
        }));
        return { status: 200, body: { rooms: visible.map(summary), nextCursor } };
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId',
      action: 'AZ-01-ROOM-READ',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: undefined,
      response: roomDetailResponseSchema,
      handler: async (ctx) => {
        const room = await rooms.getRoom(actorOf(ctx), roomOf(ctx));
        return {
          status: 200,
          body: {
            room: {
              id: room.id,
              name: room.name,
              securityProfile: room.securityProfile,
              policyVersion: room.policyVersion,
              keyState: room.keyState,
              createdAt: iso(room.createdAt),
              updatedAt: iso(room.updatedAt),
            },
            membership: { role: room.role },
          },
        };
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/members',
      action: 'AZ-01-MEMBER-LIST',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: listQuerySchema,
      body: undefined,
      response: memberListResponseSchema,
      handler: async (ctx) => {
        const after = ctx.query.cursor === undefined ? undefined : parseListCursor(ctx.query.cursor);
        const items = await rooms.listMembers(actorOf(ctx), roomOf(ctx), after, MEMBER_LIST_PAGE_SIZE + 1, ctx.request);
        const { visible, nextCursor } = page(items, MEMBER_LIST_PAGE_SIZE, (m) => ({ at: m.joinedAt, id: m.userId }));
        return {
          status: 200,
          body: {
            members: visible.map((m) => ({
              userId: m.userId,
              displayName: m.displayName,
              role: m.role,
              status: m.status,
              joinedAt: iso(m.joinedAt),
            })),
            nextCursor,
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/rename',
      action: 'AZ-02-ROOM-RENAME',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: roomRenameRequestSchema,
      response: roomRenamedResponseSchema,
      handler: async (ctx) => {
        const renamed = await rooms.renameRoom(actorOf(ctx), roomOf(ctx), ctx.body.name, ctx.request);
        return { status: 200, body: { id: renamed.id, name: renamed.name, updatedAt: iso(renamed.updatedAt) } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/profile',
      action: 'AZ-03-PROFILE-CHANGE',
      // PC-03 applies under the room's current profile here; the service adds the rules of the
      // change itself (new access requirements on an upgrade, a 5-minute step-up on a downgrade)
      // on the locked room row (CM-T048).
      access: { kind: 'room', requires: { sensitive: 'CHANGE_PROFILE' } },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: profileChangeRequestSchema,
      response: profileChangedResponseSchema,
      handler: async (ctx) => {
        const changed = await rooms.changeProfile(actorOf(ctx), roomOf(ctx), ctx.body, ctx.request);
        return { status: 200, body: changed };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/delete',
      action: 'AZ-04-ROOM-DELETE',
      access: { kind: 'room', requires: { stepUp: 'standard', sensitive: 'DELETE_ROOM' } },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: roomDeletedResponseSchema,
      handler: async (ctx) => {
        await rooms.deleteRoom(actorOf(ctx), roomOf(ctx), ctx.request);
        return { status: 200, body: { status: 'deleting' as const } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/members/:userId/role',
      action: 'AZ-10-MEMBER-ROLE',
      access: {
        kind: 'room',
        resource: ({ room, params, body }) => activeTarget(room.roomId, params.userId, [body.role]),
      },
      params: roomMemberParamsSchema,
      query: emptyQuerySchema,
      body: memberRoleChangeRequestSchema,
      response: memberRoleChangedResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: await rooms.changeMemberRole(
          actorOf(ctx),
          roomOf(ctx),
          ctx.params.userId,
          ctx.body.role,
          ctx.body.grant,
          ctx.request,
        ),
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/members/:userId/remove',
      action: 'AZ-09-MEMBER-REMOVE',
      access: {
        kind: 'room',
        requires: { sensitive: 'REMOVE_MEMBER' },
        resource: ({ room, params }) => currentTarget(room.roomId, params.userId),
      },
      params: roomMemberParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: memberRemovedResponseSchema,
      handler: async (ctx) => {
        await rooms.removeMember(actorOf(ctx), roomOf(ctx), ctx.params.userId, ctx.request);
        return {
          status: 200,
          body: { userId: ctx.params.userId, status: 'REMOVED' as const, rekeyRequired: true as const },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/members/:userId/transfer-ownership',
      action: 'AZ-05-OWNERSHIP-TRANSFER',
      access: {
        kind: 'room',
        requires: { stepUp: 'standard' },
        resource: ({ room, params }) => activeTarget(room.roomId, params.userId),
      },
      params: roomMemberParamsSchema,
      query: emptyQuerySchema,
      body: ownershipTransferRequestSchema,
      response: ownershipTransferredResponseSchema,
      handler: async (ctx) => {
        await rooms.transferOwnership(actorOf(ctx), roomOf(ctx), ctx.params.userId, ctx.body.grant, ctx.request);
        return { status: 200, body: { ownerUserId: ctx.params.userId, formerOwnerRole: 'ADMIN' as const } };
      },
    }),
    // ----------------------------------------------------------- Phase 6: room keys (CM-T036)
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/key-versions',
      action: 'AZ-15-KEY-VERSIONS',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: undefined,
      response: keyVersionsResponseSchema,
      handler: async (ctx) => {
        const material = await keys.keyMaterial(actorOf(ctx), roomOf(ctx));
        const { genesis } = material.state;
        return {
          status: 200,
          body: {
            currentKeyVersion: material.state.currentKeyVersion,
            keyState: material.state.keyState,
            genesis:
              genesis === null
                ? null
                : {
                    creatorUserId: genesis.creatorUserId,
                    creatorKeyId: genesis.creatorKeyId,
                    suite: 'CM1' as const,
                    signature: b64(genesis.signature),
                  },
            keyVersions: material.keyVersions.map((v) => ({
              keyVersion: v.keyVersion,
              status: v.status,
              suite: 'CM1' as const,
              commitment: b64(v.commitment),
              previousCommitment: v.previousCommitment === null ? null : b64(v.previousCommitment),
              creatorUserId: v.creatorUserId,
              creatorKeyId: v.creatorKeyId,
              recipients: v.recipients.map((r) => ({ userId: r.userId, keyId: r.keyId })),
              signature: b64(v.signature),
              createdAt: iso(v.createdAt),
            })),
            grants: material.grants.map((g) => ({
              subjectUserId: g.subjectUserId,
              subjectKeyId: g.subjectKeyId,
              role: g.role,
              grantorUserId: g.grantorUserId,
              grantorKeyId: g.grantorKeyId,
              signature: b64(g.signature),
            })),
            identities: material.identities.map((identity) => ({ ...identityToWire(identity), suite: 'CM1' as const })),
          },
        };
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/envelopes',
      action: 'AZ-12-ENVELOPES',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: undefined,
      response: envelopesResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: {
          envelopes: (await keys.ownEnvelopes(actorOf(ctx), roomOf(ctx), ctx.request)).map((e) => ({
            keyVersion: e.keyVersion,
            recipientKeyId: e.recipientKeyId,
            wrappedKey: b64(e.wrappedKey),
          })),
        },
      }),
    }),
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/members/:userId/identity',
      action: 'AZ-01-MEMBER-IDENTITY',
      access: { kind: 'room' },
      params: roomMemberParamsSchema,
      query: emptyQuerySchema,
      body: undefined,
      response: memberIdentityResponseSchema,
      handler: async (ctx) => {
        const { identity, grants, identities } = await keys.memberIdentity(
          actorOf(ctx),
          roomOf(ctx),
          ctx.params.userId,
        );
        const { userId: _userId, ...wire } = identityToWire(identity);
        return {
          status: 200,
          body: {
            userId: identity.userId,
            identity: { ...wire, suite: 'CM1' as const, createdAt: iso(identity.createdAt) },
            authority: {
              grants: grants.map((g) => ({
                subjectUserId: g.subjectUserId,
                subjectKeyId: g.subjectKeyId,
                role: g.role,
                grantorUserId: g.grantorUserId,
                grantorKeyId: g.grantorKeyId,
                signature: b64(g.signature),
              })),
              identities: identities.map((i) => ({ ...identityToWire(i), suite: 'CM1' as const })),
            },
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/key-reports',
      action: 'AZ-29-KEY-REPORT',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: keyReportRequestSchema,
      response: recordedResponseSchema,
      handler: (ctx) => {
        keys.reportRejectedKey(actorOf(ctx), roomOf(ctx), ctx.body, ctx.request);
        return { status: 200, body: { status: 'recorded' as const } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/safety-code',
      action: 'AZ-30-SAFETY-CODE',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: safetyCodeRecordRequestSchema,
      response: recordedResponseSchema,
      handler: (ctx) => {
        keys.recordSafetyCode(actorOf(ctx), roomOf(ctx), ctx.body, ctx.request);
        return { status: 200, body: { status: 'recorded' as const } };
      },
    }),
    // ------------------------------------------------- Phase 6: invitations (CM-T034, CM-T035)
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/invitations',
      action: 'AZ-31-INVITATION-LIST',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: listQuerySchema,
      body: undefined,
      response: roomInvitationListResponseSchema,
      handler: async (ctx) => {
        const after = ctx.query.cursor === undefined ? undefined : parseListCursor(ctx.query.cursor);
        const items = await invitations.listRoomInvitations(
          actorOf(ctx),
          roomOf(ctx),
          after,
          INVITATION_LIST_PAGE_SIZE + 1,
        );
        const { visible, nextCursor } = page(items, INVITATION_LIST_PAGE_SIZE, (i) => ({ at: i.createdAt, id: i.id }));
        return { status: 200, body: { invitations: visible.map(invitationView), nextCursor } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/invitations',
      action: 'AZ-06-INVITATION-CREATE',
      access: {
        kind: 'room',
        requires: { sensitive: 'INVITE' },
        // The requested role is what the cell restricts (ADMINs invite only MEMBER or VIEWER).
        resource: ({ room, body }) => Promise.resolve({ roomId: room.roomId, roles: [body.role] }),
      },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: invitationCreateRequestSchema,
      response: invitationCreatedResponseSchema,
      handler: async (ctx) => ({
        status: 201,
        body: {
          invitation: invitationView(
            await invitations.createInvitation(actorOf(ctx), roomOf(ctx), ctx.body, ctx.request),
          ),
        },
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/invitations/:invitationId/approve',
      action: 'AZ-07-INVITATION-APPROVE',
      access: { kind: 'room', requires: { sensitive: 'APPROVE_INVITATION' } },
      params: invitationParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: invitationApprovedResponseSchema,
      handler: async (ctx) => {
        await invitations.approveInvitation(actorOf(ctx), roomOf(ctx), ctx.params.invitationId, ctx.request);
        return { status: 200, body: { status: 'PENDING' as const } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/invitations/:invitationId/revoke',
      action: 'AZ-08-INVITATION-REVOKE',
      access: {
        kind: 'room',
        // OL-02: the invitation is loaded by its ID and the room ID; the inviter decides `own`.
        resource: async ({ room, params }) => {
          const invitation = await store.findRoomInvitation(room.roomId, params.invitationId);
          return invitation === null ? null : { roomId: invitation.roomId, createdById: invitation.invitedById };
        },
      },
      params: invitationParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: invitationClosedResponseSchema,
      handler: async (ctx) => {
        await invitations.revokeInvitation(actorOf(ctx), roomOf(ctx), ctx.params.invitationId, ctx.request);
        return { status: 200, body: { status: 'REVOKED' as const } };
      },
    }),
  ];
}
