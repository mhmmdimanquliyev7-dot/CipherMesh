import { MEMBER_LIST_PAGE_SIZE, ROOM_LIST_PAGE_SIZE, type RoomResourceFacts } from '@ciphermesh/shared';
import {
  emptyBodySchema,
  emptyQuerySchema,
  formatListCursor,
  listQuerySchema,
  memberListResponseSchema,
  memberRemovedResponseSchema,
  memberRoleChangedResponseSchema,
  memberRoleChangeRequestSchema,
  ownershipTransferredResponseSchema,
  parseListCursor,
  roomCreateRequestSchema,
  roomDeletedResponseSchema,
  roomDetailResponseSchema,
  roomListResponseSchema,
  roomMemberParamsSchema,
  roomParamsSchema,
  roomRenamedResponseSchema,
  roomRenameRequestSchema,
  roomSummarySchema,
} from '@ciphermesh/validation';
import type { RoomAccessStore } from '../db/room-access-store';
import type { RoomSummaryRecord } from '../db/room-store';
import type { RoomService } from '../rooms/service';
import { actorOf, defineRoute, roomOf, type AnyRoute } from './registry';

/**
 * Room routes (Phase 5, CM-T030, CM-T031). Creation and listing are self-service actions
 * (SS-04, SS-06) over the caller's own account. Every route below /rooms/:roomId is a room route:
 * the registry authorizes it centrally against the caller's database-loaded membership before
 * the handler runs (OL-01, INV-05), and the actions whose cells depend on the target member
 * (AZ-05, AZ-09, AZ-10) load that member by room ID and user ID (OL-02). Handlers never decide
 * authorization themselves; the service re-checks on locked state when it writes.
 *
 * No route accepts or returns key material; room keys arrive with Phase 6.
 */

const iso = (date: Date): string => date.toISOString();

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

export function roomRoutes(rooms: RoomService, access: RoomAccessStore): readonly AnyRoute[] {
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
        const items = await rooms.listMembers(actorOf(ctx), roomOf(ctx), after, MEMBER_LIST_PAGE_SIZE + 1);
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
      path: '/rooms/:roomId/delete',
      action: 'AZ-04-ROOM-DELETE',
      access: { kind: 'room', requires: { stepUp: 'standard' } },
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
        body: await rooms.changeMemberRole(actorOf(ctx), roomOf(ctx), ctx.params.userId, ctx.body.role, ctx.request),
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/members/:userId/remove',
      action: 'AZ-09-MEMBER-REMOVE',
      access: { kind: 'room', resource: ({ room, params }) => currentTarget(room.roomId, params.userId) },
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
      body: emptyBodySchema,
      response: ownershipTransferredResponseSchema,
      handler: async (ctx) => {
        await rooms.transferOwnership(actorOf(ctx), roomOf(ctx), ctx.params.userId, ctx.request);
        return { status: 200, body: { ownerUserId: ctx.params.userId, formerOwnerRole: 'ADMIN' as const } };
      },
    }),
  ];
}
