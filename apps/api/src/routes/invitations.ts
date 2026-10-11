import { INVITATION_LIST_PAGE_SIZE } from '@ciphermesh/shared';
import {
  emptyBodySchema,
  emptyQuerySchema,
  formatListCursor,
  invitationAcceptedResponseSchema,
  invitationClosedResponseSchema,
  listQuerySchema,
  ownInvitationListResponseSchema,
  ownInvitationParamsSchema,
  parseListCursor,
} from '@ciphermesh/validation';
import type { InvitationService } from '../rooms/invitations';
import { actorOf, defineRoute, type AnyRoute } from './registry';

/**
 * The invitee's own invitations (SS-03, Phase 6, CM-T035, DF-06). These are self-service routes:
 * the invitee is not a member yet, so no room route can serve them. Every invitation is loaded by
 * its ID AND invitee = session user (OL-11); another user's invitation is the same 404 as an
 * unknown ID. No route takes a bearer token or link: invitations are in-app only.
 */
const iso = (date: Date): string => date.toISOString();

export function invitationRoutes(invitations: InvitationService): readonly AnyRoute[] {
  return [
    defineRoute({
      method: 'GET',
      path: '/invitations',
      action: 'SS-03-INVITATION-LIST',
      access: { kind: 'authenticated' },
      query: listQuerySchema,
      body: undefined,
      response: ownInvitationListResponseSchema,
      handler: async (ctx) => {
        const after = ctx.query.cursor === undefined ? undefined : parseListCursor(ctx.query.cursor);
        const items = await invitations.listOwnInvitations(actorOf(ctx), after, INVITATION_LIST_PAGE_SIZE + 1);
        const visible = items.slice(0, INVITATION_LIST_PAGE_SIZE);
        const last = visible.at(-1);
        return {
          status: 200,
          body: {
            invitations: visible.map((i) => ({
              id: i.id,
              room: i.room,
              invitedBy: i.invitedBy,
              role: i.role,
              status: i.status,
              inviteeKeyId: i.inviteeKeyId,
              expiresAt: iso(i.expiresAt),
              createdAt: iso(i.createdAt),
            })),
            nextCursor:
              items.length > INVITATION_LIST_PAGE_SIZE && last !== undefined
                ? formatListCursor(last.createdAt, last.id)
                : null,
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/invitations/:invitationId/accept',
      action: 'SS-03-INVITATION-ACCEPT',
      access: { kind: 'authenticated' },
      params: ownInvitationParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: invitationAcceptedResponseSchema,
      handler: async (ctx) => {
        const accepted = await invitations.acceptInvitation(actorOf(ctx), ctx.params.invitationId, ctx.request);
        return { status: 200, body: { roomId: accepted.roomId, role: accepted.role, status: 'ACCEPTED' as const } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/invitations/:invitationId/decline',
      action: 'SS-03-INVITATION-DECLINE',
      access: { kind: 'authenticated' },
      params: ownInvitationParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: invitationClosedResponseSchema,
      handler: async (ctx) => {
        await invitations.declineInvitation(actorOf(ctx), ctx.params.invitationId, ctx.request);
        return { status: 200, body: { status: 'DECLINED' as const } };
      },
    }),
  ];
}
