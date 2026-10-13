import { toBase64Url } from '@ciphermesh/crypto/identity';
import {
  emptyBodySchema,
  emptyQuerySchema,
  rekeyCancelledResponseSchema,
  rekeyFinalizedResponseSchema,
  rekeyFinalizeRequestSchema,
  rekeyOperationParamsSchema,
  rekeyStartedResponseSchema,
  reshareRequestSchema,
  reshareResponseSchema,
  roomKeyStateResponseSchema,
  roomLeftResponseSchema,
  roomMemberParamsSchema,
  roomParamsSchema,
} from '@ciphermesh/validation';
import type { RekeyOperationRecord } from '../db/rekey-store';
import type { RekeyService } from '../rooms/rekey';
import { identityToWire } from '../rooms/statements';
import { actorOf, defineRoute, roomOf, type AnyRoute } from './registry';

/**
 * Key rotation routes (Phase 11, CM-T050 to CM-T053, ADR-013, DF-10). Every route is a room route:
 * the registry authorizes it centrally against the caller's database-loaded membership and the
 * room's policy before the handler runs (INV-05, INV-08), and the service decides again on locked
 * state. Operations are addressed by the room AND the operation ID (OL-13). No route accepts or
 * returns room key material: the finalize body carries the public commitment, the signed
 * statement and RSA-OAEP envelopes, and the start response public identities and grants only.
 */

const iso = (date: Date): string => date.toISOString();

const operationView = (operation: RekeyOperationRecord) => ({
  id: operation.id,
  mode: operation.mode,
  status: operation.status,
  startedByUserId: operation.startedById,
  baseVersion: operation.baseVersion,
  targetVersion: operation.targetVersion,
  leaseExpiresAt: iso(operation.leaseExpiresAt),
  createdAt: iso(operation.createdAt),
});

export function rekeyRoutes(rekey: RekeyService): readonly AnyRoute[] {
  return [
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/rekey-operations/current',
      action: 'AZ-15-KEY-STATE',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: undefined,
      response: roomKeyStateResponseSchema,
      handler: async (ctx) => {
        const state = await rekey.keyState(actorOf(ctx), roomOf(ctx));
        return {
          status: 200,
          body: {
            keyState: state.keyState,
            rekeyReasons: state.rekeyReasons,
            rekeyRequiredSince: state.rekeyRequiredSince === null ? null : iso(state.rekeyRequiredSince),
            currentKeyVersion: state.currentKeyVersion,
            cryptoperiodEndsAt: state.cryptoperiodEndsAt === null ? null : iso(state.cryptoperiodEndsAt),
            cryptoperiodReminder: state.cryptoperiodReminder,
            operation: state.operation === null ? null : operationView(state.operation),
            membersNeedingKeys: state.membersNeedingKeys,
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/rekey-operations',
      action: 'AZ-13-REKEY-START',
      // PC-03: starting a rekey is a sensitive operation (step-up within 15 minutes in RESTRICTED).
      access: { kind: 'room', requires: { sensitive: 'START_REKEY' } },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: rekeyStartedResponseSchema,
      handler: async (ctx) => {
        const started = await rekey.startRekey(actorOf(ctx), roomOf(ctx), ctx.request);
        return {
          status: 201,
          body: {
            operation: operationView(started.operation),
            recipients: started.recipients.map((r) => ({
              userId: r.userId,
              displayName: r.displayName,
              kind: r.kind,
              identity: { ...identityToWire(r.identity), suite: 'CM1' as const },
            })),
            grants: started.grants.map((g) => ({
              subjectUserId: g.subjectUserId,
              subjectKeyId: g.subjectKeyId,
              role: g.role,
              grantorUserId: g.grantorUserId,
              grantorKeyId: g.grantorKeyId,
              signature: toBase64Url(g.signature),
            })),
            identities: started.identities.map((i) => ({ ...identityToWire(i), suite: 'CM1' as const })),
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/rekey-operations/:operationId/finalize',
      action: 'AZ-13-REKEY-FINALIZE',
      access: { kind: 'room' },
      params: rekeyOperationParamsSchema,
      query: emptyQuerySchema,
      body: rekeyFinalizeRequestSchema,
      response: rekeyFinalizedResponseSchema,
      handler: async (ctx) => {
        const done = await rekey.finalizeRekey(
          actorOf(ctx),
          roomOf(ctx),
          ctx.params.operationId,
          ctx.body,
          ctx.request,
        );
        return {
          status: 200,
          body: { operationId: done.operationId, keyVersion: done.keyVersion, completedAt: iso(done.completedAt) },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/rekey-operations/:operationId/cancel',
      action: 'AZ-13-REKEY-CANCEL',
      access: { kind: 'room' },
      params: rekeyOperationParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: rekeyCancelledResponseSchema,
      handler: async (ctx) => {
        const result = await rekey.cancelRekey(actorOf(ctx), roomOf(ctx), ctx.params.operationId, ctx.request);
        return {
          status: 200,
          body: { operationId: ctx.params.operationId, status: 'CANCELLED' as const, keyState: result.keyState },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/leave',
      action: 'AZ-11-LEAVE',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: roomLeftResponseSchema,
      handler: async (ctx) => {
        await rekey.leaveRoom(actorOf(ctx), roomOf(ctx), ctx.request);
        return { status: 200, body: { status: 'LEFT' as const, rekeyRequired: true as const } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/members/:userId/reshare',
      action: 'AZ-14-RESHARE',
      // "Same checks as invitations" (authorization model AZ-14): PC-03 as for inviting.
      access: { kind: 'room', requires: { sensitive: 'INVITE' } },
      params: roomMemberParamsSchema,
      query: emptyQuerySchema,
      body: reshareRequestSchema,
      response: reshareResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: await rekey.reshareKeys(actorOf(ctx), roomOf(ctx), ctx.params.userId, ctx.body, ctx.request),
      }),
    }),
  ];
}
