import { toBase64Url } from '@ciphermesh/crypto/identity';
import { SECRET_LIST_PAGE_SIZE } from '@ciphermesh/shared';
import {
  emptyBodySchema,
  emptyQuerySchema,
  formatListCursor,
  parseListCursor,
  roomParamsSchema,
  secretCreatedResponseSchema,
  secretCreateRequestSchema,
  secretListQuerySchema,
  secretListResponseSchema,
  secretParamsSchema,
  secretRevealResponseSchema,
  secretRevokedResponseSchema,
} from '@ciphermesh/validation';
import type { RoomStore } from '../db/room-store';
import type { SecretService, SecretView } from '../secrets/service';
import { actorOf, defineRoute, roomOf, type AnyRoute, type RoomResourceInput } from './registry';

/**
 * Recipient-bound secret routes (Phase 9, CM-T043, CM-T044; DF-09). Every route is a room route:
 * the registry authorizes it centrally against the caller's database-loaded membership before the
 * handler runs (OL-01, INV-05), and secrets are loaded by secret ID AND room ID (OL-02). No route
 * accepts or returns secret text or a SEK; only the reveal returns ciphertext, to the recipient,
 * from the transaction that burns it (OL-06, INV-13).
 *
 *   GET  /rooms/{roomId}/secrets                     AZ-32  metadata the caller may see (OL-14)
 *   POST /rooms/{roomId}/secrets                     AZ-23  one secret for one ACTIVE member
 *   POST /rooms/{roomId}/secrets/{secretId}/reveal   AZ-24  the recipient only; at most once with burn
 *   POST /rooms/{roomId}/secrets/{secretId}/revoke   AZ-25  ACTIVE secrets; own secrets for MEMBERs
 *
 * There is deliberately no GET for one secret and no GET that releases anything: a link preview,
 * prefetch or crawler cannot consume a secret (DF-09).
 */

/** The explicit projection of a secret's metadata. */
function metadataView(secret: SecretView) {
  return {
    id: secret.id,
    senderId: secret.senderId,
    recipientUserId: secret.recipientUserId,
    recipientKeyId: secret.recipientKeyId,
    status: secret.status,
    burnAfterReading: secret.burnAfterReading,
    expiresAt: secret.expiresAt.toISOString(),
    createdAt: secret.createdAt.toISOString(),
    revealedAt: secret.revealedAt === null ? null : secret.revealedAt.toISOString(),
    destroyedAt: secret.destroyedAt === null ? null : secret.destroyedAt.toISOString(),
  };
}

export function secretRoutes(secrets: SecretService, store: RoomStore): readonly AnyRoute[] {
  // OL-02: the secret is loaded by its ID and the room ID. The stored recipient decides AZ-24
  // (OL-06) and the stored sender decides `own` for AZ-25 (OL-04).
  const recipientResource = async ({ room, params }: RoomResourceInput<{ secretId: string }, unknown, unknown>) => {
    const secret = await store.findRoomSecret(room.roomId, params.secretId);
    return secret === null ? null : { roomId: secret.roomId, recipientUserId: secret.recipientUserId };
  };
  const senderResource = async ({ room, params }: RoomResourceInput<{ secretId: string }, unknown, unknown>) => {
    const secret = await store.findRoomSecret(room.roomId, params.secretId);
    return secret === null ? null : { roomId: secret.roomId, createdById: secret.senderId };
  };

  return [
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/secrets',
      action: 'AZ-32-SECRET-LIST',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: secretListQuerySchema,
      body: undefined,
      response: secretListResponseSchema,
      handler: async (ctx) => {
        const after = ctx.query.cursor === undefined ? undefined : parseListCursor(ctx.query.cursor);
        const page = await secrets.listSecrets(actorOf(ctx), roomOf(ctx), after, SECRET_LIST_PAGE_SIZE + 1);
        const visible = page.slice(0, SECRET_LIST_PAGE_SIZE);
        const last = visible.at(-1);
        return {
          status: 200,
          body: {
            secrets: visible.map(metadataView),
            nextCursor:
              page.length > SECRET_LIST_PAGE_SIZE && last !== undefined
                ? formatListCursor(last.createdAt, last.id)
                : null,
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/secrets',
      action: 'AZ-23-SECRET-CREATE',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: secretCreateRequestSchema,
      response: secretCreatedResponseSchema,
      handler: async (ctx) => ({
        status: 201,
        body: { secret: metadataView(await secrets.createSecret(actorOf(ctx), roomOf(ctx), ctx.body, ctx.request)) },
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/secrets/:secretId/reveal',
      action: 'AZ-24-SECRET-REVEAL',
      access: { kind: 'room', requires: { sensitive: 'SECRET_REVEAL' }, resource: recipientResource },
      params: secretParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: secretRevealResponseSchema,
      handler: async (ctx) => {
        const { view, released } = await secrets.revealSecret(
          actorOf(ctx),
          roomOf(ctx),
          ctx.params.secretId,
          ctx.request,
        );
        return {
          status: 200,
          body: {
            secret: metadataView(view),
            ciphertext: {
              suite: 'CM1' as const,
              wrappedSek: toBase64Url(released.wrappedSek),
              payloadIv: toBase64Url(released.payloadIv),
              ciphertext: toBase64Url(released.payloadCiphertext),
            },
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/secrets/:secretId/revoke',
      action: 'AZ-25-SECRET-REVOKE',
      access: { kind: 'room', resource: senderResource },
      params: secretParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: secretRevokedResponseSchema,
      handler: async (ctx) => {
        await secrets.revokeSecret(actorOf(ctx), roomOf(ctx), ctx.params.secretId, ctx.request);
        return { status: 200, body: { status: 'REVOKED' as const } };
      },
    }),
  ];
}
