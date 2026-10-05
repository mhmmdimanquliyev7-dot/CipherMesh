import { SESSION_COOKIE } from '@ciphermesh/shared';
import {
  directoryEntrySchema,
  directoryLookupRequestSchema,
  emptyQuerySchema,
  vaultCreatedResponseSchema,
  vaultCreateRequestSchema,
  vaultResetRequestSchema,
  vaultResetResponseSchema,
  vaultResponseSchema,
  vaultRewrapRequestSchema,
  vaultRewrapResponseSchema,
} from '@ciphermesh/validation';
import { serializeAuthCookie } from '../auth/cookies';
import type { VaultService } from '../vault/service';
import { actorOf, defineRoute, type AnyRoute } from './registry';

/**
 * Vault and public-key directory routes (Phase 4, CM-T025 to CM-T028). All require a session; the
 * owner of every vault operation is the session's user, never a request field (OL-10). Setup,
 * re-wrap and reset change what protects the identity's private keys, so they require a recent
 * step-up (account password, plus TOTP when enabled); a reset destroys the old identity and needs
 * the strict window. The Vault Passphrase is never part of any request: it stays in the browser,
 * and these strict request schemas would reject any extra field (INV-01).
 */
export function vaultRoutes(vault: VaultService): readonly AnyRoute[] {
  return [
    defineRoute({
      method: 'GET',
      path: '/vault',
      action: 'SS-02-VAULT-READ',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: undefined,
      response: vaultResponseSchema,
      handler: async (ctx) => {
        const result = await vault.getVault(actorOf(ctx));
        return {
          status: 200,
          body: {
            vault: result.vault,
            createdAt: result.createdAt.toISOString(),
            rewrappedAt: result.rewrappedAt?.toISOString() ?? null,
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/vault',
      action: 'SS-02-VAULT-CREATE',
      access: { kind: 'authenticated', requires: { stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: vaultCreateRequestSchema,
      response: vaultCreatedResponseSchema,
      handler: async (ctx) => {
        const created = await vault.createVault(actorOf(ctx), ctx.body, ctx.request);
        return {
          status: 201,
          body: { keyId: created.keyId, fingerprint: created.fingerprint, createdAt: created.createdAt.toISOString() },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/vault/rewrap',
      action: 'SS-02-VAULT-REWRAP',
      access: { kind: 'authenticated', requires: { stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: vaultRewrapRequestSchema,
      response: vaultRewrapResponseSchema,
      handler: async (ctx) => {
        const { rewrappedAt } = await vault.rewrapVault(actorOf(ctx), ctx.body, ctx.request);
        return { status: 200, body: { status: 'ok' as const, rewrappedAt: rewrappedAt.toISOString() } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/vault/reset',
      action: 'SS-02-VAULT-RESET',
      access: { kind: 'authenticated', requires: { stepUp: 'strict' } },
      query: emptyQuerySchema,
      body: vaultResetRequestSchema,
      response: vaultResetResponseSchema,
      handler: async (ctx) => {
        const reset = await vault.resetVault(actorOf(ctx), ctx.body.supersedesKeyId, ctx.body.vault, ctx.request);
        return {
          status: 201,
          body: {
            keyId: reset.keyId,
            fingerprint: reset.fingerprint,
            createdAt: reset.createdAt.toISOString(),
            otherSessionsRevoked: reset.otherSessionsRevoked,
          },
          cookies: [serializeAuthCookie(SESSION_COOKIE, reset.session.token, reset.session.maxAgeSeconds)],
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/directory/lookup',
      action: 'SS-05-DIRECTORY-LOOKUP',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: directoryLookupRequestSchema,
      response: directoryEntrySchema,
      handler: async (ctx) => ({ status: 200, body: await vault.lookup(actorOf(ctx), ctx.body.email, ctx.request) }),
    }),
  ];
}
