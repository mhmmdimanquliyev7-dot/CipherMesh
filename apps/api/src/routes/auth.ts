import { PREAUTH_COOKIE, SESSION_COOKIE } from '@ciphermesh/shared';
import {
  adminUserRequestSchema,
  changePasswordRequestSchema,
  emptyBodySchema,
  emptyQuerySchema,
  loginRequestSchema,
  mfaVerifyRequestSchema,
  recoveryCodesResponseSchema,
  recoveryLoginRequestSchema,
  registerRequestSchema,
  registerResponseSchema,
  sessionInfoResponseSchema,
  sessionListResponseSchema,
  sessionRevokeRequestSchema,
  statusOkResponseSchema,
  stepUpRequestSchema,
  stepUpResponseSchema,
  totpConfirmRequestSchema,
  totpEnrollResponseSchema,
  z,
} from '@ciphermesh/validation';
import type { AdminService } from '../auth/admin';
import { clearAuthCookie, serializeAuthCookie } from '../auth/cookies';
import type { AuthService } from '../auth/service';
import type { IssuedSession } from '../auth/sessions';
import { actorOf, defineRoute, type AnyRoute, type PublicRouteEntry } from './registry';

/**
 * Authentication routes (Phase 3). Public entries need a security review, like every public route
 * (authorization model section 6). All state-changing routes pass the same-origin gate, the JSON
 * content-type gate and the custom header check before they reach a handler (INV-19), and so do
 * registration, login and the MFA step (login CSRF, session-and-csrf.md section 8.3).
 */
export const AUTH_PUBLIC_ROUTES: readonly PublicRouteEntry[] = Object.freeze([
  { method: 'POST', path: '/auth/register' },
  { method: 'POST', path: '/auth/login' },
  { method: 'POST', path: '/auth/mfa/verify' },
  { method: 'POST', path: '/auth/mfa/recovery' },
]);

const sessionCookie = (session: IssuedSession): string =>
  serializeAuthCookie(SESSION_COOKIE, session.token, session.maxAgeSeconds);

const recoveryLoginResponseSchema = z.strictObject({
  status: z.literal('authenticated'),
  recoveryCodesRemaining: z.number().int().min(0).max(10),
});

export function authRoutes(auth: AuthService, admin: AdminService): readonly AnyRoute[] {
  return [
    defineRoute({
      method: 'POST',
      path: '/auth/register',
      action: 'AUTH-REGISTER',
      access: { kind: 'public', justification: 'Account creation; rate-limited per client address (CM-T015)' },
      query: emptyQuerySchema,
      body: registerRequestSchema,
      response: registerResponseSchema,
      handler: async ({ body, request }) => {
        await auth.register(body, request);
        return { status: 201, body: { status: 'registered' as const } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/auth/login',
      action: 'AUTH-LOGIN',
      access: { kind: 'public', justification: 'Password login; throttled per address and per account (CM-T016)' },
      query: emptyQuerySchema,
      body: loginRequestSchema,
      response: z.strictObject({ status: z.enum(['authenticated', 'mfa_required']) }),
      handler: async ({ body, request }) => {
        // Any session or pre-authentication cookie sent with the request is ignored: login always
        // issues new state, so a planted token is never promoted (session fixation, T-08).
        const outcome = await auth.login(body, request);
        if (outcome.kind === 'mfa_required') {
          return {
            status: 200,
            body: { status: 'mfa_required' as const },
            cookies: [serializeAuthCookie(PREAUTH_COOKIE, outcome.preAuthToken, outcome.maxAgeSeconds)],
          };
        }
        return {
          status: 200,
          body: { status: 'authenticated' as const },
          cookies: [sessionCookie(outcome.session), clearAuthCookie(PREAUTH_COOKIE)],
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/auth/mfa/verify',
      action: 'AUTH-MFA-VERIFY',
      access: { kind: 'public', justification: 'Second login step; needs the pre-authentication cookie (CM-T019)' },
      query: emptyQuerySchema,
      body: mfaVerifyRequestSchema,
      response: z.strictObject({ status: z.literal('authenticated') }),
      handler: async ({ body, request }) => {
        const { session } = await auth.completeMfa(
          request.cookie(PREAUTH_COOKIE),
          { kind: 'totp', code: body.code },
          request,
        );
        return {
          status: 200,
          body: { status: 'authenticated' as const },
          cookies: [sessionCookie(session), clearAuthCookie(PREAUTH_COOKIE)],
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/auth/mfa/recovery',
      action: 'AUTH-MFA-RECOVERY',
      access: { kind: 'public', justification: 'Second login step with a recovery code (CM-T019)' },
      query: emptyQuerySchema,
      body: recoveryLoginRequestSchema,
      response: recoveryLoginResponseSchema,
      handler: async ({ body, request }) => {
        const result = await auth.completeMfa(
          request.cookie(PREAUTH_COOKIE),
          { kind: 'recovery', code: body.recoveryCode },
          request,
        );
        return {
          status: 200,
          body: { status: 'authenticated' as const, recoveryCodesRemaining: result.recoveryCodesRemaining ?? 0 },
          cookies: [sessionCookie(result.session), clearAuthCookie(PREAUTH_COOKIE)],
        };
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/auth/session',
      action: 'SS-01-SESSION',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: undefined,
      response: sessionInfoResponseSchema,
      // Reads only; the session's activity timestamp is bookkeeping, not a user-visible change.
      handler: (ctx) => {
        const actor = actorOf(ctx);
        const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());
        return {
          status: 200,
          body: {
            user: {
              id: actor.user.id,
              email: actor.user.email,
              displayName: actor.user.displayName,
              platformRole: actor.user.platformRole,
              mfaEnabled: actor.user.mfaEnabled,
            },
            session: {
              authenticatedAt: actor.session.authenticatedAt.toISOString(),
              mfaVerifiedAt: iso(actor.session.mfaVerifiedAt),
              stepUpAt: iso(actor.session.stepUpAt),
              idleExpiresAt: actor.session.idleExpiresAt.toISOString(),
              absoluteExpiresAt: actor.session.absoluteExpiresAt.toISOString(),
            },
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/auth/logout',
      action: 'SS-01-LOGOUT',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: statusOkResponseSchema,
      handler: async (ctx) => {
        await auth.logout(actorOf(ctx), ctx.request);
        return { status: 200, body: { status: 'ok' as const }, cookies: [clearAuthCookie(SESSION_COOKIE)] };
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/auth/sessions',
      action: 'SS-01-SESSIONS-LIST',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: undefined,
      response: sessionListResponseSchema,
      handler: async (ctx) => {
        const sessions = await auth.listSessions(actorOf(ctx));
        return {
          status: 200,
          body: {
            sessions: sessions.map((s) => ({
              id: s.id,
              current: s.current,
              createdAt: s.createdAt.toISOString(),
              lastSeenAt: s.lastSeenAt.toISOString(),
              userAgent: s.userAgent,
              ipAddress: s.ipAddress,
            })),
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/auth/sessions/revoke',
      action: 'SS-01-SESSION-REVOKE',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: sessionRevokeRequestSchema,
      response: statusOkResponseSchema,
      handler: async (ctx) => {
        const { current } = await auth.revokeSession(actorOf(ctx), ctx.body.sessionId, ctx.request);
        return {
          status: 200,
          body: { status: 'ok' as const },
          ...(current ? { cookies: [clearAuthCookie(SESSION_COOKIE)] } : {}),
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/auth/sessions/revoke-others',
      action: 'SS-01-SESSIONS-REVOKE-OTHERS',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: statusOkResponseSchema,
      handler: async (ctx) => {
        await auth.revokeOtherSessions(actorOf(ctx), ctx.request);
        return { status: 200, body: { status: 'ok' as const } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/auth/step-up',
      action: 'SS-01-STEP-UP',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: stepUpRequestSchema,
      response: stepUpResponseSchema,
      handler: async (ctx) => {
        const { session, stepUpAt } = await auth.stepUp(actorOf(ctx), ctx.body, ctx.request);
        return {
          status: 200,
          body: { status: 'ok' as const, stepUpAt: stepUpAt.toISOString() },
          cookies: [sessionCookie(session)],
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/auth/password',
      action: 'SS-01-PASSWORD',
      access: { kind: 'authenticated' },
      query: emptyQuerySchema,
      body: changePasswordRequestSchema,
      response: statusOkResponseSchema,
      handler: async (ctx) => {
        const session = await auth.changePassword(actorOf(ctx), ctx.body, ctx.request);
        return { status: 200, body: { status: 'ok' as const }, cookies: [sessionCookie(session)] };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/mfa/totp/enroll',
      action: 'SS-01-MFA-ENROLL',
      access: { kind: 'authenticated', requires: { stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: totpEnrollResponseSchema,
      handler: async (ctx) => {
        const enrollment = await auth.startTotpEnrollment(actorOf(ctx), ctx.request);
        return { status: 200, body: { otpauthUri: enrollment.uri, secret: enrollment.base32 } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/mfa/totp/confirm',
      action: 'SS-01-MFA-CONFIRM',
      access: { kind: 'authenticated', requires: { stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: totpConfirmRequestSchema,
      response: recoveryCodesResponseSchema,
      handler: async (ctx) => {
        const result = await auth.confirmTotpEnrollment(actorOf(ctx), ctx.body.code, ctx.request);
        return {
          status: 200,
          body: { recoveryCodes: result.recoveryCodes },
          cookies: [sessionCookie(result.session)],
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/mfa/totp/disable',
      action: 'SS-01-MFA-DISABLE',
      access: { kind: 'authenticated', requires: { stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: statusOkResponseSchema,
      handler: async (ctx) => {
        const session = await auth.disableTotp(actorOf(ctx), ctx.request);
        return { status: 200, body: { status: 'ok' as const }, cookies: [sessionCookie(session)] };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/mfa/recovery-codes/regenerate',
      action: 'SS-01-RECOVERY-REGENERATE',
      access: { kind: 'authenticated', requires: { stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: recoveryCodesResponseSchema,
      handler: async (ctx) => {
        const codes = await auth.regenerateRecoveryCodes(actorOf(ctx), ctx.request);
        return { status: 200, body: { recoveryCodes: codes } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/admin/users/disable',
      action: 'PA-03-DISABLE',
      access: { kind: 'authenticated', requires: { platformAdmin: true, stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: adminUserRequestSchema,
      response: statusOkResponseSchema,
      handler: async (ctx) => {
        await admin.disableAccount(actorOf(ctx), ctx.body.userId, ctx.request);
        return { status: 200, body: { status: 'ok' as const } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/admin/users/enable',
      action: 'PA-03-ENABLE',
      access: { kind: 'authenticated', requires: { platformAdmin: true, stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: adminUserRequestSchema,
      response: statusOkResponseSchema,
      handler: async (ctx) => {
        await admin.enableAccount(actorOf(ctx), ctx.body.userId, ctx.request);
        return { status: 200, body: { status: 'ok' as const } };
      },
    }),
  ];
}
