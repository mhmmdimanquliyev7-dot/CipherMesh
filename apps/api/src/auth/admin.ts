import { ErrorCode } from '@ciphermesh/shared';
import type { AuthStore } from '../db/auth-store';
import { HttpError } from '../http/errors';
import type { SecurityEventSink } from './security-events';
import type { Actor, RequestMeta } from './sessions';

/**
 * Platform administration (CM-T022, PA-03). PLATFORM_ADMIN manages accounts only: it grants no
 * room access, no membership and no key material (PA-05), and nothing here touches rooms.
 * PLATFORM_ADMIN itself is granted only by the server-side CLI (src/cli/platform-admin.ts),
 * never through the API.
 */
export interface AdminDependencies {
  readonly transaction: <T>(fn: (store: AuthStore) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');

export function createAdminService(deps: AdminDependencies) {
  return {
    /**
     * Disables an account and revokes all of its sessions in one transaction. The session check
     * also refuses disabled accounts on every request, so the effect is immediate. Not allowed for
     * oneself or for the last active platform administrator. Room memberships become SUSPENDED once
     * rooms exist (Phase 5, integration test in Phase 11).
     */
    async disableAccount(actor: Actor, userId: string, meta: RequestMeta): Promise<void> {
      if (userId === actor.userId) {
        throw new HttpError(403, ErrorCode.FORBIDDEN, 'Administrators cannot disable their own account');
      }
      const now = deps.clock();
      const revoked = await deps.transaction(async (tx) => {
        const admins = await tx.lockActiveAdmins();
        const target = await tx.findUserStatus(userId);
        if (target === null) throw notFound();
        if (target.platformRole === 'PLATFORM_ADMIN' && target.status === 'ACTIVE' && admins.length <= 1) {
          throw new HttpError(403, ErrorCode.FORBIDDEN, 'The last platform administrator cannot be disabled');
        }
        await tx.setUserStatus(userId, 'DISABLED');
        return tx.revokeUserSessions(userId, 'ACCOUNT_DISABLED', now);
      });
      deps.events.record({
        name: 'ACCOUNT_DISABLED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        targetUserId: userId,
        requestId: meta.requestId,
        details: { sessionsRevoked: revoked },
      });
    },

    async enableAccount(actor: Actor, userId: string, meta: RequestMeta): Promise<void> {
      await deps.transaction(async (tx) => {
        const target = await tx.findUserStatus(userId);
        if (target === null) throw notFound();
        await tx.setUserStatus(userId, 'ACTIVE');
      });
      deps.events.record({
        name: 'ACCOUNT_ENABLED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        targetUserId: userId,
        requestId: meta.requestId,
      });
    },
  };
}

export type AdminService = ReturnType<typeof createAdminService>;

/**
 * Server-side role change (CLI only). Granting requires MFA on the target (authorization-model.md:
 * platform administrators must use MFA). Revoking the last active administrator is refused.
 * Every change revokes all sessions of the account (session-and-csrf.md section 4).
 */
export async function changePlatformRole(
  deps: AdminDependencies,
  email: string,
  role: 'USER' | 'PLATFORM_ADMIN',
): Promise<'changed' | 'unchanged'> {
  const now = deps.clock();
  const outcome = await deps.transaction(async (tx) => {
    const admins = await tx.lockActiveAdmins();
    const user = await tx.findUserByEmail(email);
    if (user === null) throw new Error('No account with that email address');
    if (role === 'PLATFORM_ADMIN' && !user.mfaEnabled) {
      throw new Error(
        'The account must enable multi-factor authentication before it can become a platform administrator',
      );
    }
    if (role === 'USER' && user.platformRole === 'PLATFORM_ADMIN' && admins.length <= 1 && admins.includes(user.id)) {
      throw new Error('The last active platform administrator cannot be removed');
    }
    if (!(await tx.setPlatformRole(user.id, role))) return { changed: false, userId: user.id, revoked: 0 };
    const revoked = await tx.revokeUserSessions(user.id, 'PLATFORM_ROLE_CHANGED', now);
    return { changed: true, userId: user.id, revoked };
  });
  if (outcome.changed) {
    deps.events.record({
      name: 'PLATFORM_ROLE_CHANGED',
      outcome: 'SUCCESS',
      targetUserId: outcome.userId,
      details: { role, sessionsRevoked: outcome.revoked, via: 'cli' },
    });
  }
  return outcome.changed ? 'changed' : 'unchanged';
}
