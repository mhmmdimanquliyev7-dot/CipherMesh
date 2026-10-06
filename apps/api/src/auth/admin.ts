import { ErrorCode } from '@ciphermesh/shared';
import type { AuthStore } from '../db/auth-store';
import type { AccountTransactionStores } from '../db/room-store';
import { HttpError } from '../http/errors';
import type { SecurityEventSink } from './security-events';
import type { Actor, RequestMeta } from './sessions';

/**
 * Platform administration (CM-T022, PA-03). PLATFORM_ADMIN manages accounts only: it grants no
 * room access, no membership and no key material (PA-05). The one room consequence is PA-03's:
 * disabling an account suspends its room memberships and sets those rooms to REKEY_REQUIRED, in
 * the same transaction (Phase 5). PLATFORM_ADMIN itself is granted only by the server-side CLI
 * (src/cli/platform-admin.ts), never through the API.
 */
export interface AdminDependencies {
  readonly transaction: <T>(fn: (stores: AccountTransactionStores) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

/** The CLI's platform-role change touches accounts and sessions only. */
export interface PlatformRoleDependencies {
  readonly transaction: <T>(fn: (store: AuthStore) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');

export function createAdminService(deps: AdminDependencies) {
  return {
    /**
     * Disables an account in one transaction: status DISABLED, all sessions revoked, and every
     * ACTIVE room membership SUSPENDED with its rooms set to REKEY_REQUIRED (MEMBER_SUSPENDED,
     * key-lifecycle R3, INV-07). The session check also refuses disabled accounts on every
     * request, so the effect is immediate. Not allowed for oneself or for the last active platform
     * administrator. Repeating it is harmless: it suspends whatever is still ACTIVE.
     */
    async disableAccount(actor: Actor, userId: string, meta: RequestMeta): Promise<void> {
      if (userId === actor.userId) {
        throw new HttpError(403, ErrorCode.FORBIDDEN, 'Administrators cannot disable their own account');
      }
      const now = deps.clock();
      const outcome = await deps.transaction(async ({ auth, rooms }) => {
        const admins = await auth.lockActiveAdmins();
        const target = await auth.findUserStatus(userId);
        if (target === null) throw notFound();
        if (target.platformRole === 'PLATFORM_ADMIN' && target.status === 'ACTIVE' && admins.length <= 1) {
          throw new HttpError(403, ErrorCode.FORBIDDEN, 'The last platform administrator cannot be disabled');
        }
        // The user row is updated before the memberships are read: a room creation by this user
        // holds the row lock until it commits, so its OWNER membership is suspended here too.
        await auth.setUserStatus(userId, 'DISABLED');
        const revoked = await auth.revokeUserSessions(userId, 'ACCOUNT_DISABLED', now);
        const suspended = await rooms.suspendMemberships(userId, actor.userId, now);
        return { revoked, suspended };
      });
      deps.events.record({
        name: 'ACCOUNT_DISABLED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        targetUserId: userId,
        requestId: meta.requestId,
        details: { sessionsRevoked: outcome.revoked, membershipsSuspended: outcome.suspended.length },
      });
      for (const room of outcome.suspended) {
        deps.events.record({
          name: 'MEMBER_SUSPENDED',
          outcome: 'SUCCESS',
          actorUserId: actor.userId,
          targetUserId: userId,
          requestId: meta.requestId,
          details: { roomId: room.roomId },
        });
        if (room.rekeyNewlyRequired) {
          deps.events.record({
            name: 'REKEY_REQUIRED',
            outcome: 'SUCCESS',
            actorUserId: actor.userId,
            requestId: meta.requestId,
            details: { roomId: room.roomId, reason: 'MEMBER_SUSPENDED' },
          });
        }
      }
    },

    /**
     * Re-enables an account. Suspended memberships stay SUSPENDED: their envelopes are gone, and
     * an OWNER or ADMIN reinstates the member by re-sharing keys (AZ-14, Phase 6).
     */
    async enableAccount(actor: Actor, userId: string, meta: RequestMeta): Promise<void> {
      await deps.transaction(async ({ auth }) => {
        const target = await auth.findUserStatus(userId);
        if (target === null) throw notFound();
        await auth.setUserStatus(userId, 'ACTIVE');
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
  deps: PlatformRoleDependencies,
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
