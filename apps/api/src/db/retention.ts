import type { PrismaClient } from '../generated/prisma/client';

/**
 * Retention for authentication data (data-model section 5, CM-T017, CM-T018). Runs as the worker
 * role (cm_worker), which holds DELETE on these tables; the API role does not. Expiry is always
 * enforced at read time; this job only reclaims space and limits how long personal data
 * (IP addresses, user agents) is kept.
 */
export const RETENTION = Object.freeze({
  /** Sessions are deleted 30 days after they ended (revocation or expiry). */
  sessionsAfterEndDays: 30,
  /** Pre-authentication challenges are deleted one day after they expired. */
  challengesAfterExpiryDays: 1,
  /** Login attempts are kept for 90 days (data-model 4.4). */
  loginAttemptsDays: 90,
});

const DAY = 24 * 60 * 60_000;

export async function runAuthRetention(
  prisma: PrismaClient,
  now: Date,
): Promise<{ sessions: number; challenges: number; loginAttempts: number }> {
  const sessionCutoff = new Date(now.getTime() - RETENTION.sessionsAfterEndDays * DAY);
  const sessions = await prisma.session.deleteMany({
    where: {
      OR: [
        { revokedAt: { lt: sessionCutoff } },
        { absoluteExpiresAt: { lt: sessionCutoff } },
        { idleExpiresAt: { lt: sessionCutoff } },
      ],
    },
  });
  const challenges = await prisma.authChallenge.deleteMany({
    where: { expiresAt: { lt: new Date(now.getTime() - RETENTION.challengesAfterExpiryDays * DAY) } },
  });
  const loginAttempts = await prisma.loginAttempt.deleteMany({
    where: { occurredAt: { lt: new Date(now.getTime() - RETENTION.loginAttemptsDays * DAY) } },
  });
  return { sessions: sessions.count, challenges: challenges.count, loginAttempts: loginAttempts.count };
}
