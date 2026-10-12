import type pg from 'pg';
import { expect } from 'vitest';
import type { SecurityEvent } from '../../apps/api/src/auth/security-events';
import type { AuthTestApi } from './auth';
import { vaultOf } from './room-crypto';
import type { Person } from './rooms';

// Helpers for the policy suites (Phase 10, tests/policy). Session ages are moved in the database,
// as cm_api, the way time would move them: the API still decides with its own clock and the stored
// session row. Nothing here changes a policy, a membership or an authorization rule.

const MINUTE = 60_000;

/** Sets the password sign-in time of the person's live sessions `ms` before the API's clock. */
export async function signedInAgo(db: pg.Client, api: AuthTestApi, who: Person, ms: number): Promise<void> {
  const result = await db.query('UPDATE sessions SET authenticated_at = $2 WHERE user_id = $1 AND revoked_at IS NULL', [
    who.userId,
    new Date(api.clock.now().getTime() - ms),
  ]);
  expect(result.rowCount).toBeGreaterThan(0);
}

/** Sets (or clears, with null) the step-up time of the person's live sessions. */
export async function steppedUpAgo(db: pg.Client, api: AuthTestApi, who: Person, ms: number | null): Promise<void> {
  const at = ms === null ? null : new Date(api.clock.now().getTime() - ms);
  const result = await db.query('UPDATE sessions SET step_up_at = $2 WHERE user_id = $1 AND revoked_at IS NULL', [
    who.userId,
    at,
  ]);
  expect(result.rowCount).toBeGreaterThan(0);
}

/** A step-up older than the 15-minute PC-03 window. */
export const STALE_STEP_UP_MS = 16 * MINUTE;

/** The confirmed-fingerprint override a RESTRICTED invitation needs (PC-05). */
export const confirmedFingerprint = (invitee: Person): { confirmedFingerprint: string } => ({
  confirmedFingerprint: vaultOf(invitee).identity.fingerprint,
});

/** The policy refusals recorded since `from` (ROOM_ACCESS_DENIED with a PROFILE_* or policy reason). */
export function policyDenials(api: AuthTestApi, from = 0): { action: unknown; reason: unknown }[] {
  return api.events
    .slice(from)
    .filter((e: SecurityEvent) => e.name === 'ROOM_ACCESS_DENIED')
    .map((e) => ({ action: e.details?.['action'], reason: e.details?.['reason'] }))
    .filter((d) => typeof d.reason === 'string' && /^(PROFILE_|POLICY_)/.test(d.reason));
}

/**
 * Queues requests behind a held lock on the room row, in the given order: holds `SELECT ... FOR
 * UPDATE` on the room, starts each request only after the previous one is waiting (directly or
 * behind another waiter), then releases. PostgreSQL grants the row to the waiters in that order,
 * so the first request commits before the second re-checks, while both passed their gates at the
 * start on the same state. The deadline stays below the API's 5-second transaction limit.
 */
export async function inRoomLockOrder(
  observer: pg.Client,
  locker: pg.Client,
  roomId: string,
  starts: readonly (() => Promise<Response>)[],
): Promise<Response[]> {
  await locker.query('BEGIN');
  const running: Promise<Response>[] = [];
  try {
    await locker.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId]);
    const pid = (await locker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
    for (const start of starts) {
      running.push(start());
      const deadline = Date.now() + 4_000;
      for (;;) {
        const { rows } = await observer.query<{ n: number }>(
          `WITH RECURSIVE waiting(pid) AS (
             SELECT pid FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid))
             UNION
             SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY (pg_blocking_pids(a.pid))
           )
           SELECT count(*)::int AS n FROM waiting`,
          [pid],
        );
        if ((rows[0]?.n ?? 0) >= running.length) break;
        if (Date.now() > deadline) throw new Error(`request ${String(running.length)} did not queue behind the lock`);
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    }
  } finally {
    await locker.query('COMMIT');
  }
  return Promise.all(running);
}

type Response = { readonly status: number; readonly body: Record<string, unknown> };

/**
 * Every row of one room that a request could change, as one string: the room, memberships,
 * invitations, envelopes, key versions, files, notes and secrets. Equal strings mean nothing
 * changed (attack class G of the BOLA suite, applied to policy refusals).
 */
export async function roomSnapshot(db: pg.Client, roomId: string): Promise<string> {
  const parts: unknown[] = [];
  for (const sql of [
    'SELECT * FROM rooms WHERE id = $1',
    'SELECT * FROM room_members WHERE room_id = $1 ORDER BY id',
    'SELECT * FROM invitations WHERE room_id = $1 ORDER BY id',
    'SELECT * FROM key_envelopes WHERE room_id = $1 ORDER BY id',
    'SELECT * FROM room_key_versions WHERE room_id = $1 ORDER BY version',
    'SELECT * FROM encrypted_files WHERE room_id = $1 ORDER BY id',
    'SELECT * FROM encrypted_notes WHERE room_id = $1 ORDER BY id',
    'SELECT * FROM secrets WHERE room_id = $1 ORDER BY id',
  ]) {
    parts.push((await db.query(sql, [roomId])).rows);
  }
  return JSON.stringify(parts, (_key, value: unknown) => (Buffer.isBuffer(value) ? value.toString('base64') : value));
}
