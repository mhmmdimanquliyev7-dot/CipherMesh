import { createVault, vaultRecordToWire } from '@ciphermesh/crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { Database } from '../../apps/api/src/db/client';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { invite, vaultOf } from '../helpers/room-crypto';
import {
  apiDatabase,
  createRoom,
  memberships,
  personWithVault,
  platformAdministrator,
  roomRow,
  stepUp,
  whileLocked,
  type Person,
} from '../helpers/rooms';
import { newPassphrase, runner } from '../helpers/vault';

// Phase 6 (CM-T035) and the Phase 5 handoff: invitation acceptance against every concurrent change
// that could invalidate it. Each test holds the row lock that both transactions need, starts both
// requests, waits until PostgreSQL reports both waiting, and releases the lock, so the two
// transactions really overlap and either may win. The final state must be valid for either order;
// above all, an account disable never misses a membership that an acceptance creates.
let api: AuthTestApi;
let db: pg.Client;
let database: Database;
let platform: Person & { readonly secret: string };

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  database = apiDatabase();
  platform = await platformAdministrator(api, database);
});
afterAll(async () => {
  await api.close();
  await database.close();
  await db.end();
});

const accept = (who: Person, id: string) => who.browser.request('POST', `/invitations/${id}/accept`, {});

/** A room of a new owner with an open invitation for a new invitee. */
async function openInvitation(): Promise<{ owner: Person; invitee: Person; roomId: string; id: string }> {
  const owner = await personWithVault(api, db);
  const invitee = await personWithVault(api, db);
  const roomId = await createRoom(owner);
  const created = await invite(owner, roomId, invitee, 'MEMBER');
  expect(created.status, JSON.stringify(created.body)).toBe(201);
  return { owner, invitee, roomId, id: (created.body['invitation'] as { id: string }).id };
}

async function invitationStatus(id: string): Promise<string | undefined> {
  const { rows } = await db.query<{ status: string }>('SELECT status::text FROM invitations WHERE id = $1', [id]);
  return rows[0]?.status;
}
const membershipOf = async (roomId: string, userId: string) =>
  (await memberships(db, roomId)).filter((m) => m.user_id === userId);

describe('invitation acceptance racing a concurrent change (CM-T035)', () => {
  it('an account disable never leaves the disabled invitee an ACTIVE membership (PA-03)', async () => {
    for (let round = 0; round < 3; round += 1) {
      const { invitee, roomId, id } = await openInvitation();
      await stepUp(api, platform, platform.secret);
      // Both transactions need the invitee's user row: the acceptance to check the account, the
      // disable to change it.
      const [accepted, disabled] = await whileLocked(
        db,
        'SELECT id FROM users WHERE id = $1 FOR UPDATE',
        [invitee.userId],
        () =>
          Promise.all([
            accept(invitee, id),
            platform.browser.request('POST', '/admin/users/disable', { userId: invitee.userId }),
          ]),
      );
      expect(disabled.status).toBe(200);
      expect([200, 401]).toContain(accepted.status);
      const rows = await membershipOf(roomId, invitee.userId);
      expect(rows.filter((m) => m.status === 'ACTIVE')).toEqual([]);
      if (accepted.status === 200) {
        // The acceptance won: the disable then suspended the new membership and locked the room.
        expect(rows.map((m) => m.status)).toEqual(['SUSPENDED']);
        expect((await roomRow(db, roomId)).key_state).toBe('REKEY_REQUIRED');
        const { rows: envelopes } = await db.query(
          'SELECT 1 FROM key_envelopes WHERE room_id = $1 AND recipient_user_id = $2',
          [roomId, invitee.userId],
        );
        expect(envelopes).toEqual([]);
      } else {
        expect(rows).toEqual([]);
        expect(await invitationStatus(id)).toBe('PENDING');
      }
    }
  });

  it('an account disable while the acceptance waits for the room still finds and suspends the new membership', async () => {
    // The acceptance takes the user row before the room. Holding the room lock stops it after that
    // step; a disable started then must wait for it. Without the user-row lock, the disable would
    // finish first and the acceptance would then add an ACTIVE membership for a disabled account.
    const { invitee, roomId, id } = await openInvitation();
    await stepUp(api, platform, platform.secret);
    const locker = await testDatabase(inject('databaseName')).connect('api');
    try {
      await locker.query('BEGIN');
      await locker.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId]);
      const pid = (await locker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      const waitingBehindLocker = async (): Promise<number> =>
        (
          await db.query<{ n: number }>(
            `WITH RECURSIVE waiting(pid) AS (
               SELECT pid FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid))
               UNION
               SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY (pg_blocking_pids(a.pid))
             )
             SELECT count(*)::int AS n FROM waiting`,
            [pid],
          )
        ).rows[0]?.n ?? 0;
      const accepting = accept(invitee, id);
      for (const deadline = Date.now() + 3_000; (await waitingBehindLocker()) < 1;) {
        if (Date.now() > deadline) throw new Error('the acceptance never waited for the room');
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      const progress = { disableDone: false };
      const disabling = platform.browser
        .request('POST', '/admin/users/disable', { userId: invitee.userId })
        .finally(() => {
          progress.disableDone = true;
        });
      // Either the disable queues behind the acceptance (correct) or it finishes on its own.
      for (const deadline = Date.now() + 2_000; !progress.disableDone && (await waitingBehindLocker()) < 2;) {
        if (Date.now() > deadline) break;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      await locker.query('COMMIT');
      const [accepted, disabled] = await Promise.all([accepting, disabling]);
      expect(disabled.status).toBe(200);
      expect([200, 401]).toContain(accepted.status);
      const rows = await membershipOf(roomId, invitee.userId);
      expect(rows.filter((m) => m.status === 'ACTIVE')).toEqual([]);
    } finally {
      await locker.end();
    }
  });

  it('a revocation and an acceptance: exactly one wins', async () => {
    for (let round = 0; round < 3; round += 1) {
      const { owner, invitee, roomId, id } = await openInvitation();
      const [revoked, accepted] = await whileLocked(db, 'SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId], () =>
        Promise.all([
          owner.browser.request('POST', `/rooms/${roomId}/invitations/${id}/revoke`, {}),
          accept(invitee, id),
        ]),
      );
      expect([revoked.status, accepted.status].sort()).toEqual([200, 409]);
      const status = await invitationStatus(id);
      const rows = await membershipOf(roomId, invitee.userId);
      if (accepted.status === 200) {
        expect(status).toBe('ACCEPTED');
        expect(rows.map((m) => m.status)).toEqual(['ACTIVE']);
      } else {
        expect(status).toBe('REVOKED');
        expect(rows).toEqual([]);
      }
    }
  });

  it('two acceptances of one invitation create one membership', async () => {
    const { invitee, roomId, id } = await openInvitation();
    const responses = await whileLocked(db, 'SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId], () =>
      Promise.all([accept(invitee, id), accept(invitee, id)]),
    );
    expect(responses.map((r) => r.status).sort()).toEqual([200, 409]);
    expect((await membershipOf(roomId, invitee.userId)).map((m) => m.status)).toEqual(['ACTIVE']);
  });

  it('a room deletion and an acceptance leave the room DELETING and unreachable', async () => {
    const { owner, invitee, roomId, id } = await openInvitation();
    await stepUp(api, owner);
    const [deleted, accepted] = await whileLocked(db, 'SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId], () =>
      Promise.all([owner.browser.request('POST', `/rooms/${roomId}/delete`, {}), accept(invitee, id)]),
    );
    expect(deleted.status).toBe(200);
    expect([200, 404]).toContain(accepted.status);
    expect((await roomRow(db, roomId)).status).toBe('DELETING');
    expect((await invitee.browser.request('GET', `/rooms/${roomId}`)).status).toBe(404);
  });

  it('a member loss (REKEY_REQUIRED) and an acceptance: no one joins a locked room', async () => {
    for (let round = 0; round < 2; round += 1) {
      const { owner, invitee, roomId, id } = await openInvitation();
      const leaving = await personWithVault(api, db);
      const joined = await invite(owner, roomId, leaving, 'MEMBER');
      expect((await accept(leaving, (joined.body['invitation'] as { id: string }).id)).status).toBe(200);
      const [removed, accepted] = await whileLocked(db, 'SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId], () =>
        Promise.all([
          owner.browser.request('POST', `/rooms/${roomId}/members/${leaving.userId}/remove`, {}),
          accept(invitee, id),
        ]),
      );
      expect(removed.status).toBe(200);
      expect((await roomRow(db, roomId)).key_state).toBe('REKEY_REQUIRED');
      if (accepted.status === 200) {
        // The acceptance came first, while the room was writable.
        expect((await membershipOf(roomId, invitee.userId)).map((m) => m.status)).toEqual(['ACTIVE']);
      } else {
        expect(accepted.status).toBe(409);
        expect(errorCode(accepted)).toBe('REKEY_REQUIRED');
        expect(await membershipOf(roomId, invitee.userId)).toEqual([]);
        expect(await invitationStatus(id)).toBe('PENDING');
      }
    }
  });

  it('a vault reset of the invitee and an acceptance: never a membership for a retired identity', async () => {
    for (let round = 0; round < 2; round += 1) {
      const { invitee, roomId, id } = await openInvitation();
      const oldKey = vaultOf(invitee).identity.keyId;
      await stepUp(api, invitee);
      const fresh = await createVault({
        userId: invitee.userId,
        passphrase: newPassphrase(),
        account: { email: invitee.email, displayName: 'Synthetic Test User' },
        runner,
      });
      const resetBody = { supersedesKeyId: oldKey, vault: vaultRecordToWire(fresh.record) };
      // Both need the invitee's identity row: the reset to retire it, the acceptance to keep it.
      const [reset, accepted] = await whileLocked(
        db,
        'SELECT id FROM user_key_pairs WHERE id = $1 FOR UPDATE',
        [oldKey],
        () => Promise.all([invitee.browser.request('POST', '/vault/reset', resetBody), accept(invitee, id)]),
      );
      expect(reset.status).toBe(201);
      if (accepted.status === 200) {
        // Accepted while the identity was current; the reset came after and found nothing open.
        expect(await invitationStatus(id)).toBe('ACCEPTED');
        expect((await membershipOf(roomId, invitee.userId)).map((m) => m.status)).toEqual(['ACTIVE']);
      } else {
        expect(accepted.status).toBe(409);
        expect(errorCode(accepted)).toBe('IDENTITY_KEY_CHANGED');
        expect(await invitationStatus(id)).toBe('REVOKED');
        expect(await membershipOf(roomId, invitee.userId)).toEqual([]);
      }
    }
  });
});
