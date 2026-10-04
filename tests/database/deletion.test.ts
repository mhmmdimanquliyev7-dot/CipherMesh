import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { DUMMY, insert, insertKeyPair, insertMember, insertRoom, insertUser } from '../helpers/db-fixtures';
import {
  inRolledBackTransaction,
  loadDatabaseTestEnv,
  sqlState,
  sqlStateInSavepoint,
  SQLSTATE,
  testDatabase,
} from '../helpers/database';

// Deletion behaviour of data-model section 5: tombstones instead of cascades, envelope deletion
// on member removal, and retention deletes only where the model allows them.
loadDatabaseTestEnv();
const db = testDatabase(inject('databaseName'));
let api: pg.Client;
let worker: pg.Client;
let migrator: pg.Client;

beforeAll(async () => {
  api = await db.connect('api');
  worker = await db.connect('worker');
  migrator = await db.connect('migrator');
});
afterAll(async () => {
  await Promise.all([api.end(), worker.end(), migrator.end()]);
});

describe('foreign keys restrict deletion (no cascades)', () => {
  it('even the table owner cannot delete a user or a room that other rows reference', async () => {
    const room = await insertRoom(api);
    await inRolledBackTransaction(migrator, async () => {
      expect(await sqlStateInSavepoint(migrator, 'DELETE FROM users WHERE id = $1', [room.ownerId])).toBe(
        SQLSTATE.foreignKeyViolation,
      );
      expect(await sqlStateInSavepoint(migrator, 'DELETE FROM rooms WHERE id = $1', [room.roomId])).toBe(
        SQLSTATE.foreignKeyViolation,
      );
      expect(
        await sqlStateInSavepoint(migrator, 'DELETE FROM room_key_versions WHERE room_id = $1', [room.roomId]),
      ).toBe(SQLSTATE.foreignKeyViolation);
    });
  });

  it('declares no ON DELETE CASCADE anywhere, and SET NULL only for purged rekey operations', async () => {
    const { rows } = await migrator.query<{ conname: string; action: string }>(
      `SELECT conname, confdeltype AS action FROM pg_constraint
        WHERE contype = 'f' AND connamespace = 'public'::regnamespace AND confdeltype <> 'r'`,
    );
    expect(rows).toEqual([{ conname: 'room_key_versions_created_by_operation_id_fkey', action: 'n' }]);
  });
});

describe('member removal (data-model section 5, INV-07)', () => {
  it('the API role can remove a member, delete their envelopes and lock the room in one transaction', async () => {
    const room = await insertRoom(api);
    const member = await insertUser(api);
    const memberKey = await insertKeyPair(api, member);
    await insertMember(api, room.roomId, member);
    await insert(api, 'key_envelopes', {
      room_id: room.roomId,
      key_version: 1,
      recipient_user_id: member,
      recipient_key_id: memberKey,
      status: 'ACTIVE',
      wrapped_key: DUMMY.rsaCiphertext(),
      algorithm: 'RSA-OAEP-3072-SHA256',
      created_by_id: room.ownerId,
    });

    await inRolledBackTransaction(api, async () => {
      await api.query(
        `UPDATE room_members SET status = 'REMOVED', removed_at = now(), removed_by_id = $3, removal_reason = 'REMOVED_BY_ADMIN'
          WHERE room_id = $1 AND user_id = $2`,
        [room.roomId, member, room.ownerId],
      );
      const deleted = await api.query('DELETE FROM key_envelopes WHERE room_id = $1 AND recipient_user_id = $2', [
        room.roomId,
        member,
      ]);
      expect(deleted.rowCount).toBe(1);
      await api.query(
        `UPDATE rooms SET key_state = 'REKEY_REQUIRED', rekey_reasons = array_append(rekey_reasons, 'MEMBER_REMOVED'),
                rekey_required_since = now(), membership_epoch = membership_epoch + 1 WHERE id = $1`,
        [room.roomId],
      );
      const { rows } = await api.query('SELECT key_state, membership_epoch::int AS epoch FROM rooms WHERE id = $1', [
        room.roomId,
      ]);
      expect(rows).toEqual([{ key_state: 'REKEY_REQUIRED', epoch: 1 }]);
    });
  });
});

describe('retention deletes by the worker', () => {
  it('purging a closed rekey operation keeps the key version it activated', async () => {
    const room = await insertRoom(api);
    const operationId = randomUUID();
    await insert(api, 'rekey_operations', {
      id: operationId,
      room_id: room.roomId,
      started_by_id: room.ownerId,
      mode: 'MANUAL',
      status: 'COMPLETED',
      base_version: 1,
      target_version: 2,
      membership_epoch: 0,
      recipient_set_digest: DUMMY.digest(),
      lease_expires_at: new Date(Date.now() + 600_000),
      payload_digest: DUMMY.digest(),
      completed_at: new Date(),
      closed_at: new Date(),
    });
    await api.query(`UPDATE room_key_versions SET status = 'RETIRED', retired_at = now() WHERE room_id = $1`, [
      room.roomId,
    ]);
    await insert(api, 'room_key_versions', {
      room_id: room.roomId,
      version: 2,
      status: 'ACTIVE',
      commitment: DUMMY.digest(),
      algorithm_suite: 'CM1',
      reasons: '{MANUAL}',
      created_by_operation_id: operationId,
      created_by_id: room.ownerId,
    });

    const purged = await worker.query('DELETE FROM rekey_operations WHERE id = $1 AND closed_at IS NOT NULL', [
      operationId,
    ]);
    expect(purged.rowCount).toBe(1);
    const { rows } = await api.query(
      'SELECT version, created_by_operation_id FROM room_key_versions WHERE room_id = $1 ORDER BY version',
      [room.roomId],
    );
    expect(rows).toEqual([
      { version: 1, created_by_operation_id: null },
      { version: 2, created_by_operation_id: null },
    ]);
  });

  it('the worker may delete expired sessions and old login attempts; the API role may not', async () => {
    const user = await insertUser(api);
    const past = new Date(Date.now() - 86_400_000 * 40);
    await insert(api, 'sessions', {
      user_id: user,
      token_digest: DUMMY.digest().fill(randomUUID().charCodeAt(0)),
      created_at: past,
      last_seen_at: past,
      idle_expires_at: new Date(past.getTime() + 1_800_000),
      absolute_expires_at: new Date(past.getTime() + 43_200_000),
      authenticated_at: past,
    });
    await insert(api, 'login_attempts', { user_id: user, outcome: 'SUCCESS', occurred_at: past });
    expect(await sqlState(api.query('DELETE FROM sessions WHERE user_id = $1', [user]))).toBe(
      SQLSTATE.insufficientPrivilege,
    );
    expect(await sqlState(api.query('DELETE FROM login_attempts WHERE user_id = $1', [user]))).toBe(
      SQLSTATE.insufficientPrivilege,
    );
    expect((await worker.query('DELETE FROM sessions WHERE user_id = $1', [user])).rowCount).toBe(1);
    expect((await worker.query('DELETE FROM login_attempts WHERE user_id = $1', [user])).rowCount).toBe(1);
  });
});
