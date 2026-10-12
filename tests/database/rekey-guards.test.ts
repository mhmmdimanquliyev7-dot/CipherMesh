import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';
import {
  DUMMY,
  insert,
  insertKeyPair,
  insertMember,
  insertRoom,
  insertStatement,
  insertUser,
  type RoomFixture,
} from '../helpers/db-fixtures';
import { loadDatabaseTestEnv, sqlState, sqlStateInSavepoint, SQLSTATE, testDatabase } from '../helpers/database';

// Phase 11 (CM-T050 to CM-T053): the database guards of migration 20261011000000_key_rotation,
// exercised as the API role (cm_api) inside rolled-back transactions. They back the API's rules so
// that a faulty or compromised writer of the runtime role cannot break the rekey state machine
// silently (T-36, T-37, INV-07). Expected failures are asserted by SQLSTATE.
loadDatabaseTestEnv();
const db = testDatabase(inject('databaseName'));
let api: pg.Client;

beforeAll(async () => {
  api = await db.connect('api');
});
afterAll(async () => {
  await api.end();
});
beforeEach(async () => {
  await api.query('BEGIN');
});
afterEach(async () => {
  await api.query('ROLLBACK');
});

const attempt = (table: string, row: Record<string, unknown>): Promise<string> =>
  sqlStateInSavepoint(api, ...insertStatement(table, row));
const run = (sql: string, values: unknown[] = []): Promise<string> => sqlStateInSavepoint(api, sql, values);
/** Runs a statement and then the deferred commit-time checks, inside a savepoint. */
const atCommit = (sql: string): Promise<string> => run(`${sql}; SET CONSTRAINTS ALL IMMEDIATE`);

function operationRow(room: RoomFixture, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: randomUUID(),
    room_id: room.roomId,
    started_by_id: room.ownerId,
    mode: 'MANUAL',
    base_version: 1,
    target_version: 2,
    membership_epoch: 0,
    recipient_set_digest: DUMMY.digest(),
    lease_expires_at: new Date(Date.now() + 600_000),
    ...overrides,
  };
}

const lock = (room: RoomFixture) =>
  `UPDATE rooms SET key_state = 'REKEY_REQUIRED', rekey_reasons = '{MEMBER_REMOVED}', rekey_required_since = now() WHERE id = '${room.roomId}'`;

describe('rekey operations (ADR-013)', () => {
  it('keep the snapshot write-once and closed operations final; a PENDING one is never deleted', async () => {
    const room = await insertRoom(api);
    const op = operationRow(room);
    await insert(api, 'rekey_operations', op);
    const id = op['id'] as string;
    for (const change of [
      'membership_epoch = 5',
      'base_version = 2, target_version = 3',
      "recipient_set_digest = '\\x00'::bytea || recipient_set_digest",
      "lease_expires_at = lease_expires_at + interval '1 hour'",
      `started_by_id = '${room.ownerId}'::uuid, mode = 'MANDATORY'`,
    ]) {
      expect(await run(`UPDATE rekey_operations SET ${change} WHERE id = $1`, [id]), change).toBe(
        SQLSTATE.integrityConstraintViolation,
      );
    }
    // The API role cannot delete operations at all (grant layer); the worker case is below.
    expect(await run('DELETE FROM rekey_operations WHERE id = $1', [id])).toBe(SQLSTATE.insufficientPrivilege);
    expect(
      await run(
        `UPDATE rekey_operations SET status = 'CANCELLED', closed_at = now(), closed_reason = 'X' WHERE id = $1`,
        [id],
      ),
    ).toBe('none');
    // Closed is final: no reopening, no completion, no new payload.
    expect(await run(`UPDATE rekey_operations SET status = 'PENDING', closed_at = NULL WHERE id = $1`, [id])).toBe(
      SQLSTATE.integrityConstraintViolation,
    );
    expect(
      await run(
        `UPDATE rekey_operations SET status = 'COMPLETED', completed_at = now(), payload_digest = $2 WHERE id = $1`,
        [id, DUMMY.digest()],
      ),
    ).toBe(SQLSTATE.integrityConstraintViolation);
  });

  it('a room is REKEYING exactly while a MANDATORY operation is PENDING, checked at commit', async () => {
    const room = await insertRoom(api);
    expect(await run(lock(room))).toBe('none');
    // REKEYING without an operation, and a MANDATORY operation in a room that is not REKEYING.
    expect(await atCommit(`UPDATE rooms SET key_state = 'REKEYING' WHERE id = '${room.roomId}'`)).toBe(
      SQLSTATE.checkViolation,
    );
    const mandatory = operationRow(room, { mode: 'MANDATORY' });
    expect(await atCommit(insertSql('rekey_operations', mandatory))).toBe(SQLSTATE.checkViolation);
    // Together they are consistent.
    expect(
      await atCommit(
        `${insertSql('rekey_operations', mandatory)}; UPDATE rooms SET key_state = 'REKEYING' WHERE id = '${room.roomId}'`,
      ),
    ).toBe('none');
    // A MANUAL operation exists only while the room is ACTIVE.
    const other = await insertRoom(api);
    expect(await run(lock(other))).toBe('none');
    expect(await atCommit(insertSql('rekey_operations', operationRow(other)))).toBe(SQLSTATE.checkViolation);
  });

  it('an epoch change closes the PENDING operation as STALE and returns a REKEYING room to REKEY_REQUIRED', async () => {
    const room = await insertRoom(api);
    await api.query(lock(room));
    const op = operationRow(room, { mode: 'MANDATORY' });
    await insert(api, 'rekey_operations', op);
    await api.query(`UPDATE rooms SET key_state = 'REKEYING' WHERE id = $1`, [room.roomId]);
    // Any writer of the epoch, not only the API's advanceEpoch.
    await api.query('UPDATE rooms SET membership_epoch = membership_epoch + 1 WHERE id = $1', [room.roomId]);
    const { rows } = await api.query<{ status: string; closed_reason: string; key_state: string }>(
      `SELECT o.status::text, o.closed_reason, r.key_state::text FROM rekey_operations o JOIN rooms r ON r.id = o.room_id
        WHERE o.id = $1`,
      [op['id']],
    );
    expect(rows[0]).toEqual({ status: 'STALE', closed_reason: 'MEMBERSHIP_CHANGED', key_state: 'REKEY_REQUIRED' });
    expect(await run('UPDATE rooms SET membership_epoch = membership_epoch - 1 WHERE id = $1', [room.roomId])).toBe(
      SQLSTATE.checkViolation,
    );
  });
});

describe('the worker purges only closed operations', () => {
  it('a PENDING operation is never deleted, even by the role that purges closed ones', async () => {
    const committed = await db.connect('api');
    const worker = await db.connect('worker');
    try {
      const room = await insertRoom(committed);
      const op = operationRow(room);
      await insert(committed, 'rekey_operations', op);
      expect(await sqlState(worker.query('DELETE FROM rekey_operations WHERE id = $1', [op['id']]))).toBe(
        SQLSTATE.integrityConstraintViolation,
      );
      await committed.query(
        `UPDATE rekey_operations SET status = 'ABANDONED', closed_at = now(), closed_reason = 'LEASE_EXPIRED' WHERE id = $1`,
        [op['id']],
      );
      expect((await worker.query('DELETE FROM rekey_operations WHERE id = $1', [op['id']])).rowCount).toBe(1);
    } finally {
      await committed.end();
      await worker.end();
    }
  });
});

describe('key versions and the room key state (key-lifecycle 1.1, INV-07)', () => {
  const version2 = (room: RoomFixture, overrides: Record<string, unknown> = {}) => ({
    room_id: room.roomId,
    version: 2,
    status: 'ACTIVE',
    commitment: Buffer.alloc(32, 0x5a),
    algorithm_suite: 'CM1',
    reasons: '{MANUAL}',
    created_by_id: room.ownerId,
    created_by_key_id: room.ownerKeyId,
    previous_commitment: DUMMY.digest(),
    recipient_user_ids: [room.ownerId],
    recipient_key_ids: [room.ownerKeyId],
    statement_signature: DUMMY.signature(),
    ...overrides,
  });

  it('a version chains to the commitment of the version before, without gaps', async () => {
    const room = await insertRoom(api);
    await api.query(`UPDATE room_key_versions SET status = 'RETIRED', retired_at = now() WHERE room_id = $1`, [
      room.roomId,
    ]);
    // DUMMY.digest() is version 1's commitment in the fixture.
    expect(await attempt('room_key_versions', version2(room, { previous_commitment: Buffer.alloc(32, 0x01) }))).toBe(
      SQLSTATE.integrityConstraintViolation,
    );
    expect(await attempt('room_key_versions', version2(room, { version: 3 }))).toBe(
      SQLSTATE.integrityConstraintViolation,
    );
    expect(await attempt('room_key_versions', version2(room))).toBe('none');
  });

  it('a status only moves ACTIVE -> RETIRED -> DESTROYED, and wrap_count never decreases', async () => {
    const room = await insertRoom(api);
    const update = (set: string) =>
      run(`UPDATE room_key_versions SET ${set} WHERE room_id = $1 AND version = 1`, [room.roomId]);
    expect(await update('wrap_count = 5')).toBe('none');
    expect(await update('wrap_count = 4')).toBe(SQLSTATE.integrityConstraintViolation);
    expect(await update(`status = 'RETIRED', retired_at = now()`)).toBe('none');
    expect(await update(`status = 'ACTIVE', retired_at = NULL`)).toBe(SQLSTATE.integrityConstraintViolation);
    expect(await update(`status = 'DESTROYED', destroyed_at = now()`)).toBe('none');
    expect(await update(`status = 'RETIRED', destroyed_at = NULL`)).toBe(SQLSTATE.integrityConstraintViolation);
  });

  it('a locked room is unlocked only together with the next ACTIVE version', async () => {
    const room = await insertRoom(api);
    await api.query(lock(room));
    const unlock = (extra = '') =>
      run(
        `UPDATE rooms SET key_state = 'ACTIVE', rekey_reasons = '{}', rekey_required_since = NULL ${extra} WHERE id = $1`,
        [room.roomId],
      );
    expect(await unlock()).toBe(SQLSTATE.checkViolation);
    // Moving to a version that does not exist, or skipping one, is refused as well.
    expect(await unlock(', current_key_version = 2')).toBe(SQLSTATE.checkViolation);
    await api.query(`UPDATE room_key_versions SET status = 'RETIRED', retired_at = now() WHERE room_id = $1`, [
      room.roomId,
    ]);
    await insert(api, 'room_key_versions', version2(room));
    expect(await unlock(', current_key_version = 3')).toBe(SQLSTATE.checkViolation);
    expect(await unlock(', current_key_version = 2')).toBe('none');
  });
});

describe('the grant history (room_member_grants)', () => {
  it('records every grant stored on a membership, and refuses any change or deletion', async () => {
    const room = await insertRoom(api);
    const member = await insertUser(api);
    const firstKey = await insertKeyPair(api, member);
    const grant = (subjectKeyId: string, role: string) => ({
      subject_key_id: subjectKeyId,
      grant_role: role,
      grantor_user_id: room.ownerId,
      grantor_key_id: room.ownerKeyId,
      grant_signature: DUMMY.signature(),
    });
    await insertMember(api, room.roomId, member, { role: 'ADMIN', ...grant(firstKey, 'ADMIN') });
    await api.query(
      `UPDATE user_key_pairs SET status = 'SUPERSEDED', superseded_at = now(),
                       encrypted_private_key = NULL, encrypted_signing_private_key = NULL WHERE id = $1`,
      [firstKey],
    );
    const secondKey = await insertKeyPair(api, member);
    // A re-share replaces the membership's grant; the history keeps both.
    await api.query(
      `UPDATE room_members SET subject_key_id = $3, grant_signature = $4 WHERE room_id = $1 AND user_id = $2`,
      [room.roomId, member, secondKey, Buffer.alloc(64, 0x33)],
    );
    const { rows } = await api.query<{ subject_key_id: string; role: string }>(
      'SELECT subject_key_id::text, role::text FROM room_member_grants WHERE room_id = $1 ORDER BY created_at, subject_key_id',
      [room.roomId],
    );
    expect(rows.map((r) => r.subject_key_id).sort()).toEqual([firstKey, secondKey].sort());
    expect(new Set(rows.map((r) => r.role))).toEqual(new Set(['ADMIN']));
    expect(await run('UPDATE room_member_grants SET role = $2 WHERE room_id = $1', [room.roomId, 'OWNER'])).toBe(
      SQLSTATE.insufficientPrivilege,
    );
    expect(await run('DELETE FROM room_member_grants WHERE room_id = $1', [room.roomId])).toBe(
      SQLSTATE.insufficientPrivilege,
    );
    // A grant naming a key of another user is refused by the composite key.
    const stranger = await insertKeyPair(api, await insertUser(api));
    expect(
      await attempt('room_member_grants', {
        room_id: room.roomId,
        subject_user_id: member,
        subject_key_id: stranger,
        role: 'MEMBER',
        grantor_user_id: room.ownerId,
        grantor_key_id: room.ownerKeyId,
        grant_signature: DUMMY.signature(),
      }),
    ).toBe(SQLSTATE.foreignKeyViolation);
  });
});

/** An INSERT with literal values, for statements that must run in one simple query. */
function insertSql(table: string, row: Record<string, unknown>): string {
  const literal = (value: unknown): string => {
    if (value instanceof Date) return `'${value.toISOString()}'`;
    if (Buffer.isBuffer(value)) return `'\\x${value.toString('hex')}'::bytea`;
    if (typeof value === 'number') return String(value);
    return `'${String(value).replace(/'/g, "''")}'`;
  };
  const keys = Object.keys(row);
  return `INSERT INTO ${table} (${keys.join(', ')}) VALUES (${keys.map((k) => literal(row[k])).join(', ')})`;
}
