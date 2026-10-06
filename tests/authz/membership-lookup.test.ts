import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { createRoomAccessStore, type RoomAccessStore } from '../../apps/api/src/db/room-access-store';
import { createLogger } from '../../apps/api/src/logging/logger';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { insertMember, insertRoomWithoutKeys, insertUser } from '../helpers/db-fixtures';

// CM-T029, OL-01: the membership lookup behind every room authorization decision, run against
// PostgreSQL as the least-privilege API role. The query itself enforces the room, the user, the
// membership state and the room state, so a membership in room A can never come back for room B
// (T-06), and its projection carries no room name and no key material.
let db: pg.Client;
let database: Database;
let store: RoomAccessStore;

beforeAll(async () => {
  loadDatabaseTestEnv();
  const test = testDatabase(inject('databaseName'));
  db = await test.connect('api');
  database = createDatabase({
    url: new SecretValue(test.url('api')),
    logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
    poolMax: 2,
  });
  store = createRoomAccessStore(database.prisma);
});
afterAll(async () => {
  await database.close();
  await db.end();
});

const removed = { status: 'REMOVED', removed_at: new Date(), removal_reason: 'REMOVED_BY_ADMIN' };

describe('room membership lookup (OL-01)', () => {
  it('returns the ACTIVE membership with identifiers, role and states only', async () => {
    const owner = await insertUser(db);
    const roomId = await insertRoomWithoutKeys(db, owner, { security_profile: 'CONFIDENTIAL' });
    const record = await store.findActiveMembership(roomId, owner);
    expect(record).toEqual({
      membershipId: expect.any(String) as unknown,
      roomId,
      userId: owner,
      role: 'OWNER',
      status: 'ACTIVE',
      room: { status: 'ACTIVE', keyState: 'ACTIVE', securityProfile: 'CONFIDENTIAL' },
    });
    expect(Object.keys(record ?? {}).sort()).toEqual(['membershipId', 'role', 'room', 'roomId', 'status', 'userId']);
    expect(Object.keys(record?.room ?? {}).sort()).toEqual(['keyState', 'securityProfile', 'status']);
  });

  it('never returns a membership of room A for room B, for any role (T-06)', async () => {
    const roomA = await insertRoomWithoutKeys(db, await insertUser(db));
    const ownerB = await insertUser(db);
    const roomB = await insertRoomWithoutKeys(db, ownerB);
    for (const role of ['ADMIN', 'MEMBER', 'VIEWER'] as const) {
      const user = await insertUser(db);
      await insertMember(db, roomA, user, { role });
      expect((await store.findActiveMembership(roomA, user))?.role).toBe(role);
      expect(await store.findActiveMembership(roomB, user)).toBeNull();
    }
    // The OWNER of room B is nobody in room A.
    expect((await store.findActiveMembership(roomB, ownerB))?.role).toBe('OWNER');
    expect(await store.findActiveMembership(roomA, ownerB)).toBeNull();
  });

  it("never returns another user's membership", async () => {
    const owner = await insertUser(db);
    const roomId = await insertRoomWithoutKeys(db, owner);
    expect(await store.findActiveMembership(roomId, await insertUser(db))).toBeNull();
  });

  it('returns nothing for SUSPENDED, REMOVED and LEFT memberships', async () => {
    const roomId = await insertRoomWithoutKeys(db, await insertUser(db));
    const states = [
      { status: 'SUSPENDED' },
      removed,
      { status: 'LEFT', removed_at: new Date(), removal_reason: 'LEFT_ROOM' },
    ];
    for (const state of states) {
      const user = await insertUser(db);
      await insertMember(db, roomId, user, { role: 'ADMIN', ...state });
      expect(await store.findActiveMembership(roomId, user)).toBeNull();
    }
  });

  it('ignores historical rows: a removed and re-added member is found by the current row only', async () => {
    const roomId = await insertRoomWithoutKeys(db, await insertUser(db));
    const user = await insertUser(db);
    const old = await insertMember(db, roomId, user, { role: 'ADMIN', ...removed });
    const current = await insertMember(db, roomId, user, { role: 'VIEWER' });
    expect(await store.findActiveMembership(roomId, user)).toMatchObject({ membershipId: current, role: 'VIEWER' });
    expect(current).not.toBe(old);
  });

  it('returns nothing in a DELETING or DELETED room, even for its OWNER', async () => {
    for (const status of ['DELETING', 'DELETED']) {
      const owner = await insertUser(db);
      const roomId = await insertRoomWithoutKeys(db, owner);
      await db.query('UPDATE rooms SET status = $2, deleted_at = now() WHERE id = $1', [roomId, status]);
      expect(await store.findActiveMembership(roomId, owner)).toBeNull();
    }
  });

  it('answers unknown and malformed identifiers with null, without a database error', async () => {
    const owner = await insertUser(db);
    const roomId = await insertRoomWithoutKeys(db, owner);
    expect(await store.findActiveMembership(randomUUID(), owner)).toBeNull();
    for (const bad of ['not-a-uuid', roomId.toUpperCase(), `${roomId}x`, '', "' OR '1'='1"]) {
      expect(await store.findActiveMembership(bad, owner)).toBeNull();
      expect(await store.findActiveMembership(roomId, bad)).toBeNull();
    }
  });

  it('reads the current role on every call: a change is visible at once (no cache)', async () => {
    const roomId = await insertRoomWithoutKeys(db, await insertUser(db));
    const user = await insertUser(db);
    const membershipId = await insertMember(db, roomId, user, { role: 'ADMIN' });
    expect((await store.findActiveMembership(roomId, user))?.role).toBe('ADMIN');
    await db.query(`UPDATE room_members SET role = 'VIEWER' WHERE id = $1`, [membershipId]);
    expect((await store.findActiveMembership(roomId, user))?.role).toBe('VIEWER');
    await db.query(
      `UPDATE room_members SET status = 'REMOVED', removed_at = now(), removal_reason = 'REMOVED_BY_ADMIN' WHERE id = $1`,
      [membershipId],
    );
    expect(await store.findActiveMembership(roomId, user)).toBeNull();
  });
});
