import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { runRoomCleanup } from '../../apps/api/src/db/room-cleanup';
import { createLogger } from '../../apps/api/src/logging/logger';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import {
  addMember,
  apiDatabase,
  createRoom,
  errorOf,
  insertDummyEnvelope,
  memberships,
  mfaPersonWithVault,
  NOT_FOUND_BODY,
  person,
  personWithVault,
  platformAdministrator,
  roomRow,
  stepUp,
  type Person,
} from '../helpers/rooms';

// CM-T030: room creation, listing, reading, renaming and deletion against the real API, with
// real sessions and PostgreSQL as cm_api. Authorization comes from the central gate (CM-T029)
// and is re-checked on locked state by every change.
let api: AuthTestApi;
let db: pg.Client;
let database: Database;

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  database = apiDatabase();
});
afterAll(async () => {
  await api.close();
  await database.close();
  await db.end();
});

const create = (who: Person, body: Record<string, unknown>) => who.browser.request('POST', '/rooms', body);
const list = (who: Person, cursor?: string) =>
  who.browser.request('GET', cursor === undefined ? '/rooms' : `/rooms?cursor=${encodeURIComponent(cursor)}`);
const read = (who: Person, roomId: string) => who.browser.request('GET', `/rooms/${roomId}`);
const members = (who: Person, roomId: string) => who.browser.request('GET', `/rooms/${roomId}/members`);
const rename = (who: Person, roomId: string, body: Record<string, unknown>) =>
  who.browser.request('POST', `/rooms/${roomId}/rename`, body);
const destroy = (who: Person, roomId: string) => who.browser.request('POST', `/rooms/${roomId}/delete`, {});
const roomIds = (response: { body: Record<string, unknown> }) =>
  ((response.body['rooms'] as { id: string }[] | undefined) ?? []).map((room) => room.id);

async function keyRows(roomId: string): Promise<number> {
  const { rows } = await db.query<{ n: number }>(
    `SELECT (SELECT count(*) FROM room_key_versions WHERE room_id = $1)
          + (SELECT count(*) FROM key_envelopes WHERE room_id = $1) AS n`,
    [roomId],
  );
  return Number(rows[0]?.n);
}

describe('room creation (SS-04)', () => {
  it('creates the room and the OWNER membership, and no key material', async () => {
    const owner = await personWithVault(api, db);
    const roomId = randomUUID();
    const response = await create(owner, { roomId, name: '  Project  notes ', securityProfile: 'STANDARD' });
    expect(response.status).toBe(201);
    expect(response.body).toEqual({
      id: roomId,
      name: 'Project  notes',
      securityProfile: 'STANDARD',
      role: 'OWNER',
      keyState: 'ACTIVE',
      createdAt: expect.any(String) as unknown,
    });
    expect(await memberships(db, roomId)).toEqual([
      { user_id: owner.userId, role: 'OWNER', status: 'ACTIVE', removal_reason: null },
    ]);
    const { rows } = await db.query(
      'SELECT security_profile::text, policy_version, created_by_id::text, current_key_version FROM rooms WHERE id = $1',
      [roomId],
    );
    expect(rows).toEqual([
      { security_profile: 'STANDARD', policy_version: 1, created_by_id: owner.userId, current_key_version: 1 },
    ]);
    // Room keys arrive with Phase 6: no key version and no envelope exist.
    expect(await keyRows(roomId)).toBe(0);
    expect(api.events.some((e) => e.name === 'ROOM_CREATED' && e.details?.['roomId'] === roomId)).toBe(true);
  });

  it.each([
    ['an empty name', { name: '   ' }],
    ['a name over 100 characters', { name: 'x'.repeat(101) }],
    ['a name with a control character', { name: 'bad\u0007name' }],
    ['a name with a bidirectional override', { name: 'invoice‮txt.exe' }],
    ['an unknown profile', { securityProfile: 'TOP_SECRET' }],
    ['a lowercase profile', { securityProfile: 'standard' }],
    ['a malformed room ID', { roomId: 'not-a-uuid' }],
    ['an uppercase room ID', { roomId: randomUUID().toUpperCase() }],
    ['a role field', { role: 'OWNER' }],
    ['an owner field', { ownerId: randomUUID() }],
    ['a user ID field', { userId: randomUUID() }],
    ['key material', { roomKey: 'AAAA', envelope: 'AAAA' }],
    ['a commitment', { commitment: 'AAAA' }],
  ])('refuses %s with a validation error and creates nothing', async (_label, change) => {
    const owner = await personWithVault(api, db);
    const body = { roomId: randomUUID(), name: 'Valid name', securityProfile: 'STANDARD', ...change };
    const response = await create(owner, body);
    expect(response.status).toBe(400);
    expect(errorCode(response)).toBe('VALIDATION_FAILED');
    const { rows } = await db.query('SELECT count(*)::int AS n FROM rooms WHERE created_by_id = $1', [owner.userId]);
    expect(rows).toEqual([{ n: 0 }]);
  });

  it('requires an active vault (SS-04)', async () => {
    const noVault = await person(api);
    const response = await create(noVault, { roomId: randomUUID(), name: 'Room', securityProfile: 'STANDARD' });
    expect(response.status).toBe(403);
    expect(errorCode(response)).toBe('VAULT_SETUP_REQUIRED');
  });

  it('requires an MFA-verified session for CONFIDENTIAL and RESTRICTED rooms (PC-01)', async () => {
    const plain = await personWithVault(api, db);
    for (const securityProfile of ['CONFIDENTIAL', 'RESTRICTED']) {
      const response = await create(plain, { roomId: randomUUID(), name: 'Room', securityProfile });
      expect(response.status).toBe(403);
      expect(errorCode(response)).toBe('MFA_REQUIRED');
    }
    const strong = await mfaPersonWithVault(api, db);
    expect(await createRoom(strong, 'CONFIDENTIAL')).toEqual(expect.any(String));
    expect(await createRoom(strong, 'RESTRICTED')).toEqual(expect.any(String));
  });

  it('refuses a room ID that was ever used, without creating anything', async () => {
    const first = await personWithVault(api, db);
    const second = await personWithVault(api, db);
    const roomId = await createRoom(first);
    const reuse = await create(second, { roomId, name: 'Takeover', securityProfile: 'STANDARD' });
    expect(reuse.status).toBe(409);
    expect(errorCode(reuse)).toBe('ROOM_ID_UNAVAILABLE');
    expect(await memberships(db, roomId)).toHaveLength(1);
    expect((await roomRow(db, roomId)).name).toBe('Synthetic room');
  });
});

describe('room creation: PC-02 maximum time since the last password authentication', () => {
  it('refuses RESTRICTED after one hour and CONFIDENTIAL after four, while STANDARD still works', async () => {
    // A separate API instance: its clock moves without affecting the other tests.
    const local = await startAuthApi();
    try {
      const who = await mfaPersonWithVault(local, db);
      // Move past one hour in steps below the 30-minute idle timeout, using the session in between.
      for (let i = 0; i < 3; i += 1) {
        local.clock.advance(25 * 60_000);
        expect((await who.browser.request('GET', '/auth/session')).status).toBe(200);
      }
      const restricted = await create(who, { roomId: randomUUID(), name: 'Room', securityProfile: 'RESTRICTED' });
      expect(restricted.status).toBe(401);
      expect(errorCode(restricted)).toBe('REAUTH_REQUIRED');
      expect(await createRoom(who, 'CONFIDENTIAL')).toEqual(expect.any(String));
      for (let i = 0; i < 8; i += 1) {
        local.clock.advance(25 * 60_000);
        expect((await who.browser.request('GET', '/auth/session')).status).toBe(200);
      }
      const confidential = await create(who, { roomId: randomUUID(), name: 'Room', securityProfile: 'CONFIDENTIAL' });
      expect(errorCode(confidential)).toBe('REAUTH_REQUIRED');
      expect(await createRoom(who, 'STANDARD')).toEqual(expect.any(String));
    } finally {
      await local.close();
    }
  });
});

describe('room listing (SS-06, OL-08)', () => {
  it('lists only rooms with an ACTIVE membership of the caller, with the caller role', async () => {
    const owner = await personWithVault(api, db);
    const viewer = await personWithVault(api, db);
    const own = await createRoom(owner);
    const shared = await createRoom(owner, 'STANDARD', 'Shared room');
    await addMember(db, shared, viewer.userId, 'VIEWER');
    const suspendedRoom = await createRoom(owner);
    await addMember(db, suspendedRoom, viewer.userId, 'MEMBER', { status: 'SUSPENDED' });
    const leftRoom = await createRoom(owner);
    await addMember(db, leftRoom, viewer.userId, 'MEMBER', {
      status: 'LEFT',
      removed_at: new Date(),
      removal_reason: 'LEFT_ROOM',
    });
    const other = await createRoom(await personWithVault(api, db));

    const viewerList = await list(viewer);
    expect(viewerList.status).toBe(200);
    expect(viewerList.body).toEqual({
      rooms: [
        {
          id: shared,
          name: 'Shared room',
          securityProfile: 'STANDARD',
          role: 'VIEWER',
          keyState: 'ACTIVE',
          createdAt: expect.any(String) as unknown,
        },
      ],
      nextCursor: null,
    });
    const ownerIds = roomIds(await list(owner));
    expect(ownerIds).toEqual(expect.arrayContaining([own, shared, suspendedRoom, leftRoom]));
    expect(ownerIds).not.toContain(other);
  });

  it('pages newest first with a cursor and a maximum page size of 50', async () => {
    const owner = await personWithVault(api, db);
    const created: string[] = [];
    for (let i = 0; i < 52; i += 1) {
      api.clock.advance(1_000);
      created.push(await createRoom(owner));
    }
    const first = await list(owner);
    expect(roomIds(first)).toEqual(created.slice(-50).reverse());
    const cursor = first.body['nextCursor'];
    expect(typeof cursor).toBe('string');
    const second = await list(owner, String(cursor));
    expect(roomIds(second)).toEqual(created.slice(0, 2).reverse());
    expect(second.body['nextCursor']).toBeNull();
  });

  it('refuses malformed cursors and unknown query parameters', async () => {
    const owner = await personWithVault(api, db);
    for (const bad of ['nope', `${new Date().toISOString()}_not-a-uuid`, `2026-13-01T00:00:00.000Z_${randomUUID()}`]) {
      expect((await list(owner, bad)).status).toBe(400);
    }
    expect((await owner.browser.request('GET', `/rooms?userId=${owner.userId}`)).status).toBe(400);
    expect((await owner.browser.request('GET', '/rooms?role=OWNER')).status).toBe(400);
  });

  it('shows a PLATFORM_ADMIN only its own memberships, never other rooms (PA-05)', async () => {
    const admin = await platformAdministrator(api, database);
    await createRoom(await personWithVault(api, db));
    const response = await list(admin);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ rooms: [], nextCursor: null });
  });
});

describe('reading a room and its members (AZ-01)', () => {
  it('returns the room and the caller role to every member, and only members and suspended members', async () => {
    const owner = await personWithVault(api, db);
    const viewer = await person(api);
    const suspended = await person(api);
    const roomId = await createRoom(owner, 'STANDARD', 'Visible');
    await addMember(db, roomId, viewer.userId, 'VIEWER');
    await addMember(db, roomId, suspended.userId, 'ADMIN', { status: 'SUSPENDED' });
    const removedUser = await person(api);
    await addMember(db, roomId, removedUser.userId, 'MEMBER', {
      status: 'REMOVED',
      removed_at: new Date(),
      removal_reason: 'REMOVED_BY_ADMIN',
    });

    const detail = await read(viewer, roomId);
    expect(detail.status).toBe(200);
    expect(detail.body).toMatchObject({
      room: { id: roomId, name: 'Visible', securityProfile: 'STANDARD', keyState: 'ACTIVE' },
      membership: { role: 'VIEWER' },
    });
    const list = await members(viewer, roomId);
    expect(list.status).toBe(200);
    // Fixture rows take the database clock and the API's rows its own, so compare as sets.
    const listed = (list.body['members'] as { userId: string; role: string; status: string }[])
      .map((m) => `${m.userId} ${m.role} ${m.status}`)
      .sort();
    expect(listed).toEqual(
      [`${owner.userId} OWNER ACTIVE`, `${viewer.userId} VIEWER ACTIVE`, `${suspended.userId} ADMIN SUSPENDED`].sort(),
    );
    // No email, no membership ID, no internal state.
    expect(Object.keys((list.body['members'] as object[])[0] ?? {}).sort()).toEqual([
      'displayName',
      'joinedAt',
      'role',
      'status',
      'userId',
    ]);
    for (const outsider of [removedUser, suspended, await person(api)]) {
      expect(errorOf(await read(outsider, roomId))).toEqual(NOT_FOUND_BODY);
      expect(errorOf(await members(outsider, roomId))).toEqual(NOT_FOUND_BODY);
    }
  });
});

describe('renaming a room (AZ-02)', () => {
  it('allows OWNER and ADMIN, denies MEMBER and VIEWER, and hides the room from outsiders', async () => {
    const owner = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    const cast: Record<string, Person> = {
      ADMIN: await person(api),
      MEMBER: await person(api),
      VIEWER: await person(api),
    };
    for (const [role, who] of Object.entries(cast)) await addMember(db, roomId, who.userId, role as 'ADMIN');
    expect((await rename(owner, roomId, { name: 'By owner' })).body).toMatchObject({ id: roomId, name: 'By owner' });
    expect((await rename(cast['ADMIN'] as Person, roomId, { name: 'By admin' })).status).toBe(200);
    for (const role of ['MEMBER', 'VIEWER']) {
      const denied = await rename(cast[role] as Person, roomId, { name: `By ${role}` });
      expect(denied.status).toBe(403);
      expect(errorCode(denied)).toBe('FORBIDDEN');
    }
    const outsider = await personWithVault(api, db);
    expect(errorOf(await rename(outsider, roomId, { name: 'Outsider' }))).toEqual(NOT_FOUND_BODY);
    expect((await roomRow(db, roomId)).name).toBe('By admin');
  });

  it('never takes a role, user or room from the request', async () => {
    const owner = await personWithVault(api, db);
    const viewer = await person(api);
    const roomId = await createRoom(owner);
    const otherRoom = await createRoom(owner);
    await addMember(db, roomId, viewer.userId, 'VIEWER');
    for (const extra of [{ role: 'OWNER' }, { userId: owner.userId }, { roomId: otherRoom }]) {
      const response = await rename(viewer, roomId, { name: 'Escalated', ...extra });
      expect(response.status).toBe(400);
    }
    const forged = await viewer.browser.request(
      'POST',
      `/rooms/${roomId}/rename`,
      { name: 'Escalated' },
      { 'x-room-role': 'OWNER', 'x-user-id': owner.userId },
    );
    expect(forged.status).toBe(403);
    expect((await roomRow(db, roomId)).name).toBe('Synthetic room');
  });

  it('applies to the addressed room only: a member of room A cannot rename room B', async () => {
    const ownerA = await personWithVault(api, db);
    const roomA = await createRoom(ownerA);
    const roomB = await createRoom(await personWithVault(api, db));
    expect(errorOf(await rename(ownerA, roomB, { name: 'Hijack' }))).toEqual(NOT_FOUND_BODY);
    expect((await roomRow(db, roomB)).name).toBe('Synthetic room');
    expect((await roomRow(db, roomA)).name).toBe('Synthetic room');
  });

  it('records ROOM_RENAMED without the name', async () => {
    const owner = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    api.events.length = 0;
    await rename(owner, roomId, { name: 'Sensitive codename' });
    const event = api.events.find((e) => e.name === 'ROOM_RENAMED');
    expect(event?.details).toEqual({ roomId });
    expect(JSON.stringify(api.events)).not.toContain('Sensitive codename');
  });
});

describe('deleting a room (AZ-04, step-up in every profile)', () => {
  it('is OWNER-only, needs a step-up, and refuses every request at once afterwards', async () => {
    const owner = await personWithVault(api, db);
    const admin = await person(api);
    const roomId = await createRoom(owner);
    await addMember(db, roomId, admin.userId, 'ADMIN');
    await stepUp(api, admin);
    const byAdmin = await destroy(admin, roomId);
    expect(byAdmin.status).toBe(403);
    const withoutStepUp = await destroy(owner, roomId);
    expect(withoutStepUp.status).toBe(401);
    expect(errorCode(withoutStepUp)).toBe('STEP_UP_REQUIRED');
    expect((await roomRow(db, roomId)).status).toBe('ACTIVE');

    await stepUp(api, owner);
    api.events.length = 0;
    const deleted = await destroy(owner, roomId);
    expect(deleted.status).toBe(200);
    expect(deleted.body).toEqual({ status: 'deleting' });
    expect(api.events.find((e) => e.name === 'ROOM_DELETED')?.details).toEqual({ roomId });
    expect((await roomRow(db, roomId)).status).toBe('DELETING');
    for (const who of [owner, admin]) {
      expect(errorOf(await read(who, roomId))).toEqual(NOT_FOUND_BODY);
      expect(errorOf(await members(who, roomId))).toEqual(NOT_FOUND_BODY);
      expect(errorOf(await rename(who, roomId, { name: 'After' }))).toEqual(NOT_FOUND_BODY);
      expect(roomIds(await list(who))).not.toContain(roomId);
    }
    expect(errorOf(await destroy(owner, roomId))).toEqual(NOT_FOUND_BODY);
  });

  it('gives a PLATFORM_ADMIN without a membership nothing but 404, even with a step-up', async () => {
    const owner = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    const admin = await platformAdministrator(api, database);
    await stepUp(api, admin, admin.secret);
    expect(errorOf(await destroy(admin, roomId))).toEqual(NOT_FOUND_BODY);
    expect((await roomRow(db, roomId)).status).toBe('ACTIVE');
  });

  it('is finished by the worker only when nothing is left to clean (fail-safe)', async () => {
    const owner = await personWithVault(api, db);
    const empty = await createRoom(owner);
    const withEnvelope = await createRoom(owner);
    await insertDummyEnvelope(db, withEnvelope, owner.userId, owner.userId);
    await stepUp(api, owner);
    expect((await destroy(owner, empty)).status).toBe(200);
    expect((await destroy(owner, withEnvelope)).status).toBe(200);
    const active = await createRoom(owner);

    const worker = createDatabase({
      url: new SecretValue(testDatabase(inject('databaseName')).url('worker')),
      logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
      poolMax: 1,
    });
    try {
      const { roomsDeleted } = await runRoomCleanup(worker.prisma);
      expect(roomsDeleted).toBeGreaterThanOrEqual(1);
    } finally {
      await worker.close();
    }
    expect((await roomRow(db, empty)).status).toBe('DELETED');
    // An envelope is left: the room stays DELETING (and inaccessible) instead of DELETED.
    expect((await roomRow(db, withEnvelope)).status).toBe('DELETING');
    expect((await roomRow(db, active)).status).toBe('ACTIVE');
  });
});
