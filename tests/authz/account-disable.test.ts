import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { Database } from '../../apps/api/src/db/client';
import { Browser, errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import {
  addMember,
  apiDatabase,
  createRoom,
  insertDummyEnvelope,
  memberships,
  personWithVault,
  platformAdministrator,
  roomRow,
  stepUp,
  whileLocked,
  type Person,
} from '../helpers/rooms';

// PA-03 and key-lifecycle R3 (Phase 5): disabling an account suspends every ACTIVE room
// membership of it and sets those rooms to REKEY_REQUIRED with MEMBER_SUSPENDED, in the same
// transaction that disables the account and revokes its sessions (INV-07). No key is created;
// the rekey itself belongs to Phase 11.
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

async function adminRequest(path: string, userId: string) {
  await stepUp(api, platform, platform.secret);
  return platform.browser.request('POST', path, { userId });
}
const disable = (userId: string) => adminRequest('/admin/users/disable', userId);
const enable = (userId: string) => adminRequest('/admin/users/enable', userId);
const membershipOf = async (roomId: string, userId: string) =>
  (await memberships(db, roomId)).find((m) => m.user_id === userId);
const envelopeRecipients = async (roomId: string) =>
  (
    await db.query<{ r: string }>('SELECT recipient_user_id::text AS r FROM key_envelopes WHERE room_id = $1', [roomId])
  ).rows.map((row) => row.r);

describe('disabling an account (PA-03) suspends its room memberships', () => {
  let target: Person;
  let other: Person;
  let asMember: string;
  let asOwner: string;
  let unrelated: string;
  let formerRoom: string;

  beforeAll(async () => {
    target = await personWithVault(api, db);
    other = await personWithVault(api, db);
    asMember = await createRoom(other);
    await addMember(db, asMember, target.userId, 'MEMBER');
    asOwner = await createRoom(target);
    unrelated = await createRoom(other);
    formerRoom = await createRoom(other);
    await addMember(db, formerRoom, target.userId, 'VIEWER', {
      status: 'REMOVED',
      removed_at: new Date(),
      removal_reason: 'REMOVED_BY_ADMIN',
    });
    await insertDummyEnvelope(db, asMember, target.userId, other.userId);
    await insertDummyEnvelope(db, unrelated, other.userId, other.userId);
  });

  it('starts from ACTIVE memberships and writable rooms', async () => {
    expect((await membershipOf(asMember, target.userId))?.status).toBe('ACTIVE');
    expect((await membershipOf(asOwner, target.userId))?.status).toBe('ACTIVE');
    expect((await target.browser.request('GET', `/rooms/${asMember}`)).status).toBe(200);
  });

  it('suspends every ACTIVE membership, locks those rooms and deletes the envelopes, in one step', async () => {
    const epochs: number[] = [];
    // One query at a time: a pg client runs one query at once.
    for (const roomId of [asMember, asOwner, unrelated, formerRoom]) epochs.push((await roomRow(db, roomId)).epoch);
    api.events.length = 0;
    const response = await disable(target.userId);
    expect(response.status).toBe(200);

    for (const [roomId, role] of [
      [asMember, 'MEMBER'],
      [asOwner, 'OWNER'],
    ] as const) {
      // The role is kept, so an OWNER or ADMIN can reinstate the member later (AZ-14).
      expect(await membershipOf(roomId, target.userId)).toEqual({
        user_id: target.userId,
        role,
        status: 'SUSPENDED',
        removal_reason: 'ACCOUNT_DISABLED',
      });
    }
    expect(await roomRow(db, asMember)).toMatchObject({
      key_state: 'REKEY_REQUIRED',
      rekey_reasons: '{MEMBER_SUSPENDED}',
      epoch: (epochs[0] ?? 0) + 1,
    });
    expect(await roomRow(db, asOwner)).toMatchObject({
      key_state: 'REKEY_REQUIRED',
      rekey_reasons: '{MEMBER_SUSPENDED}',
      epoch: (epochs[1] ?? 0) + 1,
    });
    // Unrelated rooms and departed memberships are untouched.
    expect(await roomRow(db, unrelated)).toMatchObject({ key_state: 'ACTIVE', epoch: epochs[2] });
    expect(await roomRow(db, formerRoom)).toMatchObject({ key_state: 'ACTIVE', epoch: epochs[3] });
    expect((await membershipOf(formerRoom, target.userId))?.status).toBe('REMOVED');
    expect(await envelopeRecipients(asMember)).toEqual([]);
    expect(await envelopeRecipients(unrelated)).toEqual([other.userId]);

    const disabled = api.events.find((e) => e.name === 'ACCOUNT_DISABLED');
    expect(disabled?.details).toMatchObject({ membershipsSuspended: 2 });
    const suspendedRooms = api.events.filter((e) => e.name === 'MEMBER_SUSPENDED').map((e) => e.details?.['roomId']);
    expect(suspendedRooms.sort()).toEqual([asMember, asOwner].sort());
    expect(api.events.filter((e) => e.name === 'REKEY_REQUIRED').map((e) => e.details)).toEqual(
      expect.arrayContaining([
        { roomId: asMember, reason: 'MEMBER_SUSPENDED' },
        { roomId: asOwner, reason: 'MEMBER_SUSPENDED' },
      ]),
    );
  });

  it('leaves the disabled user no way into the rooms, and the other members keep them', async () => {
    for (const path of ['/rooms', `/rooms/${asMember}`, `/rooms/${asOwner}/members`]) {
      const response = await target.browser.request('GET', path);
      expect(response.status).toBe(401);
      expect(errorCode(response)).toBe('UNAUTHENTICATED');
    }
    const view = await other.browser.request('GET', `/rooms/${asMember}/members`);
    expect(view.status).toBe(200);
    const listed = (view.body['members'] as { userId: string; status: string }[]).find(
      (m) => m.userId === target.userId,
    );
    expect(listed?.status).toBe('SUSPENDED');
  });

  it('is harmless when repeated', async () => {
    const before = await roomRow(db, asMember);
    api.events.length = 0;
    expect((await disable(target.userId)).status).toBe(200);
    expect(await roomRow(db, asMember)).toEqual(before);
    expect(api.events.filter((e) => e.name === 'MEMBER_SUSPENDED')).toEqual([]);
  });

  it('re-enabling restores the login but not the memberships (reinstatement is AZ-14, Phase 6)', async () => {
    expect((await enable(target.userId)).status).toBe(200);
    const browser = new Browser(api);
    expect((await browser.login({ email: target.email, password: target.password })).status).toBe(200);
    expect((await browser.request('GET', '/rooms')).body).toEqual({ rooms: [], nextCursor: null });
    expect((await browser.request('GET', `/rooms/${asOwner}`)).status).toBe(404);
    expect((await membershipOf(asOwner, target.userId))?.status).toBe('SUSPENDED');
    // The room has no ACTIVE OWNER now; OWNER-only actions wait for reinstatement (model 2.1).
    expect((await roomRow(db, asOwner)).key_state).toBe('REKEY_REQUIRED');
  });
});

describe('disabling an account while the same user creates a room', () => {
  it('never leaves an ACTIVE membership for a disabled account', async () => {
    for (let round = 0; round < 2; round += 1) {
      const user = await personWithVault(api, db);
      await stepUp(api, platform, platform.secret);
      const roomId = randomUUID();
      // Both transactions need the user row: the creation to check the account, the disable to
      // change it. Holding it makes them overlap; either may win.
      const [created, disabled] = await whileLocked(
        db,
        'SELECT id FROM users WHERE id = $1 FOR UPDATE',
        [user.userId],
        () =>
          Promise.all([
            user.browser.request('POST', '/rooms', { roomId, name: 'Racing', securityProfile: 'STANDARD' }),
            platform.browser.request('POST', '/admin/users/disable', { userId: user.userId }),
          ]),
      );
      expect(disabled.status).toBe(200);
      expect([201, 401]).toContain(created.status);
      const { rows } = await db.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM room_members WHERE user_id = $1 AND status = 'ACTIVE'",
        [user.userId],
      );
      expect(rows).toEqual([{ n: 0 }]);
      if (created.status === 201) {
        expect((await membershipOf(roomId, user.userId))?.status).toBe('SUSPENDED');
        expect((await roomRow(db, roomId)).key_state).toBe('REKEY_REQUIRED');
      }
    }
  });
});
