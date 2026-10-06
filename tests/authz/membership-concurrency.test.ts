import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import {
  activeOwners,
  addMember,
  createRoom,
  memberships,
  person,
  personWithVault,
  roomRow,
  stepUp,
  whileLocked,
  type Person,
} from '../helpers/rooms';

// CM-T031 concurrency. A decision taken when a request arrives must not outlive a concurrent
// change. Each test holds the room row lock itself, starts two requests, waits until PostgreSQL
// reports both blocked behind that lock (so both passed the central gate with the same, soon
// stale, state), then releases the lock. Whichever writer comes second is re-authorized on the
// state the first one left, inside its own transaction; the invariants hold for either order.
let api: AuthTestApi;
let db: pg.Client;
let owner: Person;
let admin: Person;
let admin2: Person;
let member: Person;

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  owner = await personWithVault(api, db);
  [admin, admin2, member] = [await person(api), await person(api), await person(api)];
});
afterAll(async () => {
  await api.close();
  await db.end();
});

async function staffedRoom(): Promise<string> {
  const roomId = await createRoom(owner);
  await addMember(db, roomId, admin.userId, 'ADMIN');
  await addMember(db, roomId, admin2.userId, 'ADMIN');
  await addMember(db, roomId, member.userId, 'MEMBER');
  return roomId;
}

/** Holds the room row lock while both requests start (see whileLocked). */
const racing = <T>(roomId: string, start: () => Promise<T>): Promise<T> =>
  whileLocked(db, 'SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [roomId], start);

const changeRole = (who: Person, roomId: string, target: Person, role: string) =>
  who.browser.request('POST', `/rooms/${roomId}/members/${target.userId}/role`, { role });
const remove = (who: Person, roomId: string, target: Person) =>
  who.browser.request('POST', `/rooms/${roomId}/members/${target.userId}/remove`, {});
const transfer = (who: Person, roomId: string, target: Person) =>
  who.browser.request('POST', `/rooms/${roomId}/members/${target.userId}/transfer-ownership`, {});
const statuses = (responses: readonly { status: number }[]) => responses.map((r) => r.status).sort();
const roleOf = async (roomId: string, who: Person) =>
  (await memberships(db, roomId)).find((m) => m.user_id === who.userId && m.status !== 'REMOVED')?.role;

describe('concurrent membership changes (CM-T031)', () => {
  it('two concurrent ownership transfers leave exactly one OWNER', async () => {
    for (let round = 0; round < 3; round += 1) {
      const roomId = await staffedRoom();
      await stepUp(api, owner);
      const responses = await racing(roomId, () =>
        Promise.all([transfer(owner, roomId, admin), transfer(owner, roomId, admin2)]),
      );
      // The second transfer is re-checked after the first: its caller is now an ADMIN.
      expect(statuses(responses)).toEqual([200, 403]);
      const owners = await activeOwners(db, roomId);
      expect(owners).toHaveLength(1);
      expect([admin.userId, admin2.userId]).toContain(owners[0]);
      expect(await roleOf(roomId, owner)).toBe('ADMIN');
    }
  });

  it('an ADMIN demotion racing an OWNER promotion never lets the ADMIN demote an ADMIN', async () => {
    const roomId = await staffedRoom();
    api.events.length = 0;
    const [byOwner, byAdmin] = await racing(roomId, () =>
      Promise.all([changeRole(owner, roomId, member, 'ADMIN'), changeRole(admin, roomId, member, 'VIEWER')]),
    );
    expect(byOwner.status).toBe(200);
    expect(await roleOf(roomId, member)).toBe('ADMIN');
    const promotion = api.events.find((e) => e.name === 'MEMBER_ROLE_CHANGED' && e.actorUserId === owner.userId);
    // Either the ADMIN came first (MEMBER to VIEWER, then VIEWER to ADMIN), or it was refused
    // because the target was already an ADMIN.
    if (byAdmin.status === 200) expect(promotion?.details?.['from']).toBe('VIEWER');
    else {
      expect(byAdmin.status).toBe(403);
      expect(promotion?.details?.['from']).toBe('MEMBER');
    }
  });

  it('two concurrent removals of one member succeed once and lock the room once', async () => {
    const roomId = await staffedRoom();
    const before = (await roomRow(db, roomId)).epoch;
    const responses = await racing(roomId, () =>
      Promise.all([remove(owner, roomId, member), remove(admin, roomId, member)]),
    );
    expect(statuses(responses)).toEqual([200, 404]);
    expect(await roomRow(db, roomId)).toMatchObject({
      key_state: 'REKEY_REQUIRED',
      rekey_reasons: '{MEMBER_REMOVED}',
      epoch: before + 1,
    });
  });

  it('a role change racing a removal never resurrects the removed member', async () => {
    const roomId = await staffedRoom();
    const [removal, change] = await racing(roomId, () =>
      Promise.all([remove(owner, roomId, member), changeRole(admin, roomId, member, 'VIEWER')]),
    );
    expect(removal.status).toBe(200);
    expect([200, 404]).toContain(change.status);
    expect((await memberships(db, roomId)).filter((m) => m.user_id === member.userId).map((m) => m.status)).toEqual([
      'REMOVED',
    ]);
  });

  it('an ownership transfer racing a role change of the same ADMIN lets exactly one through', async () => {
    const roomId = await staffedRoom();
    await stepUp(api, owner);
    const responses = await racing(roomId, () =>
      Promise.all([transfer(owner, roomId, admin), changeRole(owner, roomId, admin, 'MEMBER')]),
    );
    // Transfer first: the caller is an ADMIN and the target the OWNER. Role change first: the
    // target is a MEMBER and cannot become OWNER. Never both.
    expect(statuses(responses)).toEqual([200, 403]);
    expect(await activeOwners(db, roomId)).toHaveLength(1);
  });

  it('a deletion racing a role change or a rename leaves the room DELETING and unreachable', async () => {
    for (const second of [
      (roomId: string) => changeRole(admin, roomId, member, 'VIEWER'),
      (roomId: string) => admin.browser.request('POST', `/rooms/${roomId}/rename`, { name: 'Racing' }),
    ]) {
      const roomId = await staffedRoom();
      await stepUp(api, owner);
      const [deletion, other] = await racing(roomId, () =>
        Promise.all([owner.browser.request('POST', `/rooms/${roomId}/delete`, {}), second(roomId)]),
      );
      expect(deletion.status).toBe(200);
      expect([200, 404]).toContain(other.status);
      expect((await roomRow(db, roomId)).status).toBe('DELETING');
      expect((await admin.browser.request('GET', `/rooms/${roomId}`)).status).toBe(404);
    }
  });
});
