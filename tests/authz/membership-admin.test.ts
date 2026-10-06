import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { Database } from '../../apps/api/src/db/client';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import {
  activeOwners,
  addMember,
  apiDatabase,
  createRoom,
  errorOf,
  insertDummyEnvelope,
  memberships,
  NOT_FOUND_BODY,
  person,
  personWithVault,
  platformAdministrator,
  roomRow,
  stepUp,
  type Person,
} from '../helpers/rooms';

// CM-T031: role changes (AZ-10), member removal (AZ-09) and ownership transfer (AZ-05) against
// the real API and PostgreSQL as cm_api. The matrix is the one in authorization-model.md
// section 3; every target is loaded by room ID and user ID (OL-02).
let api: AuthTestApi;
let db: pg.Client;
let database: Database;
let owner: Person;
let admin: Person;
let admin2: Person;
let member: Person;
let viewer: Person;
let outsider: Person;

type Role = 'OWNER' | 'ADMIN' | 'MEMBER' | 'VIEWER';
const ASSIGNABLE = ['ADMIN', 'MEMBER', 'VIEWER'] as const;

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  database = apiDatabase();
  owner = await personWithVault(api, db);
  [admin, admin2, member, viewer] = [await person(api), await person(api), await person(api), await person(api)];
  outsider = await personWithVault(api, db);
});
afterAll(async () => {
  await api.close();
  await database.close();
  await db.end();
});

/** A room of `owner` with admin, admin2, member and viewer as members. */
async function staffedRoom(): Promise<string> {
  const roomId = await createRoom(owner);
  await addMember(db, roomId, admin.userId, 'ADMIN');
  await addMember(db, roomId, admin2.userId, 'ADMIN');
  await addMember(db, roomId, member.userId, 'MEMBER');
  await addMember(db, roomId, viewer.userId, 'VIEWER');
  return roomId;
}

const setRole = (roomId: string, userId: string, role: Role) =>
  db.query(`UPDATE room_members SET role = $3 WHERE room_id = $1 AND user_id = $2 AND status = 'ACTIVE'`, [
    roomId,
    userId,
    role,
  ]);
const roleOf = async (roomId: string, userId: string) =>
  (await memberships(db, roomId)).find((m) => m.user_id === userId && m.status !== 'REMOVED')?.role;

const changeRole = (who: Person, roomId: string, targetId: string, role: string) =>
  who.browser.request('POST', `/rooms/${roomId}/members/${targetId}/role`, { role });
const remove = (who: Person, roomId: string, targetId: string) =>
  who.browser.request('POST', `/rooms/${roomId}/members/${targetId}/remove`, {});
const transfer = (who: Person, roomId: string, targetId: string) =>
  who.browser.request('POST', `/rooms/${roomId}/members/${targetId}/transfer-ownership`, {});

describe('role changes (AZ-10)', () => {
  it('lets the OWNER change any member among ADMIN, MEMBER and VIEWER', async () => {
    const roomId = await staffedRoom();
    for (const from of ASSIGNABLE) {
      for (const to of ASSIGNABLE) {
        await setRole(roomId, member.userId, from);
        const response = await changeRole(owner, roomId, member.userId, to);
        expect(response.status, `${from} to ${to}`).toBe(200);
        expect(response.body).toEqual({ userId: member.userId, role: to });
        expect(await roleOf(roomId, member.userId)).toBe(to);
      }
    }
  });

  it('lets an ADMIN change only between MEMBER and VIEWER', async () => {
    const roomId = await staffedRoom();
    for (const from of ASSIGNABLE) {
      for (const to of ASSIGNABLE) {
        await setRole(roomId, member.userId, from);
        const allowed = from !== 'ADMIN' && to !== 'ADMIN';
        const response = await changeRole(admin, roomId, member.userId, to);
        expect(response.status, `${from} to ${to}`).toBe(allowed ? 200 : 403);
        expect(await roleOf(roomId, member.userId)).toBe(allowed ? to : from);
      }
    }
    // Never the OWNER, never another ADMIN, never itself.
    for (const target of [owner, admin2, admin]) {
      const response = await changeRole(admin, roomId, target.userId, 'VIEWER');
      expect(response.status).toBe(403);
      expect(errorCode(response)).toBe('FORBIDDEN');
    }
    expect(await roleOf(roomId, admin.userId)).toBe('ADMIN');
  });

  it('refuses MEMBER and VIEWER callers', async () => {
    const roomId = await staffedRoom();
    for (const caller of [member, viewer]) {
      for (const target of [viewer, member]) {
        expect((await changeRole(caller, roomId, target.userId, 'MEMBER')).status).toBe(403);
      }
    }
    expect(await roleOf(roomId, viewer.userId)).toBe('VIEWER');
  });

  it('never makes an OWNER: the schema refuses it and the OWNER cannot change its own role', async () => {
    const roomId = await staffedRoom();
    const asOwner = await changeRole(owner, roomId, admin.userId, 'OWNER');
    expect(asOwner.status).toBe(400);
    expect(errorCode(asOwner)).toBe('VALIDATION_FAILED');
    expect((await changeRole(owner, roomId, owner.userId, 'ADMIN')).status).toBe(403);
    expect(await activeOwners(db, roomId)).toEqual([owner.userId]);
    for (const role of ['owner', 'SUPERADMIN', 'PLATFORM_ADMIN', '']) {
      expect((await changeRole(owner, roomId, member.userId, role)).status).toBe(400);
    }
  });

  it('answers 404 for a target in another room, a non-member and a suspended member (OL-02)', async () => {
    const roomId = await staffedRoom();
    const otherRoom = await createRoom(outsider);
    const stranger = await person(api);
    await addMember(db, otherRoom, stranger.userId, 'MEMBER');
    const suspended = await person(api);
    await addMember(db, roomId, suspended.userId, 'MEMBER', { status: 'SUSPENDED' });
    for (const target of [stranger.userId, outsider.userId, randomUUID(), suspended.userId]) {
      expect(errorOf(await changeRole(owner, roomId, target, 'VIEWER'))).toEqual(NOT_FOUND_BODY);
    }
    // Nor can the owner of room A reach a member of room B through room B's path.
    expect(errorOf(await changeRole(owner, otherRoom, stranger.userId, 'VIEWER'))).toEqual(NOT_FOUND_BODY);
    expect(await roleOf(otherRoom, stranger.userId)).toBe('MEMBER');
  });

  it('increments the membership epoch, records MEMBER_ROLE_CHANGED, and treats an unchanged role as a no-op', async () => {
    const roomId = await staffedRoom();
    const before = (await roomRow(db, roomId)).epoch;
    api.events.length = 0;
    expect((await changeRole(owner, roomId, member.userId, 'VIEWER')).status).toBe(200);
    expect((await roomRow(db, roomId)).epoch).toBe(before + 1);
    expect(api.events.find((e) => e.name === 'MEMBER_ROLE_CHANGED')).toMatchObject({
      actorUserId: owner.userId,
      targetUserId: member.userId,
      details: { roomId, from: 'MEMBER', to: 'VIEWER' },
    });
    expect((await changeRole(owner, roomId, member.userId, 'VIEWER')).status).toBe(200);
    expect((await roomRow(db, roomId)).epoch).toBe(before + 1);
    expect(api.events.filter((e) => e.name === 'MEMBER_ROLE_CHANGED')).toHaveLength(1);
    // A role change is not a member loss: the room stays writable.
    expect((await roomRow(db, roomId)).key_state).toBe('ACTIVE');
  });
});

describe('member removal (AZ-09, INV-07)', () => {
  it('lets the OWNER remove ADMIN, MEMBER and VIEWER, and an ADMIN remove MEMBER and VIEWER', async () => {
    const byOwner = await staffedRoom();
    for (const target of [admin, member, viewer]) {
      const response = await remove(owner, byOwner, target.userId);
      expect(response.status).toBe(200);
      expect(response.body).toEqual({ userId: target.userId, status: 'REMOVED', rekeyRequired: true });
    }
    const byAdmin = await staffedRoom();
    for (const target of [member, viewer]) expect((await remove(admin, byAdmin, target.userId)).status).toBe(200);
  });

  it('never removes the OWNER, and an ADMIN never removes an ADMIN or itself', async () => {
    const roomId = await staffedRoom();
    for (const [caller, target] of [
      [owner, owner],
      [admin, owner],
      [admin, admin2],
      [admin, admin],
      [member, viewer],
      [viewer, member],
    ] as const) {
      const response = await remove(caller, roomId, target.userId);
      expect(response.status).toBe(403);
    }
    expect((await memberships(db, roomId)).every((m) => m.status === 'ACTIVE')).toBe(true);
    expect((await roomRow(db, roomId)).key_state).toBe('ACTIVE');
  });

  it('removes in one transaction: REMOVED, envelopes deleted, epoch incremented, REKEY_REQUIRED', async () => {
    const roomId = await staffedRoom();
    await insertDummyEnvelope(db, roomId, member.userId, owner.userId);
    await insertDummyEnvelope(db, roomId, viewer.userId, owner.userId);
    const before = (await roomRow(db, roomId)).epoch;
    api.events.length = 0;
    expect((await remove(admin, roomId, member.userId)).status).toBe(200);

    expect((await memberships(db, roomId)).find((m) => m.user_id === member.userId)).toMatchObject({
      status: 'REMOVED',
      removal_reason: 'REMOVED_BY_ADMIN',
    });
    const { rows } = await db.query<{ recipient: string }>(
      'SELECT recipient_user_id::text AS recipient FROM key_envelopes WHERE room_id = $1',
      [roomId],
    );
    expect(rows.map((row) => row.recipient)).toEqual([viewer.userId]);
    expect(await roomRow(db, roomId)).toMatchObject({
      key_state: 'REKEY_REQUIRED',
      rekey_reasons: '{MEMBER_REMOVED}',
      epoch: before + 1,
    });
    expect(api.events.map((e) => e.name)).toEqual(['MEMBER_REMOVED', 'REKEY_REQUIRED']);
    expect(api.events[1]?.details).toEqual({ roomId, reason: 'MEMBER_REMOVED' });

    // A second loss keeps the room locked, records no second REKEY_REQUIRED and adds no duplicate reason.
    api.events.length = 0;
    expect((await remove(owner, roomId, viewer.userId)).status).toBe(200);
    expect(await roomRow(db, roomId)).toMatchObject({ rekey_reasons: '{MEMBER_REMOVED}', epoch: before + 2 });
    expect(api.events.map((e) => e.name)).toEqual(['MEMBER_REMOVED']);
  });

  it('ends the removed member access at once, and the room stays administrable while locked', async () => {
    const roomId = await staffedRoom();
    expect((await remove(owner, roomId, viewer.userId)).status).toBe(200);
    for (const path of [`/rooms/${roomId}`, `/rooms/${roomId}/members`]) {
      expect(errorOf(await viewer.browser.request('GET', path))).toEqual(NOT_FOUND_BODY);
    }
    expect(errorOf(await remove(owner, roomId, viewer.userId))).toEqual(NOT_FOUND_BODY);
    // REKEY_REQUIRED blocks content writes and invitations (PC-16), not membership administration.
    expect((await changeRole(owner, roomId, member.userId, 'VIEWER')).status).toBe(200);
  });

  it('removes a SUSPENDED member, and answers 404 for targets outside the room', async () => {
    const roomId = await staffedRoom();
    const suspended = await person(api);
    await addMember(db, roomId, suspended.userId, 'MEMBER', { status: 'SUSPENDED' });
    expect((await remove(owner, roomId, suspended.userId)).status).toBe(200);
    const otherRoom = await createRoom(outsider);
    const stranger = await person(api);
    await addMember(db, otherRoom, stranger.userId, 'VIEWER');
    expect(errorOf(await remove(owner, roomId, stranger.userId))).toEqual(NOT_FOUND_BODY);
    expect(errorOf(await remove(owner, otherRoom, stranger.userId))).toEqual(NOT_FOUND_BODY);
    expect((await memberships(db, otherRoom)).find((m) => m.user_id === stranger.userId)?.status).toBe('ACTIVE');
    expect((await roomRow(db, otherRoom)).key_state).toBe('ACTIVE');
  });
});

describe('ownership transfer (AZ-05)', () => {
  it('moves ownership to a current ADMIN with a step-up; the former OWNER becomes an ADMIN', async () => {
    const roomId = await staffedRoom();
    await stepUp(api, owner);
    const before = (await roomRow(db, roomId)).epoch;
    api.events.length = 0;
    const response = await transfer(owner, roomId, admin.userId);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ ownerUserId: admin.userId, formerOwnerRole: 'ADMIN' });
    expect(await activeOwners(db, roomId)).toEqual([admin.userId]);
    expect(await roleOf(roomId, owner.userId)).toBe('ADMIN');
    expect((await roomRow(db, roomId)).epoch).toBe(before + 1);
    expect(api.events.find((e) => e.name === 'OWNERSHIP_TRANSFERRED')).toMatchObject({
      actorUserId: owner.userId,
      targetUserId: admin.userId,
      details: { roomId },
    });
    // The former OWNER lost the OWNER-only actions; the new OWNER has them.
    expect((await transfer(owner, roomId, admin2.userId)).status).toBe(403);
    expect((await owner.browser.request('POST', `/rooms/${roomId}/delete`, {})).status).toBe(403);
    await stepUp(api, admin);
    expect((await transfer(admin, roomId, owner.userId)).status).toBe(200);
    expect(await activeOwners(db, roomId)).toEqual([owner.userId]);
  });

  it('refuses a MEMBER, a VIEWER, the OWNER itself, a suspended ADMIN and non-members as the new OWNER', async () => {
    const roomId = await staffedRoom();
    const suspendedAdmin = await person(api);
    await addMember(db, roomId, suspendedAdmin.userId, 'ADMIN', { status: 'SUSPENDED' });
    await stepUp(api, owner);
    for (const target of [member, viewer, owner])
      expect((await transfer(owner, roomId, target.userId)).status).toBe(403);
    for (const target of [suspendedAdmin.userId, outsider.userId, randomUUID()]) {
      expect(errorOf(await transfer(owner, roomId, target))).toEqual(NOT_FOUND_BODY);
    }
    expect(await activeOwners(db, roomId)).toEqual([owner.userId]);
  });

  it('is OWNER-only: ADMIN, MEMBER, VIEWER and a PLATFORM_ADMIN cannot transfer', async () => {
    const roomId = await staffedRoom();
    for (const caller of [admin, member, viewer]) {
      await stepUp(api, caller);
      const response = await transfer(caller, roomId, admin2.userId);
      expect(response.status).toBe(403);
    }
    const platform = await platformAdministrator(api, database);
    await stepUp(api, platform, platform.secret);
    expect(errorOf(await transfer(platform, roomId, admin.userId))).toEqual(NOT_FOUND_BODY);
    expect(await activeOwners(db, roomId)).toEqual([owner.userId]);
  });

  it('needs a step-up in every profile, and changes nothing without it', async () => {
    const roomId = await staffedRoom();
    const fresh = await personWithVault(api, db);
    const room2 = await createRoom(fresh);
    await addMember(db, room2, admin.userId, 'ADMIN');
    const response = await transfer(fresh, room2, admin.userId);
    expect(response.status).toBe(401);
    expect(errorCode(response)).toBe('STEP_UP_REQUIRED');
    expect(await activeOwners(db, room2)).toEqual([fresh.userId]);
    expect(await activeOwners(db, roomId)).toEqual([owner.userId]);
  });

  it('never accepts an ADMIN of another room as the new OWNER (OL-02)', async () => {
    const roomId = await staffedRoom();
    const otherRoom = await createRoom(outsider);
    const foreignAdmin = await person(api);
    await addMember(db, otherRoom, foreignAdmin.userId, 'ADMIN');
    await stepUp(api, owner);
    expect(errorOf(await transfer(owner, roomId, foreignAdmin.userId))).toEqual(NOT_FOUND_BODY);
    expect(errorOf(await transfer(owner, otherRoom, foreignAdmin.userId))).toEqual(NOT_FOUND_BODY);
    expect(await activeOwners(db, roomId)).toEqual([owner.userId]);
    expect(await activeOwners(db, otherRoom)).toEqual([outsider.userId]);
  });
});
