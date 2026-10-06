import { ROOM_ROLES } from '@ciphermesh/shared';
import { emptyQuerySchema, uuidV4Schema, z } from '@ciphermesh/validation';
import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { changePlatformRole } from '../../apps/api/src/auth/admin';
import { SecretValue } from '../../apps/api/src/config/secret';
import { authDataAccess } from '../../apps/api/src/db/auth-store';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { createRoomAccessStore, type RoomAccessStore } from '../../apps/api/src/db/room-access-store';
import { createLogger } from '../../apps/api/src/logging/logger';
import { defineRoute, roomOf, type AnyRoute } from '../../apps/api/src/routes/registry';
import {
  Browser,
  errorCode,
  signedInUser,
  startAuthApi,
  totpCode,
  userWithMfa,
  type AuthTestApi,
} from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { insertMember, insertRoomWithoutKeys } from '../helpers/db-fixtures';

// CM-T029: the central room authorization end to end. Test-only room routes go through the
// production registry and the production authorizer; users, sessions and memberships are real
// rows in PostgreSQL, written as the least-privilege API role. Nothing in the authorization path
// is mocked. Room CRUD arrives in CM-T030, so rooms are inserted as fixtures without key material.

const roomParams = z.strictObject({ roomId: uuidV4Schema });
const memberParams = z.strictObject({ roomId: uuidV4Schema, userId: uuidV4Schema });
const accessResponse = z.strictObject({
  roomId: uuidV4Schema,
  role: z.enum(ROOM_ROLES),
  action: z.string(),
  roles: z.array(z.enum(ROOM_ROLES)),
});

let loaderCalls = 0;

/** Probe routes: they change nothing and answer with the access the registry handed them. */
function probeRoutes(store: RoomAccessStore): AnyRoute[] {
  const answer = (ctx: Parameters<typeof roomOf>[0]) => {
    const room = roomOf(ctx);
    return {
      status: 200,
      body: { roomId: room.roomId, role: room.role, action: room.action, roles: [...(room.resource?.roles ?? [])] },
    };
  };
  return [
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/authz-probe',
      action: 'AZ-01-AUTHZ-PROBE',
      access: { kind: 'room' },
      params: roomParams,
      query: emptyQuerySchema,
      body: undefined,
      response: accessResponse,
      handler: answer,
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/authz-probe/rename',
      action: 'AZ-02-AUTHZ-PROBE',
      access: { kind: 'room' },
      params: roomParams,
      query: emptyQuerySchema,
      body: z.strictObject({}),
      response: accessResponse,
      handler: answer,
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/authz-probe/delete',
      action: 'AZ-04-AUTHZ-PROBE',
      access: { kind: 'room', requires: { stepUp: 'standard' } },
      params: roomParams,
      query: emptyQuerySchema,
      body: z.strictObject({}),
      response: accessResponse,
      handler: answer,
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/authz-probe/members/:userId/role',
      action: 'AZ-10-AUTHZ-PROBE',
      access: {
        kind: 'room',
        // The target is loaded by (room ID, user ID): a member of another room is not found.
        resource: async ({ room, params, body }) => {
          loaderCalls += 1;
          const target = await store.findActiveMembership(room.roomId, params.userId);
          return target === null ? null : { roomId: target.roomId, roles: [target.role, body.role] };
        },
      },
      params: memberParams,
      query: emptyQuerySchema,
      // Deliberately wider than any real route: the matrix, not the schema, must refuse OWNER.
      body: z.strictObject({ role: z.enum(ROOM_ROLES) }),
      response: accessResponse,
      handler: answer,
    }),
  ];
}

interface Person {
  readonly browser: Browser;
  readonly userId: string;
  readonly password: string;
}

let api: AuthTestApi;
let database: Database;
let db: pg.Client;
let owner: Person;
let admin: Person;
let member: Person;
let viewer: Person;
let outsider: Person;
let platformAdmin: Person & { readonly secret: string };
let roomA: string;
let roomB: string;

const userIdOf = async (browser: Browser): Promise<string> =>
  ((await browser.request('GET', '/auth/session')).body['user'] as { id: string }).id;

async function person(): Promise<Person> {
  const { identity, browser } = await signedInUser(api);
  return { browser, userId: await userIdOf(browser), password: identity.password };
}

/** A PLATFORM_ADMIN (granted through the server-side path) with an MFA-verified session. */
async function platformAdministrator(): Promise<Person & { readonly secret: string }> {
  const user = await userWithMfa(api);
  const data = authDataAccess(database.prisma);
  const deps = { transaction: data.transaction, events: { record: () => undefined }, clock: api.clock.now };
  expect(await changePlatformRole(deps, user.identity.email, 'PLATFORM_ADMIN')).toBe('changed');
  const browser = new Browser(api);
  await browser.login(user.identity);
  await browser.request('POST', '/auth/mfa/verify', { code: totpCode(user.secret, api.clock) });
  api.clock.advance(30_000);
  return { browser, userId: await userIdOf(browser), password: user.identity.password, secret: user.secret };
}

const stepUp = async (who: Person, code?: string) => {
  const response = await who.browser.request('POST', '/auth/step-up', {
    password: who.password,
    ...(code === undefined ? {} : { code }),
  });
  expect(response.status).toBe(200);
};

const read = (who: Person, room: string) => who.browser.request('GET', `/rooms/${room}/authz-probe`);
const rename = (who: Person, room: string, extra: Record<string, string> = {}) =>
  who.browser.request('POST', `/rooms/${room}/authz-probe/rename`, {}, extra);
const destroy = (who: Person, room: string) => who.browser.request('POST', `/rooms/${room}/authz-probe/delete`, {});
const changeRole = (who: Person, room: string, target: string, role: string) =>
  who.browser.request('POST', `/rooms/${room}/authz-probe/members/${target}/role`, { role });

/** Every probe route, as the given person, against the given room. */
const everyRoute = (who: Person, room: string) => [
  read(who, room),
  rename(who, room),
  destroy(who, room),
  changeRole(who, room, owner.userId, 'VIEWER'),
];

const NOT_FOUND_BODY = { code: 'NOT_FOUND', message: 'Resource not found' };
const errorOf = (response: { body: Record<string, unknown> }) => {
  const error = response.body['error'] as Record<string, unknown> | undefined;
  return { code: error?.['code'], message: error?.['message'] };
};

beforeAll(async () => {
  loadDatabaseTestEnv();
  const test = testDatabase(inject('databaseName'));
  db = await test.connect('api');
  database = createDatabase({
    url: new SecretValue(test.url('api')),
    logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
    poolMax: 2,
  });
  api = await startAuthApi({ routes: probeRoutes(createRoomAccessStore(database.prisma)) });
  [owner, admin, member, viewer, outsider] = [
    await person(),
    await person(),
    await person(),
    await person(),
    await person(),
  ];
  platformAdmin = await platformAdministrator();
  roomA = await insertRoomWithoutKeys(db, owner.userId);
  await insertMember(db, roomA, admin.userId, { role: 'ADMIN' });
  await insertMember(db, roomA, member.userId, { role: 'MEMBER' });
  await insertMember(db, roomA, viewer.userId, { role: 'VIEWER' });
  // The outsider owns room B: full power there, nothing in room A.
  roomB = await insertRoomWithoutKeys(db, outsider.userId);
});
afterAll(async () => {
  await api.close();
  await database.close();
  await db.end();
});

describe('room routes: outsiders learn nothing (OL-01, T-05)', () => {
  it('an authenticated non-member gets the same 404 as for a room that does not exist', async () => {
    const ghost = randomUUID();
    for (const response of [
      ...(await Promise.all(everyRoute(outsider, roomA))),
      ...(await Promise.all(everyRoute(owner, ghost))),
    ]) {
      expect(response.status).toBe(404);
      expect(errorOf(response)).toEqual(NOT_FOUND_BODY);
      expect((response.body['error'] as Record<string, unknown>)['issues']).toBeUndefined();
    }
    const unknownPath = await owner.browser.request('GET', `/rooms/${roomA}/no-such-route`);
    expect(unknownPath.status).toBe(404);
    expect(errorOf(unknownPath)).toEqual(NOT_FOUND_BODY);
  });

  it('answers malformed room identifiers with the same 404, even for the OWNER', async () => {
    for (const bad of ['not-a-uuid', roomA.toUpperCase(), `${roomA}x`, '%20', `${roomA.slice(0, -1)}g`]) {
      const response = await read(owner, bad);
      expect(response.status).toBe(404);
      expect(errorOf(response)).toEqual(NOT_FOUND_BODY);
    }
    const badTarget = await changeRole(owner, roomA, 'not-a-uuid', 'VIEWER');
    expect(badTarget.status).toBe(404);
  });

  it('requires a session before any room logic', async () => {
    const anonymous = new Browser(api);
    for (const response of [
      await anonymous.request('GET', `/rooms/${roomA}/authz-probe`),
      await anonymous.request('POST', `/rooms/${roomA}/authz-probe/rename`, {}),
    ]) {
      expect(response.status).toBe(401);
      expect(errorCode(response)).toBe('UNAUTHENTICATED');
    }
  });

  it('never lets a membership in one room authorize another room (T-06)', async () => {
    for (const response of await Promise.all(everyRoute(admin, roomB))) expect(response.status).toBe(404);
    for (const response of await Promise.all(everyRoute(outsider, roomA))) expect(response.status).toBe(404);
    // The same people keep their own rooms.
    expect((await read(outsider, roomB)).body).toMatchObject({ roomId: roomB, role: 'OWNER' });
    expect((await read(admin, roomA)).body).toMatchObject({ roomId: roomA, role: 'ADMIN' });
  });

  it('gives a PLATFORM_ADMIN without a membership the 404 of an outsider, even after a step-up (PA-05)', async () => {
    for (const response of await Promise.all(everyRoute(platformAdmin, roomA))) {
      expect(response.status).toBe(404);
      expect(errorOf(response)).toEqual(NOT_FOUND_BODY);
    }
    await stepUp(platformAdmin, totpCode(platformAdmin.secret, api.clock));
    api.clock.advance(30_000);
    expect((await destroy(platformAdmin, roomA)).status).toBe(404);
  });

  it('gives a PLATFORM_ADMIN who is a member exactly that member role, nothing more', async () => {
    const roomC = await insertRoomWithoutKeys(db, owner.userId);
    await insertMember(db, roomC, platformAdmin.userId, { role: 'VIEWER' });
    expect((await read(platformAdmin, roomC)).body).toMatchObject({ roomId: roomC, role: 'VIEWER' });
    const denied = await rename(platformAdmin, roomC);
    expect(denied.status).toBe(403);
    expect(errorCode(denied)).toBe('FORBIDDEN');
  });
});

describe('room routes: the matrix with database-loaded roles (T-04)', () => {
  it('gives every role exactly its cells, and checks the matrix before asking for a step-up', async () => {
    const cases: [Person, string, number, number][] = [
      // who, role, AZ-01 read, AZ-02 rename
      [owner, 'OWNER', 200, 200],
      [admin, 'ADMIN', 200, 200],
      [member, 'MEMBER', 200, 403],
      [viewer, 'VIEWER', 200, 403],
    ];
    for (const [who, role, readStatus, renameStatus] of cases) {
      const reading = await read(who, roomA);
      expect(reading.status).toBe(readStatus);
      expect(reading.body).toMatchObject({ roomId: roomA, role, action: 'AZ-01' });
      expect((await rename(who, roomA)).status).toBe(renameStatus);
      // AZ-04 is OWNER-only: everyone else gets 403 at once, never a step-up prompt.
      if (role !== 'OWNER') {
        const deleting = await destroy(who, roomA);
        expect(deleting.status).toBe(403);
        expect(errorCode(deleting)).toBe('FORBIDDEN');
      }
    }
    const withoutStepUp = await destroy(owner, roomA);
    expect(withoutStepUp.status).toBe(401);
    expect(errorCode(withoutStepUp)).toBe('STEP_UP_REQUIRED');
    await stepUp(owner);
    expect((await destroy(owner, roomA)).body).toMatchObject({ role: 'OWNER', action: 'AZ-04' });
    // A step-up never turns a denied role into an allowed one.
    await stepUp(admin);
    expect((await destroy(admin, roomA)).status).toBe(403);
  });

  it('takes the role only from the membership row, never from headers or the request', async () => {
    const forged = {
      'x-room-role': 'OWNER',
      'x-user-id': owner.userId,
      'x-ciphermesh-role': 'ADMIN',
      'x-platform-role': 'PLATFORM_ADMIN',
    };
    const denied = await rename(viewer, roomA, forged);
    expect(denied.status).toBe(403);
    const reading = await viewer.browser.request('GET', `/rooms/${roomA}/authz-probe`, undefined, forged);
    expect(reading.body).toMatchObject({ role: 'VIEWER' });
    // Unknown request fields are rejected before any decision, so no field can carry a role.
    const withRole = await viewer.browser.request('POST', `/rooms/${roomA}/authz-probe/rename`, { role: 'OWNER' });
    expect(withRole.status).toBe(400);
    const withQuery = await viewer.browser.request('GET', `/rooms/${roomA}/authz-probe?role=OWNER`);
    expect(withQuery.status).toBe(400);
  });

  it('applies role changes and removals on the next request: nothing is cached', async () => {
    const roomD = await insertRoomWithoutKeys(db, owner.userId);
    const membershipId = await insertMember(db, roomD, member.userId, { role: 'ADMIN' });
    expect((await rename(member, roomD)).status).toBe(200);
    await db.query(`UPDATE room_members SET role = 'VIEWER' WHERE id = $1`, [membershipId]);
    expect((await rename(member, roomD)).status).toBe(403);
    expect((await read(member, roomD)).body).toMatchObject({ role: 'VIEWER' });
    await db.query(
      `UPDATE room_members SET status = 'REMOVED', removed_at = now(), removal_reason = 'REMOVED_BY_ADMIN' WHERE id = $1`,
      [membershipId],
    );
    expect((await read(member, roomD)).status).toBe(404);
  });

  it('treats SUSPENDED and LEFT memberships as no membership (OL-12)', async () => {
    const roomE = await insertRoomWithoutKeys(db, owner.userId);
    await insertMember(db, roomE, admin.userId, { role: 'ADMIN', status: 'SUSPENDED' });
    await insertMember(db, roomE, member.userId, {
      role: 'MEMBER',
      status: 'LEFT',
      removed_at: new Date(),
      removal_reason: 'LEFT_ROOM',
    });
    for (const who of [admin, member]) {
      for (const response of await Promise.all(everyRoute(who, roomE))) expect(response.status).toBe(404);
    }
  });

  it('refuses every request in a DELETING or DELETED room, even from its OWNER', async () => {
    for (const status of ['DELETING', 'DELETED']) {
      const roomF = await insertRoomWithoutKeys(db, owner.userId);
      expect((await read(owner, roomF)).status).toBe(200);
      await db.query('UPDATE rooms SET status = $2, deleted_at = now() WHERE id = $1', [roomF, status]);
      for (const response of await Promise.all(everyRoute(owner, roomF))) expect(response.status).toBe(404);
    }
  });
});

describe('room routes: object-dependent cells load the target within the room (OL-02, T-04)', () => {
  const expectRoleChange = async (who: Person, target: Person, role: string, status: number) => {
    const response = await changeRole(who, roomA, target.userId, role);
    expect(response.status, `${role} for ${target.userId} by ${who.userId}`).toBe(status);
    return response;
  };

  it('enforces the role ceilings of AZ-10 with the stored target role', async () => {
    const allowed = await expectRoleChange(admin, member, 'VIEWER', 200);
    expect(allowed.body).toMatchObject({ role: 'ADMIN', action: 'AZ-10', roles: ['MEMBER', 'VIEWER'] });
    await expectRoleChange(admin, viewer, 'MEMBER', 200);
    await expectRoleChange(admin, member, 'ADMIN', 403); // ADMINs never create ADMINs
    await expectRoleChange(admin, admin, 'MEMBER', 403); // nor change an ADMIN, themselves included
    await expectRoleChange(admin, owner, 'MEMBER', 403); // nor touch the OWNER
    await expectRoleChange(owner, admin, 'MEMBER', 200);
    await expectRoleChange(owner, member, 'ADMIN', 200);
    await expectRoleChange(owner, owner, 'ADMIN', 403); // ownership changes only by transfer (AZ-05)
    await expectRoleChange(owner, member, 'OWNER', 403);
  });

  it('treats a target outside the room as not found, and never looks it up for refused callers', async () => {
    await expectRoleChange(owner, outsider, 'VIEWER', 404); // the OWNER of room B is nobody in room A
    expect((await changeRole(owner, roomA, randomUUID(), 'VIEWER')).status).toBe(404);
    const before = loaderCalls;
    await expectRoleChange(member, viewer, 'MEMBER', 403);
    await expectRoleChange(viewer, member, 'VIEWER', 403);
    await expectRoleChange(outsider, member, 'VIEWER', 404);
    await expectRoleChange(platformAdmin, member, 'VIEWER', 404);
    expect(loaderCalls).toBe(before);
  });
});

describe('room routes: denials are recorded, never explained (authorization model section 7)', () => {
  it('records the action and the reason code only, and answers every outsider case identically', async () => {
    api.events.length = 0;
    const responses = [
      await read(outsider, roomA),
      await read(owner, randomUUID()),
      await changeRole(owner, roomA, outsider.userId, 'VIEWER'),
      await rename(viewer, roomA),
      await changeRole(admin, roomA, member.userId, 'ADMIN'),
    ];
    expect(responses.map((r) => r.status)).toEqual([404, 404, 404, 403, 403]);
    expect(responses.slice(0, 3).map(errorOf)).toEqual([NOT_FOUND_BODY, NOT_FOUND_BODY, NOT_FOUND_BODY]);
    const denials = api.events.filter((e) => e.name === 'ROOM_ACCESS_DENIED');
    expect(denials.map((e) => e.details)).toEqual([
      { action: 'AZ-01', reason: 'NOT_A_MEMBER' },
      { action: 'AZ-01', reason: 'NOT_A_MEMBER' },
      { action: 'AZ-10', reason: 'RESOURCE_NOT_FOUND' },
      { action: 'AZ-02', reason: 'ROLE_NOT_PERMITTED' },
      { action: 'AZ-10', reason: 'TARGET_ROLE_NOT_PERMITTED' },
    ]);
    expect(denials.map((e) => e.actorUserId)).toEqual([
      outsider.userId,
      owner.userId,
      owner.userId,
      viewer.userId,
      admin.userId,
    ]);
    for (const event of denials) {
      expect(event.outcome).toBe('DENIED');
      expect(event.requestId).toEqual(expect.any(String));
      expect(Object.keys(event).sort()).toEqual(['actorUserId', 'details', 'name', 'outcome', 'requestId']);
    }
  });
});
