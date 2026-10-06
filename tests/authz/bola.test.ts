import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { Database } from '../../apps/api/src/db/client';
import { startAuthApi, type AuthTestApi } from '../helpers/auth';
import { BOLA_CASES, ROOM_CASES, type BolaCase, type Response } from '../helpers/bola-cases';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { insertKeyPair } from '../helpers/db-fixtures';
import {
  addMember,
  apiDatabase,
  createRoom,
  person,
  personWithVault,
  platformAdministrator,
  stepUp,
  type Person,
} from '../helpers/rooms';

// CM-T032: the BOLA and IDOR suite (T-06, primary control test; also T-04, T-05). Every
// production room route (the table in tests/helpers/bola-cases.ts, tied to the registry by
// tests/security/bola-inventory.test.ts) is attacked with identifiers from another room, by every
// kind of caller, against the real API and PostgreSQL. A denied mutation must leave every room
// and membership row byte-for-byte unchanged, and an outsider must not be able to tell a real
// room from an invented one.
//
// Not covered here, by design: a stale authorization decision racing a change is forced in
// tests/authz/membership-concurrency.test.ts; a disabled account losing its memberships is
// tests/authz/account-disable.test.ts; the documented room-ID reuse answer of POST /rooms (L-45)
// is asserted below as a limitation, not as a membership leak.
let api: AuthTestApi;
let db: pg.Client;
let database: Database;

let ownerA: Person;
let adminA: Person;
let memberA: Person;
let viewerA: Person;
let suspendedA: Person;
let removedA: Person;
let leftA: Person;
let ownerB: Person;
let adminB: Person;
let memberB: Person;
let viewerB: Person;
let outsider: Person;
let platform: Person & { readonly secret: string };
let dualAdmin: Person; // ADMIN in A, VIEWER in B
let dualOwner: Person; // OWNER of C, MEMBER in B
let roomA: string;
let roomB: string;
let roomC: string;

const NAME_A = 'BOLA room A confidential codename';
const NAME_B = 'BOLA room B confidential codename';

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  database = apiDatabase();

  ownerA = await personWithVault(api, db);
  ownerB = await personWithVault(api, db);
  dualOwner = await personWithVault(api, db);
  [adminA, memberA, viewerA, suspendedA, removedA, leftA] = [
    await person(api),
    await person(api),
    await person(api),
    await person(api),
    await person(api),
    await person(api),
  ];
  [adminB, memberB, viewerB, outsider, dualAdmin] = [
    await person(api),
    await person(api),
    await person(api),
    await person(api),
    await person(api),
  ];
  platform = await platformAdministrator(api, database);

  roomA = await createRoom(ownerA, 'STANDARD', NAME_A);
  roomB = await createRoom(ownerB, 'STANDARD', NAME_B);
  roomC = await createRoom(dualOwner, 'STANDARD', 'BOLA room C');
  const gone = { removed_at: new Date(), removal_reason: 'REMOVED_BY_ADMIN' };
  await addMember(db, roomA, adminA.userId, 'ADMIN');
  await addMember(db, roomA, memberA.userId, 'MEMBER');
  await addMember(db, roomA, viewerA.userId, 'VIEWER');
  await addMember(db, roomA, dualAdmin.userId, 'ADMIN');
  await addMember(db, roomA, suspendedA.userId, 'ADMIN', { status: 'SUSPENDED' });
  await addMember(db, roomA, removedA.userId, 'MEMBER', { status: 'REMOVED', ...gone });
  await addMember(db, roomA, leftA.userId, 'MEMBER', {
    status: 'LEFT',
    removed_at: new Date(),
    removal_reason: 'LEFT_ROOM',
  });
  await addMember(db, roomB, adminB.userId, 'ADMIN');
  await addMember(db, roomB, memberB.userId, 'MEMBER');
  await addMember(db, roomB, viewerB.userId, 'VIEWER');
  await addMember(db, roomB, dualAdmin.userId, 'VIEWER');
  await addMember(db, roomB, dualOwner.userId, 'MEMBER');

  // Everyone confirms their account first, so a step-up never explains a refusal: it is the
  // authorization that denies (the registry decides membership before it asks for a step-up).
  for (const who of [ownerA, adminA, memberA, viewerA, suspendedA, removedA, leftA, outsider, dualAdmin, dualOwner]) {
    await stepUp(api, who);
  }
  await stepUp(api, platform, platform.secret);
}, 240_000);
afterAll(async () => {
  await api.close();
  await database.close();
  await db.end();
});

// ------------------------------------------------------------------------------------ helpers

const read = (who: Person, path: string, headers: Record<string, string> = {}): Promise<Response> =>
  who.browser.request('GET', path, undefined, headers);

/** Every row of the given rooms and their memberships, as text: compared before and after. */
async function snapshot(rooms: readonly string[]): Promise<string> {
  const roomRows = await db.query('SELECT * FROM rooms WHERE id = ANY($1) ORDER BY id', [rooms]);
  const memberRows = await db.query('SELECT * FROM room_members WHERE room_id = ANY($1) ORDER BY id', [rooms]);
  return JSON.stringify([roomRows.rows, memberRows.rows]);
}

/** What an observer sees of a refusal: the status, the stable code, the message and the body shape. */
function shape(response: Response) {
  const error = response.body['error'] as Record<string, unknown> | undefined;
  return {
    status: response.status,
    code: error?.['code'],
    message: error?.['message'],
    errorKeys: Object.keys(error ?? {}).sort(),
    topKeys: Object.keys(response.body).sort(),
  };
}
const NOT_FOUND = {
  status: 404,
  code: 'NOT_FOUND',
  message: 'Resource not found',
  errorKeys: ['code', 'message', 'requestId'],
  topKeys: ['error'],
};
const FORBIDDEN = {
  status: 403,
  code: 'FORBIDDEN',
  message: 'You do not have permission for this action',
  errorKeys: ['code', 'message', 'requestId'],
  topKeys: ['error'],
};

/** The target member a case names inside the given room's cast. */
type Cast = { readonly MEMBER: Person; readonly ADMIN: Person };
const castA = (): Cast => ({ MEMBER: memberA, ADMIN: adminA });
const castB = (): Cast => ({ MEMBER: memberB, ADMIN: adminB });
const targetIn = (c: BolaCase, cast: Cast): string | undefined =>
  c.targetsMember && c.target !== undefined ? cast[c.target].userId : undefined;
const ref = (roomId: string, userId: string | undefined) => (userId === undefined ? { roomId } : { roomId, userId });

/** Nothing of room B (or of room A) in a refusal: names, member names, member IDs. */
function expectNoRoomData(response: Response, label: string): void {
  const text = JSON.stringify(response.body);
  for (const secret of [NAME_A, NAME_B, ownerA.userId, ownerB.userId, memberB.userId, adminB.userId, roomB]) {
    expect(text.includes(secret), `${label}: leaked ${secret.slice(0, 8)}`).toBe(false);
  }
}

const outsidersOfB = (): [string, Person][] => [
  ['OWNER of room A', ownerA],
  ['ADMIN of room A', adminA],
  ['MEMBER of room A', memberA],
  ['VIEWER of room A', viewerA],
  ['SUSPENDED member of room A', suspendedA],
  ['REMOVED member of room A', removedA],
  ['former member (LEFT) of room A', leftA],
  ['user without any room', outsider],
  ['PLATFORM_ADMIN without membership', platform],
];

// ----------------------------------------------------------------- A, B, G: room B from outside

describe('A, B and G: a caller who is not in room B gets nothing, and cannot tell it from an invented room', () => {
  it.each(ROOM_CASES.map((c) => [c.key, c] as const))(
    '%s',
    async (_key, c) => {
      for (const [label, who] of outsidersOfB()) {
        const target = targetIn(c, castB());
        const before = await snapshot([roomA, roomB, roomC]);
        const real = await c.send(who, ref(roomB, target));
        const invented = await c.send(who, ref(randomUUID(), target));
        expect(shape(real), `${label} -> existing room B`).toEqual(NOT_FOUND);
        expect(shape(invented), `${label} -> invented room`).toEqual(NOT_FOUND);
        expect(shape(real), `${label}: real and invented rooms must look alike`).toEqual(shape(invented));
        expectNoRoomData(real, label);
        expect(await snapshot([roomA, roomB, roomC]), `${label}: no row may change`).toBe(before);
      }
    },
    120_000,
  );
});

// ------------------------------------------------------------------ C: target member of room B

describe('C: addressed room A with a target member of room B', () => {
  const targeted = ROOM_CASES.filter((c) => c.targetsMember);
  const callers = (): [string, Person, 'OWNER' | 'ADMIN' | 'MEMBER' | 'VIEWER'][] => [
    ['OWNER of A', ownerA, 'OWNER'],
    ['ADMIN of A', adminA, 'ADMIN'],
    ['MEMBER of A', memberA, 'MEMBER'],
    ['VIEWER of A', viewerA, 'VIEWER'],
  ];

  it.each(targeted.map((c) => [c.key, c] as const))(
    '%s refuses a member of room B before changing anything',
    async (_key, c) => {
      for (const [label, who, role] of callers()) {
        const foreign = targetIn(c, castB());
        const before = await snapshot([roomA, roomB, roomC]);
        const response = await c.send(who, ref(roomA, foreign));
        // OWNER and ADMIN pass the first step of the matrix and then fail to find the target in
        // this room (404); a transfer is OWNER-only, so an ADMIN is refused by role (403); MEMBER
        // and VIEWER are refused by role. Nobody learns anything about room B.
        const transfer = c.key.endsWith('/transfer-ownership');
        const expected = role === 'OWNER' || (role === 'ADMIN' && !transfer) ? NOT_FOUND : FORBIDDEN;
        expect(shape(response), `${label} targeting a member of B in A`).toEqual(expected);
        if (expected === NOT_FOUND) {
          const invented = await c.send(who, ref(roomA, randomUUID()));
          expect(shape(invented), `${label}: a foreign target must look like an invented one`).toEqual(NOT_FOUND);
        }
        expectNoRoomData(response, label);
        expect(await snapshot([roomA, roomB, roomC]), `${label}: no row may change`).toBe(before);
      }
    },
    120_000,
  );

  it('the same attack with the target inside room A is the legitimate path (control)', async () => {
    // Proves the refusals above come from the room boundary and not from a broken fixture.
    const roleCase = ROOM_CASES.find((c) => c.key.endsWith('/role')) as BolaCase;
    const response = await roleCase.send(ownerA, ref(roomA, memberA.userId));
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ userId: memberA.userId, role: 'VIEWER' });
    await db.query("UPDATE room_members SET role = 'MEMBER' WHERE room_id = $1 AND user_id = $2", [
      roomA,
      memberA.userId,
    ]);
  });
});

// ---------------------------------------------------- D: authority never crosses a room boundary

describe('D: a role in one room gives no authority in another', () => {
  it('an ADMIN of room A is only a VIEWER in room B', async () => {
    for (const c of ROOM_CASES.filter((x) => x.mutates)) {
      const before = await snapshot([roomA, roomB, roomC]);
      const response = await c.send(dualAdmin, ref(roomB, targetIn(c, castB())));
      expect(shape(response), `${c.key} as ADMIN-of-A in B`).toEqual(FORBIDDEN);
      expect(await snapshot([roomA, roomB, roomC]), c.key).toBe(before);
    }
    // Reads work and return room B's own data, with the role the person has in B.
    const detail = await read(dualAdmin, `/rooms/${roomB}`);
    expect(detail.status).toBe(200);
    expect(detail.body).toMatchObject({ room: { id: roomB, name: NAME_B }, membership: { role: 'VIEWER' } });
    const own = await read(dualAdmin, `/rooms/${roomA}`);
    expect(own.body).toMatchObject({ room: { id: roomA, name: NAME_A }, membership: { role: 'ADMIN' } });
    // The authority is real where it exists: the same person renames room A.
    const rename = await ROOM_CASES.find((c) => c.key.endsWith('/rename'))?.send(dualAdmin, { roomId: roomA });
    expect(rename?.status).toBe(200);
  }, 120_000);

  it('an OWNER of room C is only a MEMBER in room B: no deletion, transfer or administration there', async () => {
    for (const c of ROOM_CASES.filter((x) => x.mutates)) {
      const before = await snapshot([roomA, roomB, roomC]);
      const response = await c.send(dualOwner, ref(roomB, targetIn(c, castB())));
      expect(shape(response), `${c.key} as OWNER-of-C in B`).toEqual(FORBIDDEN);
      expect(await snapshot([roomA, roomB, roomC]), c.key).toBe(before);
    }
  }, 120_000);

  it('lists each room with the role the person has in that room', async () => {
    const listed = await read(dualAdmin, '/rooms');
    const roles = Object.fromEntries(
      (listed.body['rooms'] as { id: string; role: string }[]).map((r) => [r.id, r.role]),
    );
    expect(roles).toEqual({ [roomA]: 'ADMIN', [roomB]: 'VIEWER' });
    const owner = await read(dualOwner, '/rooms');
    const ownerRoles = Object.fromEntries(
      (owner.body['rooms'] as { id: string; role: string }[]).map((r) => [r.id, r.role]),
    );
    expect(ownerRoles).toEqual({ [roomC]: 'OWNER', [roomB]: 'MEMBER' });
  });

  it("a member list never shows another room's members", async () => {
    const response = await read(dualAdmin, `/rooms/${roomB}/members`);
    const ids = (response.body['members'] as { userId: string }[]).map((m) => m.userId).sort();
    expect(ids).toEqual(
      [ownerB.userId, adminB.userId, memberB.userId, viewerB.userId, dualAdmin.userId, dualOwner.userId].sort(),
    );
  });
});

// ------------------------------------------------------------------------------ E: member states

describe('E: SUSPENDED, REMOVED and LEFT members have no authority in their own former room', () => {
  it.each(ROOM_CASES.map((c) => [c.key, c] as const))(
    '%s',
    async (_key, c) => {
      for (const [label, who] of [
        ['SUSPENDED member (ADMIN role kept)', suspendedA],
        ['REMOVED member', removedA],
        ['LEFT member', leftA],
      ] as const) {
        const before = await snapshot([roomA, roomB, roomC]);
        const real = await c.send(who, ref(roomA, targetIn(c, castA())));
        const invented = await c.send(who, ref(randomUUID(), targetIn(c, castA())));
        expect(shape(real), label).toEqual(NOT_FOUND);
        expect(shape(real), `${label}: former room and invented room look alike`).toEqual(shape(invented));
        expectNoRoomData(real, label);
        expect(await snapshot([roomA, roomB, roomC]), label).toBe(before);
      }
    },
    120_000,
  );
});

// ------------------------------------------------------------------------------- F: room states

describe('F: DELETING and DELETED rooms refuse everyone; REKEY_REQUIRED does not widen access', () => {
  let deleting: string;
  let deleted: string;
  let rekey: string;

  beforeAll(async () => {
    deleting = await createRoom(ownerA, 'STANDARD', 'BOLA deleting room');
    deleted = await createRoom(ownerA, 'STANDARD', 'BOLA deleted room');
    rekey = await createRoom(ownerA, 'STANDARD', 'BOLA rekey room');
    for (const roomId of [deleting, deleted, rekey]) {
      await addMember(db, roomId, adminA.userId, 'ADMIN');
      await addMember(db, roomId, memberA.userId, 'MEMBER');
    }
    await db.query("UPDATE rooms SET status = 'DELETING', deleted_at = now() WHERE id = $1", [deleting]);
    await db.query("UPDATE rooms SET status = 'DELETED', deleted_at = now() WHERE id = $1", [deleted]);
    await db.query(
      `UPDATE rooms SET key_state = 'REKEY_REQUIRED', rekey_reasons = '{MEMBER_REMOVED}', rekey_required_since = now(),
              membership_epoch = membership_epoch + 1 WHERE id = $1`,
      [rekey],
    );
  });

  it.each(ROOM_CASES.map((c) => [c.key, c] as const))(
    '%s on a DELETING or DELETED room is a 404 for its own OWNER, and changes nothing',
    async (_key, c) => {
      for (const roomId of [deleting, deleted]) {
        const before = await snapshot([roomId]);
        const response = await c.send(ownerA, ref(roomId, targetIn(c, castA())));
        const invented = await c.send(ownerA, ref(randomUUID(), targetIn(c, castA())));
        expect(shape(response)).toEqual(NOT_FOUND);
        expect(shape(response)).toEqual(shape(invented));
        expect(JSON.stringify(response.body)).not.toContain('BOLA deleting room');
        expect(JSON.stringify(response.body)).not.toContain('BOLA deleted room');
        expect(await snapshot([roomId])).toBe(before);
      }
    },
    120_000,
  );

  it('a locked room (REKEY_REQUIRED) is still invisible to outsiders and PLATFORM_ADMIN', async () => {
    for (const c of ROOM_CASES) {
      for (const [label, who] of [
        ['outsider', outsider],
        ['PLATFORM_ADMIN', platform],
        ['ADMIN of another room', adminB],
      ] as const) {
        const before = await snapshot([rekey]);
        const response = await c.send(who, ref(rekey, targetIn(c, castA())));
        expect(shape(response), `${label} ${c.key}`).toEqual(NOT_FOUND);
        expect(await snapshot([rekey]), `${label} ${c.key}`).toBe(before);
      }
    }
  }, 120_000);

  it('a locked room still serves its members (the write lock is for content, Phase 7 onward)', async () => {
    const detail = await read(memberA, `/rooms/${rekey}`);
    expect(detail.status).toBe(200);
    expect(detail.body).toMatchObject({ room: { id: rekey, keyState: 'REKEY_REQUIRED' } });
  });
});

// ------------------------------------------------------------- H: client-supplied identity

describe('H: nothing the client sends can name the caller, the room owner or a role', () => {
  const FORGED = (): Record<string, string> => ({
    userId: ownerB.userId,
    roomId: roomA,
    ownerId: ownerB.userId,
    membershipId: randomUUID(),
    role: 'OWNER',
    createdById: ownerB.userId,
    actorUserId: ownerB.userId,
  });

  it.each(BOLA_CASES.filter((c) => c.mutates).map((c) => [c.key, c] as const))(
    '%s rejects forged identity, role and room fields even from an authorized caller',
    async (_key, c) => {
      // roomId is the one identifier POST /rooms accepts (the browser chooses it, DF-05); reusing a
      // known one is the documented L-45 case below. Every other identity or role field is refused.
      const fields = Object.keys(FORGED()).filter((f) => !(c.kind === 'collection' && f === 'roomId'));
      for (const field of fields) {
        const before = await snapshot([roomA, roomB, roomC]);
        // ownerB is the real OWNER of room B; for the collection route any signed-in user works.
        const response = await c.send(
          ownerB,
          ref(c.kind === 'collection' ? randomUUID() : roomB, targetIn(c, castB())),
          {
            fields: { [field]: FORGED()[field] as string },
          },
        );
        const error = response.body['error'] as { code?: string } | undefined;
        expect(response.status, `${c.key} with ${field}`).toBe(400);
        expect(error?.code, `${c.key} with ${field}`).toBe('VALIDATION_FAILED');
        expect(await snapshot([roomA, roomB, roomC]), `${c.key} with ${field}`).toBe(before);
      }
    },
    120_000,
  );

  it.each(BOLA_CASES.filter((c) => !c.mutates).map((c) => [c.key, c] as const))(
    '%s rejects identity, room and role query parameters',
    async (_key, c) => {
      for (const field of ['userId', 'roomId', 'role', 'ownerId']) {
        const response = await c.send(ownerB, ref(roomB, undefined), {
          fields: { [field]: FORGED()[field] as string },
        });
        expect(response.status, `${c.key} with ?${field}`).toBe(400);
      }
    },
  );

  it.each(ROOM_CASES.map((c) => [c.key, c] as const))(
    '%s ignores identity and role headers',
    async (_key, c) => {
      const headers = {
        'x-user-id': ownerB.userId,
        'x-room-role': 'OWNER',
        'x-ciphermesh-role': 'ADMIN',
        'x-platform-role': 'PLATFORM_ADMIN',
        'x-forwarded-user': ownerB.userId,
        authorization: `Bearer ${randomUUID()}`,
      };
      for (const [label, who] of [
        ['outsider', outsider],
        ['VIEWER of A', viewerA],
      ] as const) {
        const before = await snapshot([roomA, roomB, roomC]);
        const response = await c.send(who, ref(roomB, targetIn(c, castB())), { headers });
        expect(shape(response), `${label} with forged headers`).toEqual(NOT_FOUND);
        expect(await snapshot([roomA, roomB, roomC])).toBe(before);
      }
    },
    120_000,
  );

  it('the room list belongs to the session user: a cursor naming room B reveals nothing of it', async () => {
    const cursor = `${new Date(Date.now() + 60_000).toISOString()}_${roomB}`;
    const response = await read(ownerA, `/rooms?cursor=${encodeURIComponent(cursor)}`);
    expect(response.status).toBe(200);
    const ids = (response.body['rooms'] as { id: string }[]).map((r) => r.id);
    expect(ids).not.toContain(roomB);
    expect(JSON.stringify(response.body)).not.toContain(NAME_B);
    const spoofed = await read(outsider, '/rooms', { 'x-user-id': ownerB.userId });
    expect(spoofed.body).toEqual({ rooms: [], nextCursor: null });
    // And the PLATFORM_ADMIN sees only its own memberships, which are none.
    expect((await read(platform, '/rooms')).body).toEqual({ rooms: [], nextCursor: null });
  });
});

// ---------------------------------------------------------------- L-45: the documented limitation

describe('L-45: creating a room with a known ID answers 409 (documented limitation, not a membership leak)', () => {
  it('reveals only that the ID was used, takes nothing over and changes nothing', async () => {
    const create = BOLA_CASES.find((c) => c.key === 'POST /rooms') as BolaCase;
    // A real creator has an identity (SS-04); a synthetic one is enough to reach the ID check.
    await insertKeyPair(db, outsider.userId);
    const before = await snapshot([roomA, roomB, roomC]);
    const retry = await create.send(outsider, { roomId: roomB });
    const error = retry.body['error'] as { code?: string } | undefined;
    expect(retry.status).toBe(409);
    expect(error?.code).toBe('ROOM_ID_UNAVAILABLE');
    expectNoRoomData(retry, 'duplicate room ID');
    expect(await snapshot([roomA, roomB, roomC])).toBe(before);
    const { rows } = await db.query('SELECT count(*)::int AS n FROM room_members WHERE room_id = $1 AND user_id = $2', [
      roomB,
      outsider.userId,
    ]);
    expect(rows).toEqual([{ n: 0 }]);
  });
});
