import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { SAME_ORIGIN_HEADERS } from '../helpers/api';
import { Browser, errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { inviteAndAccept } from '../helpers/room-crypto';
import { createRoom, personWithVault, whileLocked, type Person } from '../helpers/rooms';
import { createdSecret, openRevealed, reveal, revoke } from '../helpers/secrets';

// Phase 9, CM-T044: at most one successful reveal of a burn-after-reading secret, whatever races
// it (INV-13). The races are forced, not hoped for: a test connection holds the secret's row lock
// (or the room's) while the requests start, waits until the API's transactions are queued behind
// it in PostgreSQL (pg_blocking_pids), and only then lets them go, so every request passed its
// checks before any of them wrote. Two API instances with their own connection pools stand in for
// separate API processes: they share nothing but the database, which is the authoritative state.
// Every text is synthetic.
let api: AuthTestApi;
let second: AuthTestApi;
let db: pg.Client;
let owner: Person;
let sender: Person;
let recipient: Person;
let roomId: string;

const SECRET_LOCK = 'SELECT id FROM secrets WHERE id = $1 FOR UPDATE';
const ROOM_LOCK = 'SELECT id FROM rooms WHERE id = $1 FOR UPDATE';

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  second = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  [owner, sender, recipient] = [
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
  ];
  roomId = await createRoom(owner, 'STANDARD', 'Secrets concurrency room');
  await inviteAndAccept(owner, roomId, sender, 'MEMBER');
  await inviteAndAccept(owner, roomId, recipient, 'MEMBER');
}, 240_000);
afterAll(async () => {
  await api.close();
  await second.close();
  await db.end();
});

/** The same signed-in recipient, talking to the second API instance (another tab, another process). */
function onSecondInstance(who: Person): Person {
  const browser = new Browser(second, who.browser.address);
  for (const [name, value] of who.browser.cookies) browser.cookies.set(name, value);
  return { ...who, browser };
}

const statusOf = async (id: string) =>
  (
    await db.query<{ status: string; material: boolean }>(
      'SELECT status::text AS status, wrapped_sek IS NOT NULL AS material FROM secrets WHERE id = $1',
      [id],
    )
  ).rows[0];

describe('many simultaneous reveals produce exactly one success (INV-13)', () => {
  it('two reveals from two tabs on one API instance', async () => {
    const secretId = await createdSecret(sender, roomId, recipient, 'two tabs');
    const results = await whileLocked(db, SECRET_LOCK, [secretId], () =>
      Promise.all([reveal(recipient, roomId, secretId), reveal(recipient, roomId, secretId)]),
    );
    expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
    expect(await statusOf(secretId)).toEqual({ status: 'REVEALED', material: false });
  });

  it('twenty reveals spread over two API instances: one winner, nineteen refusals, one decryptable copy', async () => {
    const text = 'twenty racers';
    const secretId = await createdSecret(sender, roomId, recipient, text);
    const other = onSecondInstance(recipient);
    const results = await whileLocked(
      db,
      SECRET_LOCK,
      [secretId],
      () =>
        Promise.all(Array.from({ length: 20 }, (_, i) => reveal(i % 2 === 0 ? recipient : other, roomId, secretId))),
      // Each instance has a pool of five connections; ten transactions queue in PostgreSQL, the
      // other ten wait for a connection and run after the lock is released.
      10,
    );
    const winners = results.filter((r) => r.status === 200);
    expect(winners).toHaveLength(1);
    expect(results.filter((r) => r.status === 409 && errorCode(r) === 'SECRET_UNAVAILABLE')).toHaveLength(19);
    expect((await openRevealed(recipient, roomId, winners[0] as (typeof results)[number])).text).toBe(text);
    expect(await statusOf(secretId)).toEqual({ status: 'REVEALED', material: false });
    const revealed = [...api.events, ...second.events].filter(
      (e) => e.name === 'SECRET_REVEALED' && e.details?.['secretId'] === secretId,
    );
    expect(revealed).toHaveLength(1);
  }, 60_000);

  it('a double click after the first reveal committed is refused', async () => {
    const secretId = await createdSecret(sender, roomId, recipient, 'double click');
    const [first, again] = [await reveal(recipient, roomId, secretId), await reveal(recipient, roomId, secretId)];
    expect([first.status, again.status]).toEqual([200, 409]);
  });
});

describe('reveal races revocation, removal and expiry', () => {
  it('reveal against revocation: exactly one of them takes effect', async () => {
    for (let round = 0; round < 3; round += 1) {
      const secretId = await createdSecret(sender, roomId, recipient, 'reveal or revoke');
      const [revealed, revoked] = await whileLocked(db, SECRET_LOCK, [secretId], () =>
        Promise.all([reveal(recipient, roomId, secretId), revoke(sender, roomId, secretId)]),
      );
      const outcome = [revealed.status, revoked.status];
      expect([
        [200, 409],
        [409, 200],
      ]).toContainEqual(outcome);
      expect((await statusOf(secretId))?.status).toBe(outcome[0] === 200 ? 'REVEALED' : 'REVOKED');
      expect((await statusOf(secretId))?.material).toBe(false);
    }
  });

  it('reveal against the removal of the recipient: the reveal wins and burns, or the removal revokes', async () => {
    const leaving = await personWithVault(api, db);
    const room = await createRoom(owner, 'STANDARD', 'Secrets removal race room');
    await inviteAndAccept(owner, room, leaving, 'MEMBER');
    const secretId = await createdSecret(owner, room, leaving, 'removal race');
    const [revealed, removed] = await whileLocked(db, ROOM_LOCK, [room], () =>
      Promise.all([
        reveal(leaving, room, secretId),
        owner.browser.request('POST', `/rooms/${room}/members/${leaving.userId}/remove`, {}),
      ]),
    );
    expect(removed.status).toBe(200);
    const final = await statusOf(secretId);
    expect(final?.material).toBe(false);
    if (revealed.status === 200) expect(final?.status).toBe('REVEALED');
    else {
      expect(revealed.status).toBe(404);
      expect(final?.status).toBe('REVOKED');
    }
  });

  it('a secret that expires while the reveal waits is refused at the moment of the reveal (INV-14)', async () => {
    const secretId = await createdSecret(sender, roomId, recipient, 'expires while waiting', {
      expiresAt: new Date(api.clock.now().getTime() + 6 * 60_000).toISOString(),
    });
    try {
      const response = await whileLocked(
        db,
        SECRET_LOCK,
        [secretId],
        () => {
          // The API reads its clock when the request arrives: move it past the expiry first.
          api.clock.advance(7 * 60_000);
          return reveal(recipient, roomId, secretId);
        },
        1,
      );
      expect([response.status, errorCode(response)]).toEqual([409, 'SECRET_UNAVAILABLE']);
      expect(await statusOf(secretId)).toEqual({ status: 'ACTIVE', material: true });
    } finally {
      api.clock.advance(-7 * 60_000);
    }
  });
});

describe('failures at the delivery boundary', () => {
  it('a transaction that fails (lock held past the five-second limit) releases nothing and burns nothing', async () => {
    const secretId = await createdSecret(sender, roomId, recipient, 'rolled back');
    const locker = await testDatabase(inject('databaseName')).connect('api');
    try {
      await locker.query('BEGIN');
      await locker.query(SECRET_LOCK, [secretId]);
      const response = await reveal(recipient, roomId, secretId);
      expect(response.status).toBeGreaterThanOrEqual(500);
      expect(JSON.stringify(response.body)).not.toMatch(/wrappedSek|ciphertext/);
      await locker.query('ROLLBACK');
    } finally {
      await locker.end();
    }
    expect(await statusOf(secretId)).toEqual({ status: 'ACTIVE', material: true });
    expect((await reveal(recipient, roomId, secretId)).status).toBe(200);
  }, 30_000);

  it('a client that disconnects while waiting loses the secret: the committed burn is final (at most once)', async () => {
    const secretId = await createdSecret(sender, roomId, recipient, 'lost response');
    const controller = new AbortController();
    const cookie = [...recipient.browser.cookies].map(([n, v]) => `${n}=${v}`).join('; ');
    const locker = await testDatabase(inject('databaseName')).connect('api');
    try {
      await locker.query('BEGIN');
      await locker.query(SECRET_LOCK, [secretId]);
      const pid = (await locker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      const request = fetch(`${api.baseUrl}/api/rooms/${roomId}/secrets/${secretId}/reveal`, {
        method: 'POST',
        headers: {
          ...SAME_ORIGIN_HEADERS,
          'content-type': 'application/json',
          'x-forwarded-for': recipient.browser.address,
          cookie,
        },
        body: '{}',
        signal: controller.signal,
      }).catch((error: unknown) => error);
      // Wait until the reveal's transaction is queued behind the lock, then drop the connection.
      for (let i = 0; i < 200; i += 1) {
        const { rows } = await db.query<{ n: number }>(
          'SELECT count(*)::int AS n FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid))',
          [pid],
        );
        if ((rows[0]?.n ?? 0) >= 1) break;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      controller.abort();
      expect(await request).toBeInstanceOf(Error);
      await locker.query('COMMIT');
    } finally {
      await locker.end();
    }
    // The server finished its transaction without a listener: the secret is burned, and no retry
    // can deliver it again. This is the documented trade-off of burn-after-reading (DF-09, L-03).
    for (let i = 0; i < 100 && (await statusOf(secretId))?.status === 'ACTIVE'; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(await statusOf(secretId)).toEqual({ status: 'REVEALED', material: false });
    expect(errorCode(await reveal(recipient, roomId, secretId))).toBe('SECRET_UNAVAILABLE');
  }, 30_000);
});
