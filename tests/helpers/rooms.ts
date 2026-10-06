import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { expect, inject } from 'vitest';
import { changePlatformRole } from '../../apps/api/src/auth/admin';
import { SecretValue } from '../../apps/api/src/config/secret';
import { authDataAccess } from '../../apps/api/src/db/auth-store';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { createLogger } from '../../apps/api/src/logging/logger';
import { Browser, signedInUser, totpCode, userWithMfa, type AuthTestApi } from './auth';
import { testDatabase } from './database';
import { DUMMY, insert, insertKeyPair } from './db-fixtures';

// Helpers for the room suites (tests/authz). People are real accounts with real sessions created
// through the API. Memberships other than the creator's OWNER membership are inserted as
// fixtures, because invitations arrive with Phase 6. Identities, key versions and envelopes are
// DUMMY byte fixtures of the sizes the schema requires: never keys, never derived from secrets.
// They exist only so the tests can prove that the server checks for an identity and deletes
// envelopes; no test creates or reads real key material.

export interface Person {
  readonly browser: Browser;
  readonly userId: string;
  readonly password: string;
  readonly email: string;
}

export const userIdOf = async (browser: Browser): Promise<string> =>
  ((await browser.request('GET', '/auth/session')).body['user'] as { id: string }).id;

/** A signed-in account without an identity (no vault). */
export async function person(api: AuthTestApi): Promise<Person> {
  const { identity, browser } = await signedInUser(api);
  return { browser, userId: await userIdOf(browser), password: identity.password, email: identity.email };
}

/** A signed-in account with an ACTIVE identity row, which room creation requires (SS-04). */
export async function personWithVault(api: AuthTestApi, db: pg.Client): Promise<Person> {
  const who = await person(api);
  await insertKeyPair(db, who.userId);
  return who;
}

/** An account with TOTP and a session verified with MFA (PC-01), plus an identity row. */
export async function mfaPersonWithVault(api: AuthTestApi, db: pg.Client): Promise<Person & { secret: string }> {
  const user = await userWithMfa(api);
  const browser = new Browser(api);
  await browser.login(user.identity);
  const verified = await browser.request('POST', '/auth/mfa/verify', { code: totpCode(user.secret, api.clock) });
  expect(verified.status).toBe(200);
  api.clock.advance(30_000);
  const userId = await userIdOf(browser);
  await insertKeyPair(db, userId);
  return { browser, userId, password: user.identity.password, email: user.identity.email, secret: user.secret };
}

/** The API's database client as cm_api, for the server-side platform-role CLI path. */
export function apiDatabase(): Database {
  return createDatabase({
    url: new SecretValue(testDatabase(inject('databaseName')).url('api')),
    logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
    poolMax: 2,
  });
}

/** A PLATFORM_ADMIN (granted through the server-side path) with an MFA-verified session. */
export async function platformAdministrator(
  api: AuthTestApi,
  database: Database,
): Promise<Person & { readonly secret: string }> {
  const user = await userWithMfa(api);
  const data = authDataAccess(database.prisma);
  const deps = { transaction: data.transaction, events: { record: () => undefined }, clock: api.clock.now };
  expect(await changePlatformRole(deps, user.identity.email, 'PLATFORM_ADMIN')).toBe('changed');
  const browser = new Browser(api);
  await browser.login(user.identity);
  await browser.request('POST', '/auth/mfa/verify', { code: totpCode(user.secret, api.clock) });
  api.clock.advance(30_000);
  return {
    browser,
    userId: await userIdOf(browser),
    password: user.identity.password,
    email: user.identity.email,
    secret: user.secret,
  };
}

/** A fresh step-up for the person (account password, plus TOTP when the secret is given). */
export async function stepUp(api: AuthTestApi, who: Person, secret?: string): Promise<void> {
  const response = await who.browser.request('POST', '/auth/step-up', {
    password: who.password,
    ...(secret === undefined ? {} : { code: totpCode(secret, api.clock) }),
  });
  expect(response.status).toBe(200);
  if (secret !== undefined) api.clock.advance(30_000);
}

/** Creates a room through the API; returns its ID. */
export async function createRoom(who: Person, profile = 'STANDARD', name = 'Synthetic room'): Promise<string> {
  const roomId = randomUUID();
  const response = await who.browser.request('POST', '/rooms', { roomId, name, securityProfile: profile });
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return roomId;
}

/** A membership fixture (invitations arrive in Phase 6). */
export async function addMember(
  db: pg.Client,
  roomId: string,
  userId: string,
  role: 'ADMIN' | 'MEMBER' | 'VIEWER',
  extra: Record<string, unknown> = {},
): Promise<void> {
  await insert(db, 'room_members', { room_id: roomId, user_id: userId, role, first_key_version: 1, ...extra });
}

/**
 * DUMMY key version 1 and one envelope for a recipient, so a test can show that losing the member
 * deletes the envelope (INV-07). The recipient gets a DUMMY identity row if it has none.
 */
export async function insertDummyEnvelope(db: pg.Client, roomId: string, recipientId: string, ownerId: string) {
  const existing = await db.query<{ id: string }>(
    "SELECT id FROM user_key_pairs WHERE user_id = $1 AND status = 'ACTIVE'",
    [recipientId],
  );
  const keyId = existing.rows[0]?.id ?? (await insertKeyPair(db, recipientId));
  await db.query(
    `INSERT INTO room_key_versions (room_id, version, status, commitment, algorithm_suite, reasons, created_by_id)
     VALUES ($1, 1, 'ACTIVE', $2, 'CM1', '{INITIAL}', $3) ON CONFLICT DO NOTHING`,
    [roomId, DUMMY.digest(), ownerId],
  );
  await insert(db, 'key_envelopes', {
    room_id: roomId,
    key_version: 1,
    recipient_user_id: recipientId,
    recipient_key_id: keyId,
    status: 'ACTIVE',
    wrapped_key: DUMMY.rsaCiphertext(),
    algorithm: 'RSA-OAEP-3072-SHA256',
    created_by_id: ownerId,
  });
}

export interface RoomRow {
  readonly status: string;
  readonly key_state: string;
  readonly rekey_reasons: string;
  readonly epoch: number;
  readonly name: string;
}

export async function roomRow(db: pg.Client, roomId: string): Promise<RoomRow> {
  const { rows } = await db.query<RoomRow>(
    `SELECT status::text, key_state::text, rekey_reasons::text, membership_epoch::int AS epoch, name
       FROM rooms WHERE id = $1`,
    [roomId],
  );
  const row = rows[0];
  if (row === undefined) throw new Error('room not found');
  return row;
}

export async function memberships(db: pg.Client, roomId: string) {
  const { rows } = await db.query<{ user_id: string; role: string; status: string; removal_reason: string | null }>(
    `SELECT user_id::text, role::text, status::text, removal_reason::text
       FROM room_members WHERE room_id = $1 ORDER BY joined_at, id`,
    [roomId],
  );
  return rows;
}

export async function activeOwners(db: pg.Client, roomId: string): Promise<string[]> {
  const { rows } = await db.query<{ user_id: string }>(
    "SELECT user_id::text FROM room_members WHERE room_id = $1 AND role = 'OWNER' AND status = 'ACTIVE'",
    [roomId],
  );
  return rows.map((row) => row.user_id);
}

/**
 * Forces two requests to overlap: holds a row lock (`lockSql`), runs `start`, waits until
 * `blocked` server sessions queue behind that lock (directly or behind each other), then
 * releases it. Both requests therefore passed their checks on the same state before either
 * wrote. The deadline stays below the 5-second limit of the API's interactive transactions.
 */
export async function whileLocked<T>(
  observer: pg.Client,
  lockSql: string,
  params: readonly unknown[],
  start: () => Promise<T>,
  blocked = 2,
): Promise<T> {
  const locker = await testDatabase(inject('databaseName')).connect('api');
  try {
    await locker.query('BEGIN');
    await locker.query(lockSql, [...params]);
    const pid = (await locker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
    const running = start();
    const deadline = Date.now() + 4_000;
    for (;;) {
      // For a row lock, the second waiter queues behind the first one, so follow the chain.
      const { rows } = await observer.query<{ n: number }>(
        `WITH RECURSIVE waiting(pid) AS (
           SELECT pid FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid))
           UNION
           SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY (pg_blocking_pids(a.pid))
         )
         SELECT count(*)::int AS n FROM waiting`,
        [pid],
      );
      if ((rows[0]?.n ?? 0) >= blocked) break;
      if (Date.now() > deadline) throw new Error(`only ${String(rows[0]?.n)} of ${String(blocked)} requests waited`);
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    await locker.query('COMMIT');
    return await running;
  } finally {
    await locker.end();
  }
}

export const errorOf = (response: { body: Record<string, unknown> }) => {
  const error = response.body['error'] as Record<string, unknown> | undefined;
  return { code: error?.['code'], message: error?.['message'] };
};

export const NOT_FOUND_BODY = { code: 'NOT_FOUND', message: 'Resource not found' };
