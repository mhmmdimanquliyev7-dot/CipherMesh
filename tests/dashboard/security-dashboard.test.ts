import { FILE_TAG_BYTES, SECURITY_METRICS } from '@ciphermesh/shared';
import { securityDashboardResponseSchema, type SecurityDashboardResponse } from '@ciphermesh/validation';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { Database } from '../../apps/api/src/db/client';
import { Browser, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { testDatabase } from '../helpers/database';
import { requireStorageEnv, uploadFile } from '../helpers/files';
import { rekey } from '../helpers/rekey';
import { inviteAndAccept } from '../helpers/room-crypto';
import {
  addMember,
  apiDatabase,
  createRoom,
  errorOf,
  mfaPersonWithVault,
  NOT_FOUND_BODY,
  person,
  personWithVault,
  platformAdministrator,
  type Person,
} from '../helpers/rooms';
import { createdSecret, inFromNow } from '../helpers/secrets';

// Platform security dashboard (Phase 14, CM-T061, CM-T062; security-dashboard.md section 5). This
// project has its own freshly migrated database and runs one file at a time, so every aggregate is
// known exactly: an empty state first, then a scenario built through the real API (invitations,
// removals, a rekey, an upload, secrets, failed logins). Values the scenario cannot fix in advance
// (sessions, throttling) are compared with an independent SQL count. Nothing is mocked.

const DAY = 24 * 60 * 60_000;
const CANARY_ROOM = `dashboard-canary-room-${String(Date.now())}`;

let api: AuthTestApi;
let db: pg.Client;
let database: Database;
let admin: Person;

const dashboard = async (who: Person): Promise<SecurityDashboardResponse> => {
  const response = await who.browser.request('GET', '/admin/security-dashboard');
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  return securityDashboardResponseSchema.parse(response.body);
};

const valuesOf = (result: SecurityDashboardResponse, id: string): Record<string, number> => {
  const metric = result.metrics.find((m) => m.id === id);
  expect(metric, id).toBeDefined();
  return Object.fromEntries((metric?.values ?? []).map((v) => [v.key, v.value]));
};

const sqlCount = async (sql: string, values: unknown[] = []): Promise<number> =>
  Number(((await db.query<{ n: string }>(sql, values)).rows[0] ?? { n: '0' }).n);

beforeAll(async () => {
  requireStorageEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  database = apiDatabase();
  admin = await platformAdministrator(api, database);
});
afterAll(async () => {
  await db.end();
  await database.close();
  await api.close();
});

describe('security dashboard (PA-01)', () => {
  it('reports every metric of the catalogue, and empty states as real zeros', async () => {
    const result = await dashboard(admin);
    expect(result.metrics.map((m) => m.id)).toEqual(SECURITY_METRICS.map((m) => m.id));
    // Only the administrator exists: no rooms, files, secrets, keys or invitations.
    expect(valuesOf(result, 'SD-01')).toEqual({ files: 0, ciphertextBytes: 0 });
    expect(valuesOf(result, 'SD-02')).toEqual({ rooms: 0 });
    expect(valuesOf(result, 'SD-03')).toEqual({ STANDARD: 0, CONFIDENTIAL: 0, RESTRICTED: 0 });
    expect(valuesOf(result, 'SD-04')).toEqual({ within24h: 0, within7d: 0 });
    expect(valuesOf(result, 'SD-06')).toEqual({ withMfa: 1, activeUsers: 1, blockedMembers: 0 });
    expect(valuesOf(result, 'SD-07')['total']).toBe(0);
    expect(valuesOf(result, 'SD-08')).toEqual({ lockedRooms: 0, oldestLockHours: 0, abandoned7d: 0 });
    expect(valuesOf(result, 'SD-13')).toEqual({ withVault: 0, activeUsers: 1 });
    expect(valuesOf(result, 'SD-14')).toEqual({ pendingApproval: 0 });
  });

  it('marks the audit-ledger metrics NOT_IMPLEMENTED with no value, never zero', async () => {
    const result = await dashboard(admin);
    for (const id of ['SD-10', 'SD-11', 'SD-12', 'SD-15']) {
      const metric = result.metrics.find((m) => m.id === id);
      expect(metric, id).toEqual({ id, status: 'NOT_IMPLEMENTED', values: [] });
    }
    expect(result.platform).toEqual([
      { id: 'api', state: 'HEALTHY' },
      { id: 'database', state: 'HEALTHY' },
      { id: 'object-storage', state: 'NOT_VERIFIED' },
      { id: 'worker', state: 'NOT_VERIFIED' },
      { id: 'cloud', state: 'NOT_CONNECTED' },
    ]);
  });

  it('computes exact aggregates for a scenario built through the real API', async () => {
    const owner = await mfaPersonWithVault(api, db);
    const member = await personWithVault(api, db);
    const recipient = await personWithVault(api, db);
    const outsider = await person(api);

    const roomA = await createRoom(owner, 'STANDARD', CANARY_ROOM);
    const roomB = await createRoom(owner, 'STANDARD', CANARY_ROOM);
    const roomC = await createRoom(owner, 'CONFIDENTIAL', CANARY_ROOM);
    await inviteAndAccept(owner, roomA, member, 'MEMBER');
    await inviteAndAccept(owner, roomA, recipient, 'MEMBER');
    // A member without MFA in a CONFIDENTIAL room: refused there by PC-01 (SD-06).
    await addMember(db, roomC, member.userId, 'MEMBER');

    const content = new TextEncoder().encode('synthetic dashboard file content');
    await uploadFile(owner, roomA, content);
    await createdSecret(owner, roomA, recipient, 'synthetic one', {
      expiresAt: inFromNow(60 * 60_000, api.clock.now()),
    });
    await createdSecret(owner, roomA, recipient, 'synthetic two', { expiresAt: inFromNow(3 * DAY, api.clock.now()) });

    // Removal locks room A; the rekey makes version 2 (reason MEMBER_REMOVED) and unlocks it.
    const removeA = await owner.browser.request('POST', `/rooms/${roomA}/members/${member.userId}/remove`, {});
    expect(removeA.status, JSON.stringify(removeA.body)).toBe(200);
    await rekey(owner, roomA);
    // Room B stays locked, with a lock that began five hours ago.
    await addMember(db, roomB, recipient.userId, 'MEMBER');
    const removeB = await owner.browser.request('POST', `/rooms/${roomB}/members/${recipient.userId}/remove`, {});
    expect(removeB.status, JSON.stringify(removeB.body)).toBe(200);
    await db.query(`UPDATE rooms SET rekey_required_since = $2 WHERE id = $1`, [
      roomB,
      new Date(api.clock.now().getTime() - 5 * 60 * 60_000 - 60_000),
    ]);

    // Two failed sign-ins for the outsider's account.
    const anonymous = new Browser(api);
    for (let i = 0; i < 2; i += 1) {
      const failed = await anonymous.request('POST', '/auth/login', {
        email: outsider.email,
        password: 'wrong password!',
      });
      expect(failed.status).toBe(401);
    }

    const result = await dashboard(admin);
    const now = api.clock.now();
    expect(valuesOf(result, 'SD-01')).toEqual({ files: 1, ciphertextBytes: content.length + FILE_TAG_BYTES });
    expect(valuesOf(result, 'SD-02')).toEqual({ rooms: 3 });
    expect(valuesOf(result, 'SD-03')).toEqual({ STANDARD: 2, CONFIDENTIAL: 1, RESTRICTED: 0 });
    expect(valuesOf(result, 'SD-04')).toEqual({ within24h: 1, within7d: 2 });
    expect(valuesOf(result, 'SD-06')).toEqual({ withMfa: 2, activeUsers: 5, blockedMembers: 1 });
    expect(valuesOf(result, 'SD-07')).toMatchObject({ total: 1, MEMBER_REMOVED: 1, MANUAL: 0 });
    expect(valuesOf(result, 'SD-08')).toMatchObject({ lockedRooms: 1, oldestLockHours: 5 });
    expect(valuesOf(result, 'SD-13')).toEqual({ withVault: 3, activeUsers: 5 });
    expect(valuesOf(result, 'SD-14')).toEqual({ pendingApproval: 0 });

    const failures = valuesOf(result, 'SD-05');
    expect(failures['failed24h']).toBe(2);
    expect(failures['failed7d']).toBe(2);
    expect(failures['sources7d']).toBe(
      await sqlCount(`SELECT count(DISTINCT ip_address) AS n FROM login_attempts WHERE outcome <> 'SUCCESS'`),
    );
    expect(failures['throttledAccounts']).toBe(
      await sqlCount(`SELECT count(*) AS n FROM users WHERE status = 'ACTIVE' AND throttled_until > $1`, [now]),
    );
    expect(valuesOf(result, 'SD-08')['abandoned7d']).toBe(
      await sqlCount(`SELECT count(*) AS n FROM rekey_operations WHERE status = 'ABANDONED'`),
    );
    expect(valuesOf(result, 'SD-09')['sessions']).toBe(
      await sqlCount(
        `SELECT count(*) AS n FROM sessions WHERE revoked_at IS NULL AND idle_expires_at > $1 AND absolute_expires_at > $1`,
        [now],
      ),
    );
    expect(valuesOf(result, 'SD-09')['sessions']).toBeGreaterThanOrEqual(5);

    // Projection: aggregates only. No room name, room or user identifier, or email in the answer.
    const text = JSON.stringify(result);
    for (const value of [CANARY_ROOM, roomA, roomB, roomC, owner.userId, member.userId, owner.email, outsider.email]) {
      expect(text).not.toContain(value);
    }
  });

  it('is invisible to everyone but platform administrators', async () => {
    const user = await personWithVault(api, db);
    const denied = await user.browser.request('GET', '/admin/security-dashboard');
    expect(denied.status).toBe(404);
    expect(errorOf(denied)).toEqual(NOT_FOUND_BODY);
    const anonymous = await new Browser(api).request('GET', '/admin/security-dashboard');
    expect(anonymous.status).toBe(401);
  });
});
