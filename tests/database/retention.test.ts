import { randomBytes } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { runAuthRetention } from '../../apps/api/src/db/retention';
import { createLogger } from '../../apps/api/src/logging/logger';
import { insert, insertUser } from '../helpers/db-fixtures';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';

// Retention of authentication data (CM-T017, CM-T018) runs as cm_worker. The API role cannot
// delete sessions or login attempts, so the job cannot run with the API credential.
loadDatabaseTestEnv();
const db = testDatabase(inject('databaseName'));
const logger = createLogger({ level: 'fatal', sink: { write: () => undefined } });
const DAY = 24 * 60 * 60_000;
let api: pg.Client;
let worker: Database;
let apiDatabase: Database;

beforeAll(async () => {
  api = await db.connect('api');
  worker = createDatabase({ url: new SecretValue(db.url('worker')), logger, poolMax: 1 });
  apiDatabase = createDatabase({ url: new SecretValue(db.url('api')), logger, poolMax: 1 });
});
afterAll(async () => {
  await api.end();
  await worker.close();
  await apiDatabase.close();
});

async function session(userId: string, endedDaysAgo: number) {
  const ended = new Date(Date.now() - endedDaysAgo * DAY);
  const created = new Date(ended.getTime() - 60 * 60_000);
  await insert(api, 'sessions', {
    user_id: userId,
    token_digest: randomBytes(32),
    created_at: created,
    last_seen_at: created,
    idle_expires_at: ended,
    absolute_expires_at: ended,
    authenticated_at: created,
  });
}

describe('authentication retention (worker role)', () => {
  it('deletes sessions 30 days after they ended, old challenges and 90-day-old login attempts, and keeps the rest', async () => {
    const user = await insertUser(api);
    await session(user, 31);
    await session(user, 5);
    const challengeCreated = new Date(Date.now() - 3 * DAY);
    await insert(api, 'auth_challenges', {
      user_id: user,
      token_digest: randomBytes(32),
      purpose: 'LOGIN_MFA',
      created_at: challengeCreated,
      expires_at: new Date(challengeCreated.getTime() + 5 * 60_000),
    });
    await insert(api, 'login_attempts', {
      user_id: user,
      outcome: 'SUCCESS',
      occurred_at: new Date(Date.now() - 91 * DAY),
    });
    await insert(api, 'login_attempts', {
      user_id: user,
      outcome: 'SUCCESS',
      occurred_at: new Date(Date.now() - 10 * DAY),
    });

    const removed = await runAuthRetention(worker.prisma, new Date());
    expect(removed.sessions).toBeGreaterThanOrEqual(1);
    expect(removed.challenges).toBeGreaterThanOrEqual(1);
    expect(removed.loginAttempts).toBeGreaterThanOrEqual(1);
    const count = async (table: string) =>
      Number(
        (await api.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table} WHERE user_id = $1`, [user])).rows[0]
          ?.n,
      );
    expect(await count('sessions')).toBe(1);
    expect(await count('auth_challenges')).toBe(0);
    expect(await count('login_attempts')).toBe(1);
  });

  it('cannot run with the API credential: the API role has no DELETE on these tables', async () => {
    await expect(runAuthRetention(apiDatabase.prisma, new Date())).rejects.toThrow();
  });
});
