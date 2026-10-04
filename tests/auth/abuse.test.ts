import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { createIdentifierHasher } from '../../apps/api/src/auth/identifier';
import { TEST_AUTH_KEYS } from '../helpers/api';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { Browser, errorCode, newAddress, newIdentity, startAuthApi, type AuthTestApi } from '../helpers/auth';

// CM-T018 (`auth-abuse` suite): per-address limits, progressive per-account backoff without
// permanent lockout, the same behaviour for unknown identifiers, bounded writes, and the Argon2id
// concurrency limit (T-09, T-10, T-26).
let api: AuthTestApi;
let db: pg.Client;

beforeAll(async () => {
  api = await startAuthApi();
  loadDatabaseTestEnv();
  db = await testDatabase(inject('databaseName')).connect('api');
});
afterAll(async () => {
  await db.end();
  await api.close();
});

/** Counts this scenario's own rows only: other suites write login attempts concurrently. */
const identifierHmac = createIdentifierHasher(TEST_AUTH_KEYS.IDENTIFIER_HMAC_KEY);
async function attemptsFor(filter: { email?: string; unknownEmail?: string; address?: string }): Promise<number> {
  if (filter.email !== undefined) {
    const { rows } = await db.query<{ n: string }>(
      'SELECT count(*) AS n FROM login_attempts a JOIN users u ON u.id = a.user_id WHERE u.email = $1',
      [filter.email],
    );
    return Number(rows[0]?.n);
  }
  if (filter.unknownEmail !== undefined) {
    const { rows } = await db.query<{ n: string }>(
      'SELECT count(*) AS n FROM login_attempts WHERE identifier_hmac = $1',
      [identifierHmac(filter.unknownEmail)],
    );
    return Number(rows[0]?.n);
  }
  const { rows } = await db.query<{ n: string }>(
    'SELECT count(*) AS n FROM login_attempts WHERE ip_address = $1::inet',
    [filter.address],
  );
  return Number(rows[0]?.n);
}

/** Five wrong passwords from five different addresses, so only the account signal applies. */
async function failFiveTimes(identity: { email: string; password: string }): Promise<number[]> {
  const statuses: number[] = [];
  for (let i = 0; i < 5; i += 1) {
    statuses.push((await new Browser(api).login({ ...identity, password: `wrong-password-${String(i)}` })).status);
  }
  return statuses;
}

describe('per-account backoff (no permanent lockout)', () => {
  it('blocks after five failures with Retry-After, then lets the right password in once the delay passes', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    expect(await failFiveTimes(identity)).toEqual([401, 401, 401, 401, 401]);

    const blocked = await new Browser(api).login(identity); // even the right password waits
    expect(blocked.status).toBe(429);
    expect(errorCode(blocked)).toBe('RATE_LIMITED');
    expect(Number(blocked.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(Number(blocked.headers.get('retry-after'))).toBeLessThanOrEqual(30);

    api.clock.advance(31_000);
    expect((await new Browser(api).login(identity)).status).toBe(200);
    // Success resets the count: the next failure is free again.
    expect((await new Browser(api).login({ ...identity, password: 'wrong-again-123' })).status).toBe(401);
    expect((await new Browser(api).login(identity)).status).toBe(200);
  });

  it('doubles the delay with further failures, capped at 15 minutes', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    await failFiveTimes(identity);
    api.clock.advance(31_000);
    expect((await new Browser(api).login({ ...identity, password: 'wrong-sixth-pw' })).status).toBe(401);
    const blocked = await new Browser(api).login(identity);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get('retry-after'))).toBeGreaterThan(30);
    expect(Number(blocked.headers.get('retry-after'))).toBeLessThanOrEqual(60);
  });

  it('behaves identically for an unknown identifier, so throttling does not reveal accounts', async () => {
    const unknown = newIdentity();
    expect(await failFiveTimes(unknown)).toEqual([401, 401, 401, 401, 401]);
    const blocked = await new Browser(api).login(unknown);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get('retry-after'))).toBeLessThanOrEqual(30);
  });
});

describe('bounded writes under backoff', () => {
  it('requests refused by the account or identifier backoff write no login_attempts rows', async () => {
    const known = newIdentity();
    await new Browser(api).register(known);
    await failFiveTimes(known);
    const unknown = newIdentity();
    await failFiveTimes(unknown);
    const before = [await attemptsFor({ email: known.email }), await attemptsFor({ unknownEmail: unknown.email })];
    expect(before).toEqual([5, 5]);
    for (let i = 0; i < 5; i += 1) {
      expect((await new Browser(api).login(known)).status).toBe(429);
      expect((await new Browser(api).login(unknown)).status).toBe(429);
    }
    expect([await attemptsFor({ email: known.email }), await attemptsFor({ unknownEmail: unknown.email })]).toEqual(
      before,
    );
  });
});

describe('per-address limits', () => {
  it('limits one address to 20 login attempts in 10 minutes across all accounts', async () => {
    const browser = new Browser(api, newAddress());
    const statuses: number[] = [];
    for (let i = 0; i < 21; i += 1) statuses.push((await browser.login(newIdentity())).status);
    expect(statuses.slice(0, 20).every((s) => s === 401)).toBe(true);
    expect(statuses[20]).toBe(429);
    expect((await new Browser(api).login(newIdentity())).status).toBe(401); // another address is unaffected
  });

  it('rejects limited requests before any database write, so a flood cannot grow login_attempts', async () => {
    const browser = new Browser(api, newAddress());
    for (let i = 0; i < 20; i += 1) await browser.login(newIdentity());
    expect(await attemptsFor({ address: browser.address })).toBe(20);
    for (let i = 0; i < 10; i += 1) expect((await browser.login(newIdentity())).status).toBe(429);
    expect(await attemptsFor({ address: browser.address })).toBe(20);
  });
});

describe('Argon2id resource limit', () => {
  it('a burst of concurrent logins gets 401 or 503 (busy) and never crashes the API', async () => {
    const results = await Promise.all(
      Array.from({ length: 60 }, () => new Browser(api, newAddress()).login(newIdentity())),
    );
    const statuses = new Set(results.map((r) => r.status));
    expect([...statuses].every((s) => s === 401 || s === 503 || s === 429)).toBe(true);
    for (const busy of results.filter((r) => r.status === 503)) {
      expect(errorCode(busy)).toBe('SERVICE_UNAVAILABLE');
      expect(busy.headers.get('retry-after')).toBe('1');
    }
    expect((await new Browser(api).request('GET', '/health')).status).toBe(200);
    expect(api.logText()).not.toContain('unhandled error');
  });
});
