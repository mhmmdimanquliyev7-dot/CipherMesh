import { SESSION_COOKIE } from '@ciphermesh/shared';
import { argon2Sync, createHash, randomBytes } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { issueToken } from '../../apps/api/src/auth/tokens';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { Browser, errorCode, newIdentity, signedInUser, startAuthApi, type AuthTestApi } from '../helpers/auth';

// CM-T016: login with opaque server-side sessions (DF-01, ADR-008).
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

const sha256 = (value: string): Buffer => createHash('sha256').update(value).digest();

describe('login', () => {
  it('issues a __Host- session cookie with HttpOnly, Secure, SameSite=Strict, Path=/ and no Domain', async () => {
    const identity = newIdentity();
    const browser = new Browser(api);
    await browser.register(identity);
    const response = await browser.login(identity);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'authenticated' });
    const cookie = response.setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    expect(cookie).toMatch(
      /^__Host-cm_session=[A-Za-z0-9_-]{43}; Max-Age=43200; Path=\/; Secure; HttpOnly; SameSite=Strict$/,
    );
    expect(cookie?.toLowerCase()).not.toContain('domain=');
    expect((await browser.request('GET', '/auth/session')).status).toBe(200);
  });

  it('stores only the SHA-256 digest of the session token, never the token itself', async () => {
    const { browser } = await signedInUser(api);
    const token = String(browser.session);
    const { rows } = await db.query<{ row: string; digest: Buffer }>(
      'SELECT row_to_json(s)::text AS row, token_digest AS digest FROM sessions s WHERE token_digest = $1',
      [sha256(token)],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.row).not.toContain(token);
    expect(rows[0]?.row).not.toContain(Buffer.from(token, 'base64url').toString('hex'));
  });

  it('answers a wrong password, an unknown account and a malformed identifier identically', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    const wrong = await new Browser(api).login({ ...identity, password: `${identity.password}x` });
    const unknown = await new Browser(api).login(newIdentity());
    const malformed = await new Browser(api).login({ email: 'not an email', password: 'whatever-password' });
    for (const r of [wrong, unknown, malformed]) {
      expect(r.status).toBe(401);
      expect(errorCode(r)).toBe('INVALID_CREDENTIALS');
      expect((r.body['error'] as { message: string }).message).toBe('The email address or password is incorrect');
      expect(r.setCookies).toEqual([]);
    }
  });

  it('spends comparable Argon2id time for unknown accounts and wrong passwords (no timing shortcut)', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    const time = async (login: () => Promise<unknown>) => {
      const start = performance.now();
      await login();
      return performance.now() - start;
    };
    const known: number[] = [];
    const unknown: number[] = [];
    for (let i = 0; i < 4; i += 1) {
      known.push(await time(() => new Browser(api).login({ ...identity, password: `wrong-${String(i)}-password` })));
      unknown.push(await time(() => new Browser(api).login(newIdentity())));
    }
    const median = (v: number[]) => [...v].sort((a, b) => a - b)[Math.floor(v.length / 2)] ?? 0;
    expect(median(unknown)).toBeGreaterThan(40);
    expect(median(unknown) / median(known)).toBeGreaterThan(0.5);
    expect(median(unknown) / median(known)).toBeLessThan(2);
  });

  it('never promotes a planted session token (session fixation, T-08)', async () => {
    const identity = newIdentity();
    const victim = new Browser(api);
    await victim.register(identity);
    // An attacker plants their own valid session token in the victim's browser before login.
    const { browser: attacker } = await signedInUser(api);
    const planted = String(attacker.session);
    victim.cookies.set(SESSION_COOKIE, planted);
    expect((await victim.login(identity)).status).toBe(200);
    expect(victim.session).not.toBe(planted);
    // The planted token still belongs to the attacker's account, not the victim's.
    const attackerView = await attacker.request('GET', '/auth/session');
    expect((attackerView.body['user'] as { email: string }).email).not.toBe(identity.email);
    // An invented, never-issued token is not accepted either.
    const invented = new Browser(api);
    invented.cookies.set(SESSION_COOKIE, issueToken().token);
    expect((await invented.request('GET', '/auth/session')).status).toBe(401);
  });

  it('refuses a disabled account with the same generic error, even with the right password', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    await db.query(`UPDATE users SET status = 'DISABLED' WHERE email = $1`, [identity.email]);
    const response = await new Browser(api).login(identity);
    expect(response.status).toBe(401);
    expect(errorCode(response)).toBe('INVALID_CREDENTIALS');
    expect(response.setCookies).toEqual([]);
  });

  it('fails closed on a malformed stored hash instead of erroring or accepting', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    await db.query(`UPDATE users SET password_hash = '$argon2id$v=19$corrupted' WHERE email = $1`, [identity.email]);
    const response = await new Browser(api).login(identity);
    expect(response.status).toBe(401);
    expect(errorCode(response)).toBe('INVALID_CREDENTIALS');
  });

  it('rehashes a password stored with older parameters at the next successful login (CP-05)', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    const salt = randomBytes(16);
    const derived = argon2Sync('argon2id', {
      message: Buffer.from(identity.password),
      nonce: salt,
      memory: 19456,
      passes: 2,
      parallelism: 1,
      tagLength: 32,
    });
    const b64 = (b: Buffer) => b.toString('base64').replace(/=+$/, '');
    await db.query('UPDATE users SET password_hash = $2 WHERE email = $1', [
      identity.email,
      `$argon2id$v=19$m=19456,t=2,p=1$${b64(salt)}$${b64(derived)}`,
    ]);
    expect((await new Browser(api).login(identity)).status).toBe(200);
    const { rows } = await db.query<{ h: string }>('SELECT password_hash AS h FROM users WHERE email = $1', [
      identity.email,
    ]);
    expect(rows[0]?.h).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=4\$/);
  });

  it('records login attempts without passwords or raw identifiers of unknown accounts (CP-12, EV-03-06)', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    // Users sometimes type their password into the identifier field.
    const typedPassword = `pw-in-email-field-${randomBytes(6).toString('hex')}`;
    await new Browser(api).login({ email: typedPassword, password: 'irrelevant-password-1' });
    await new Browser(api).login({ ...identity, password: `${identity.password}-wrong` });
    const { rows } = await db.query<{ row: string; user_id: string | null; hmac: Buffer | null }>(
      `SELECT row_to_json(a)::text AS row, a.user_id, a.identifier_hmac AS hmac FROM login_attempts a
        ORDER BY occurred_at DESC LIMIT 50`,
    );
    const all = rows.map((r) => r.row).join('\n');
    expect(all).not.toContain(typedPassword);
    expect(all).not.toContain(identity.password);
    expect(all).not.toContain(identity.email);
    expect(rows.some((r) => r.user_id === null && r.hmac?.length === 32)).toBe(true);
    expect(rows.some((r) => r.user_id !== null && r.hmac === null)).toBe(true);
  });

  it('never writes the password into the log', async () => {
    const { identity } = await signedInUser(api);
    await new Browser(api).login({ ...identity, password: `${identity.password}-typo` });
    expect(api.logText()).not.toContain(identity.password);
  });
});
