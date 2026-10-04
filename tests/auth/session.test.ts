import { SESSION_COOKIE } from '@ciphermesh/shared';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { Browser, errorCode, newIdentity, signedInUser, startAuthApi, type AuthTestApi } from '../helpers/auth';

// CM-T017: session lifecycle (session-and-csrf.md sections 3 to 7). The clock moves; the server
// decides validity from the database row, whatever the browser still holds.
let api: AuthTestApi;
let db: pg.Client;
const MINUTE = 60_000;

beforeAll(async () => {
  api = await startAuthApi();
  loadDatabaseTestEnv();
  db = await testDatabase(inject('databaseName')).connect('api');
});
afterAll(async () => {
  await db.end();
  await api.close();
});

const sessionStatus = async (browser: Browser) => (await browser.request('GET', '/auth/session')).status;

describe('session resolution', () => {
  it('returns the caller from the session only; no hash, digest or token in the response', async () => {
    const { identity, browser } = await signedInUser(api);
    const response = await browser.request('GET', '/auth/session');
    expect(response.status).toBe(200);
    expect((response.body['user'] as { email: string }).email).toBe(identity.email);
    const text = JSON.stringify(response.body);
    for (const forbidden of ['password', 'Hash', 'digest', 'token', String(browser.session)]) {
      expect(text).not.toContain(forbidden);
    }
  });

  it('ignores identity claims in headers and query strings (INV-05)', async () => {
    const { browser } = await signedInUser(api);
    const other = await signedInUser(api);
    const self = await browser.request('GET', '/auth/session');
    const myId = (self.body['user'] as { id: string }).id;
    const otherId = (await other.browser.request('GET', '/auth/session')).body['user'] as { id: string };
    const spoofed = await browser.request('GET', '/auth/session', undefined, { 'x-user-id': otherId.id });
    expect((spoofed.body['user'] as { id: string }).id).toBe(myId);
    const anonymous = new Browser(api);
    expect((await anonymous.request('GET', '/auth/session', undefined, { 'x-user-id': myId })).status).toBe(401);
    // Authentication runs before input validation (CLAUDE.md section 9), so this is a 401.
    expect((await anonymous.request('GET', `/auth/session?userId=${myId}`)).status).toBe(401);
    expect((await browser.request('GET', `/auth/session?userId=${otherId.id}`)).status).toBe(400);
  });

  it('rejects missing, random, malformed and duplicated session cookies, clearing a dead one', async () => {
    const anonymous = new Browser(api);
    const missing = await anonymous.request('GET', '/auth/session');
    expect(missing.status).toBe(401);
    expect(errorCode(missing)).toBe('UNAUTHENTICATED');
    expect(missing.setCookies).toEqual([]);

    const random = new Browser(api);
    random.cookies.set(SESSION_COOKIE, 'A'.repeat(43));
    const randomResponse = await random.request('GET', '/auth/session');
    expect(randomResponse.status).toBe(401);
    expect(randomResponse.setCookies[0]).toMatch(/^__Host-cm_session=; Max-Age=0;/);

    const { browser } = await signedInUser(api);
    const duplicated = await browser.request('GET', '/auth/session', undefined, {
      cookie: `${SESSION_COOKIE}=${String(browser.session)}; ${SESSION_COOKIE}=${'B'.repeat(43)}`,
    });
    expect(duplicated.status).toBe(401);
  });
});

describe('expiry (CP-08)', () => {
  it('expires after 30 minutes without activity, even if the browser keeps the cookie', async () => {
    const { browser } = await signedInUser(api);
    api.clock.advance(31 * MINUTE);
    expect(await sessionStatus(browser)).toBe(401);
  });

  it('extends the idle timer with activity, but never beyond 12 hours from the password login', async () => {
    const { browser } = await signedInUser(api);
    for (let elapsed = 0; elapsed < 11 * 60; elapsed += 25) {
      api.clock.advance(25 * MINUTE);
      expect(await sessionStatus(browser)).toBe(200);
    }
    api.clock.advance(70 * MINUTE - 25 * MINUTE + 1); // now just past 12 hours, still active
    expect(await sessionStatus(browser)).toBe(401);
  });
});

describe('logout and revocation', () => {
  it('logout revokes the session on the server and clears the cookie', async () => {
    const { browser } = await signedInUser(api);
    const token = String(browser.session);
    const response = await browser.request('POST', '/auth/logout', {});
    expect(response.status).toBe(200);
    expect(response.setCookies).toContain('__Host-cm_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict');
    const replay = new Browser(api);
    replay.cookies.set(SESSION_COOKIE, token);
    expect(await sessionStatus(replay)).toBe(401);
    const { rows } = await db.query<{ reason: string }>(
      `SELECT revoke_reason AS reason FROM sessions WHERE token_digest = sha256($1::bytea)`,
      [Buffer.from(token)],
    );
    expect(rows).toEqual([{ reason: 'LOGOUT' }]);
  });

  it('lists the caller own sessions and revokes one or all others', async () => {
    const identity = newIdentity();
    const first = new Browser(api);
    await first.register(identity);
    const browsers = [first, new Browser(api), new Browser(api)];
    for (const b of browsers) expect((await b.login(identity)).status).toBe(200);
    const list = await first.request('GET', '/auth/sessions');
    const sessions = list.body['sessions'] as { id: string; current: boolean; userAgent: string }[];
    expect(sessions).toHaveLength(3);
    expect(sessions.filter((s) => s.current)).toHaveLength(1);
    const other = sessions.find((s) => !s.current);
    expect((await first.request('POST', '/auth/sessions/revoke', { sessionId: other?.id })).status).toBe(200);
    expect((await Promise.all(browsers.map(sessionStatus))).filter((s) => s === 200)).toHaveLength(2);
    expect((await first.request('POST', '/auth/sessions/revoke-others', {})).status).toBe(200);
    expect(await Promise.all(browsers.map(sessionStatus))).toEqual([200, 401, 401]);
  });

  it("cannot revoke another user's session: the ID behaves as unknown", async () => {
    const alice = await signedInUser(api);
    const bob = await signedInUser(api);
    const bobSessions = (await bob.browser.request('GET', '/auth/sessions')).body['sessions'] as { id: string }[];
    const attempt = await alice.browser.request('POST', '/auth/sessions/revoke', { sessionId: bobSessions[0]?.id });
    expect(attempt.status).toBe(404);
    expect(await sessionStatus(bob.browser)).toBe(200);
  });

  it('an 11th login evicts the least recently used session (CP-08) and records an event', async () => {
    const identity = newIdentity();
    const browsers = Array.from({ length: 11 }, () => new Browser(api));
    await browsers[0]?.register(identity);
    for (const b of browsers) {
      expect((await b.login(identity)).status).toBe(200);
      api.clock.advance(1000);
    }
    const statuses = await Promise.all(browsers.map(sessionStatus));
    expect(statuses[0]).toBe(401);
    expect(statuses.slice(1).every((s) => s === 200)).toBe(true);
    expect(api.events.some((e) => e.name === 'SESSION_EVICTED')).toBe(true);
  });
});

describe('password change (section 7, EV-03-08)', () => {
  it('requires the current password, rotates this session and revokes all others', async () => {
    const identity = newIdentity();
    const current = new Browser(api);
    const other = new Browser(api);
    await current.register(identity);
    await current.login(identity);
    await other.login(identity);
    const before = String(current.session);
    const newPassword = newIdentity().password;

    const wrong = await current.request('POST', '/auth/password', {
      currentPassword: 'not-the-password-1',
      newPassword,
    });
    expect(wrong.status).toBe(401);

    const changed = await current.request('POST', '/auth/password', {
      currentPassword: identity.password,
      newPassword,
    });
    expect(changed.status).toBe(200);
    expect(current.session).not.toBe(before);
    expect(await sessionStatus(current)).toBe(200);
    expect(await sessionStatus(other)).toBe(401);
    const stale = new Browser(api);
    stale.cookies.set(SESSION_COOKIE, before);
    expect(await sessionStatus(stale)).toBe(401);
    expect((await new Browser(api).login(identity)).status).toBe(401);
    expect((await new Browser(api).login({ ...identity, password: newPassword })).status).toBe(200);
  });

  it('applies the password policy to the new password', async () => {
    const { identity, browser } = await signedInUser(api);
    const response = await browser.request('POST', '/auth/password', {
      currentPassword: identity.password,
      newPassword: 'qwerty123456', // gitleaks:allow (public breached password, must be refused)
    });
    expect(response.status).toBe(400);
    expect(errorCode(response)).toBe('PASSWORD_REJECTED');
  });
});

describe('disabled accounts', () => {
  it('lose access on the next request, even before any revocation', async () => {
    const { identity, browser } = await signedInUser(api);
    await db.query(`UPDATE users SET status = 'DISABLED' WHERE email = $1`, [identity.email]);
    expect(await sessionStatus(browser)).toBe(401);
    expect((await new Browser(api).login(identity)).status).toBe(401);
  });
});
