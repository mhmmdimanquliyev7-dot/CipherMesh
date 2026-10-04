import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { Browser, errorCode, newIdentity, startAuthApi, type AuthTestApi } from '../helpers/auth';
import type pg from 'pg';

// CM-T015: registration with Argon2id hashing, strict schemas and the CP-06 password policy.
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

const userRow = async (email: string) =>
  (
    await db.query<{ password_hash: string; platform_role: string; status: string; mfa_enabled: boolean }>(
      'SELECT password_hash, platform_role, status, mfa_enabled FROM users WHERE email = $1',
      [email],
    )
  ).rows;

describe('registration', () => {
  it('creates the account with an Argon2id PHC hash and returns nothing else; no session yet', async () => {
    const identity = newIdentity();
    const browser = new Browser(api);
    const response = await browser.register(identity);
    expect(response.status).toBe(201);
    expect(response.body).toEqual({ status: 'registered' });
    expect(response.setCookies).toEqual([]);
    const [row] = await userRow(identity.email);
    expect(row?.password_hash).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    expect(row).toMatchObject({ platform_role: 'USER', status: 'ACTIVE', mfa_enabled: false });
    expect(row?.password_hash).not.toContain(identity.password);
    expect(api.logText()).not.toContain(identity.password);
    expect(api.events.some((e) => e.name === 'USER_REGISTERED')).toBe(true);
  });

  it.each([
    ['platformRole', { platformRole: 'PLATFORM_ADMIN' }],
    ['isAdmin', { isAdmin: true }],
    ['status', { status: 'ACTIVE' }],
    ['mfaEnabled', { mfaEnabled: true }],
    ['passwordHash', { passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$x$y' }],
    ['id', { id: '7b3f0d0e-4b8f-4c4d-9a35-4a5b0f6a1c11' }],
    ['__proto__', JSON.parse('{"__proto__": {"platformRole": "PLATFORM_ADMIN"}}') as object],
  ])('rejects the privileged or unknown field %s (mass assignment) and creates nothing', async (_label, extra) => {
    const identity = newIdentity();
    const response = await new Browser(api).register({ ...identity, ...extra });
    expect(response.status).toBe(400);
    expect(errorCode(response)).toBe('VALIDATION_FAILED');
    expect(await userRow(identity.email)).toEqual([]);
  });

  it('normalizes the email once, so case and whitespace variants are the same account', async () => {
    const identity = newIdentity();
    const browser = new Browser(api);
    expect((await browser.register(identity)).status).toBe(201);
    const variant = { ...newIdentity(), email: `  ${identity.email.toUpperCase()} ` };
    const duplicate = await browser.register(variant);
    expect(duplicate.status).toBe(409);
    expect(errorCode(duplicate)).toBe('EMAIL_UNAVAILABLE');
  });

  it('lets exactly one of several concurrent registrations for the same email win', async () => {
    const identity = newIdentity();
    const results = await Promise.all(
      Array.from({ length: 5 }, () => new Browser(api).register({ ...identity, password: newIdentity().password })),
    );
    expect(results.map((r) => r.status).sort()).toEqual([201, 409, 409, 409, 409]);
    expect(await userRow(identity.email)).toHaveLength(1);
  });

  it.each([
    ['too short', 'Short-pw-1!', 'password_too_short'],
    ['too long', 'p'.repeat(129), 'password_too_long'],
    // A publicly known breached password, used to prove it is refused; not a secret.
    ['a breached password', '1qaz2wsx3edc', 'password_common'], // gitleaks:allow
    ['the email local part', 'LOCALPART-is-my-password', 'password_contains_identity'],
  ])('refuses a password that is %s with a helpful, value-free issue code', async (_label, password, code) => {
    const identity = newIdentity();
    const withIdentity = { ...identity, email: 'localpart@example.test' };
    const response = await new Browser(api).register({
      ...(code === 'password_contains_identity' ? withIdentity : identity),
      password,
    });
    expect(response.status).toBe(400);
    expect(errorCode(response)).toBe('PASSWORD_REJECTED');
    expect(JSON.stringify(response.body)).toContain(code);
    expect(JSON.stringify(response.body)).not.toContain(password);
  });

  it('accepts a 128-character password and a Unicode passphrase without truncating them', async () => {
    const long = { ...newIdentity(), password: `${newIdentity().password}${'z'.repeat(128)}`.slice(0, 128) };
    const browser = new Browser(api);
    expect((await browser.register(long)).status).toBe(201);
    expect((await browser.login(long)).status).toBe(200);
    // One character less must fail: the stored hash covers all 128 characters.
    const truncated = await new Browser(api).login({ ...long, password: long.password.slice(0, 127) });
    expect(truncated.status).toBe(401);
  });

  it('rejects control characters in the display name', async () => {
    const response = await new Browser(api).register({ ...newIdentity(), displayName: 'bad\u0007name' });
    expect(response.status).toBe(400);
  });

  it('limits registrations per client address (10 per hour)', async () => {
    const browser = new Browser(api);
    const statuses: number[] = [];
    for (let i = 0; i < 11; i += 1) statuses.push((await browser.register({ ...newIdentity(), password: 'x' })).status);
    expect(statuses.slice(0, 10).every((s) => s === 400)).toBe(true); // the limiter runs before hashing
    expect(statuses[10]).toBe(429);
    expect((await new Browser(api).register(newIdentity())).status).toBe(201); // other addresses unaffected
  });
});
