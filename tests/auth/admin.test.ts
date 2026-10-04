import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { changePlatformRole } from '../../apps/api/src/auth/admin';
import { authDataAccess } from '../../apps/api/src/db/auth-store';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createLogger } from '../../apps/api/src/logging/logger';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import {
  Browser,
  errorCode,
  newIdentity,
  signedInUser,
  startAuthApi,
  totpCode,
  userWithMfa,
  type AuthTestApi,
} from '../helpers/auth';

// CM-T022: platform administrator bootstrap (server-side only) and account disabling (PA-03).
let api: AuthTestApi;
let database: Database;
let adminDeps: Parameters<typeof changePlatformRole>[0];

beforeAll(async () => {
  api = await startAuthApi();
  loadDatabaseTestEnv();
  const logger = createLogger({ level: 'fatal', sink: { write: () => undefined } });
  database = createDatabase({
    url: new SecretValue(testDatabase(inject('databaseName')).url('api')),
    logger,
    poolMax: 2,
  });
  const data = authDataAccess(database.prisma);
  adminDeps = { transaction: data.transaction, events: { record: () => undefined }, clock: api.clock.now };
});
afterAll(async () => {
  await database.close();
  await api.close();
});

/** An administrator with an MFA-verified session and a fresh step-up. */
async function signedInAdmin() {
  const user = await userWithMfa(api);
  expect(await changePlatformRole(adminDeps, user.identity.email, 'PLATFORM_ADMIN')).toBe('changed');
  const browser = new Browser(api);
  await browser.login(user.identity);
  await browser.request('POST', '/auth/mfa/verify', { code: totpCode(user.secret, api.clock) });
  api.clock.advance(30_000);
  return { ...user, browser };
}

const disable = (browser: Browser, userId: string) => browser.request('POST', '/admin/users/disable', { userId });
const userIdOf = async (browser: Browser) =>
  ((await browser.request('GET', '/auth/session')).body['user'] as { id: string }).id;

describe('platform administrator bootstrap (CLI only)', () => {
  it('cannot be granted to an account without MFA', async () => {
    const identity = newIdentity();
    await new Browser(api).register(identity);
    await expect(changePlatformRole(adminDeps, identity.email, 'PLATFORM_ADMIN')).rejects.toThrow(/multi-factor/);
  });

  it('revokes all sessions of the account when the role changes', async () => {
    const user = await userWithMfa(api);
    await changePlatformRole(adminDeps, user.identity.email, 'PLATFORM_ADMIN');
    expect((await user.browser.request('GET', '/auth/session')).status).toBe(401);
  });

  it('is not grantable through the API: there is no such route and registration refuses the field', async () => {
    const response = await new Browser(api).register({ ...newIdentity(), platformRole: 'PLATFORM_ADMIN' } as never);
    expect(response.status).toBe(400);
  });
});

describe('account disabling (PA-03)', () => {
  it('is invisible to non-administrators (404)', async () => {
    const { browser } = await signedInUser(api);
    const target = await signedInUser(api);
    const response = await disable(browser, await userIdOf(target.browser));
    expect(response.status).toBe(404);
    expect((await target.browser.request('GET', '/auth/session')).status).toBe(200);
  });

  it('requires a step-up even for an administrator', async () => {
    const admin = await signedInAdmin();
    const target = await signedInUser(api);
    expect(errorCode(await disable(admin.browser, await userIdOf(target.browser)))).toBe('STEP_UP_REQUIRED');
  });

  it('disables the account, ends its sessions immediately and blocks login; enabling restores login', async () => {
    const admin = await signedInAdmin();
    await admin.browser.request('POST', '/auth/step-up', {
      password: admin.identity.password,
      code: totpCode(admin.secret, api.clock),
    });
    const target = await signedInUser(api);
    const targetId = await userIdOf(target.browser);
    expect((await disable(admin.browser, targetId)).status).toBe(200);
    expect((await target.browser.request('GET', '/auth/session')).status).toBe(401);
    expect((await new Browser(api).login(target.identity)).status).toBe(401);
    expect((await admin.browser.request('POST', '/admin/users/enable', { userId: targetId })).status).toBe(200);
    expect((await new Browser(api).login(target.identity)).status).toBe(200);
  });

  it('refuses to disable oneself and answers 404 for unknown accounts', async () => {
    const admin = await signedInAdmin();
    api.clock.advance(30_000);
    await admin.browser.request('POST', '/auth/step-up', {
      password: admin.identity.password,
      code: totpCode(admin.secret, api.clock),
    });
    const self = await disable(admin.browser, await userIdOf(admin.browser));
    expect(self.status).toBe(403);
    expect(errorCode(self)).toBe('FORBIDDEN');
    expect((await disable(admin.browser, '7b3f0d0e-4b8f-4c4d-9a35-4a5b0f6a1c11')).status).toBe(404);
  });

  it('administrators cannot switch off their own MFA', async () => {
    const admin = await signedInAdmin();
    api.clock.advance(30_000);
    await admin.browser.request('POST', '/auth/step-up', {
      password: admin.identity.password,
      code: totpCode(admin.secret, api.clock),
    });
    const response = await admin.browser.request('POST', '/mfa/totp/disable', {});
    expect(response.status).toBe(403);
  });
});

describe('last administrator protection', () => {
  it('the CLI refuses to remove the role from the last active administrator', async () => {
    // Remove every other administrator created by this file's tests, then try the last one.
    const admin = await userWithMfa(api);
    await changePlatformRole(adminDeps, admin.identity.email, 'PLATFORM_ADMIN');
    const { rows } = await (async () => {
      const client = await testDatabase(inject('databaseName')).connect('api');
      try {
        return await client.query<{ email: string }>(
          `SELECT email FROM users WHERE platform_role = 'PLATFORM_ADMIN' AND status = 'ACTIVE' AND email <> $1`,
          [admin.identity.email],
        );
      } finally {
        await client.end();
      }
    })();
    for (const row of rows) await changePlatformRole(adminDeps, row.email, 'USER');
    await expect(changePlatformRole(adminDeps, admin.identity.email, 'USER')).rejects.toThrow(/last active/);
  });
});
