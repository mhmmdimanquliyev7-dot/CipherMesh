import { createHash } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { Browser, errorCode, startAuthApi, totpCode, userWithMfa, type AuthTestApi } from '../helpers/auth';

// CM-T019 recovery codes (CP-10): single use, digests only, regeneration invalidates old codes,
// and a recovery-code login revokes the other sessions (session-and-csrf.md section 4).
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

async function recoveryLogin(identity: { email: string; password: string }, code: string) {
  const browser = new Browser(api);
  await browser.login(identity);
  return { browser, response: await browser.request('POST', '/auth/mfa/recovery', { recoveryCode: code }) };
}

describe('recovery codes', () => {
  it('work exactly once, report the remaining count and revoke the other sessions', async () => {
    const { identity, browser, recoveryCodes } = await userWithMfa(api);
    const code = String(recoveryCodes[0]);
    const first = await recoveryLogin(identity, code);
    expect(first.response.status).toBe(200);
    expect(first.response.body).toEqual({ status: 'authenticated', recoveryCodesRemaining: 9 });
    expect((await first.browser.request('GET', '/auth/session')).status).toBe(200);
    expect((await browser.request('GET', '/auth/session')).status).toBe(401);
    expect(api.events.some((e) => e.name === 'RECOVERY_CODE_USED')).toBe(true);

    const second = await recoveryLogin(identity, code);
    expect(second.response.status).toBe(401);
    expect(errorCode(second.response)).toBe('INVALID_CODE');
  });

  it('accept lower case and missing separators, and reject invalid codes', async () => {
    const { identity, recoveryCodes } = await userWithMfa(api);
    const relaxed = String(recoveryCodes[1]).toLowerCase().replaceAll('-', '');
    expect((await recoveryLogin(identity, relaxed)).response.status).toBe(200);
    expect((await recoveryLogin(identity, 'AAAAA-BBBBB-CCCCC-DDDDD')).response.status).toBe(401);
    expect((await recoveryLogin(identity, 'not a code')).response.status).toBe(401);
  });

  it('are stored only as SHA-256 digests', async () => {
    const { identity, recoveryCodes } = await userWithMfa(api);
    const { rows } = await db.query<{ row: string; digest: Buffer }>(
      `SELECT row_to_json(r)::text AS row, r.code_digest AS digest FROM recovery_codes r
         JOIN users u ON u.id = r.user_id WHERE u.email = $1`,
      [identity.email],
    );
    expect(rows).toHaveLength(10);
    const digests = new Set(rows.map((r) => r.digest.toString('hex')));
    for (const code of recoveryCodes) {
      expect(rows.map((r) => r.row).join()).not.toContain(code.replaceAll('-', ''));
      expect(digests.has(createHash('sha256').update(code.replaceAll('-', '')).digest('hex'))).toBe(true);
    }
  });

  it('are consumed by exactly one of two concurrent logins', async () => {
    const { identity, recoveryCodes } = await userWithMfa(api);
    const a = new Browser(api);
    const b = new Browser(api);
    await a.login(identity);
    await b.login(identity);
    const code = String(recoveryCodes[2]);
    const results = await Promise.all([
      a.request('POST', '/auth/mfa/recovery', { recoveryCode: code }),
      b.request('POST', '/auth/mfa/recovery', { recoveryCode: code }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });

  it('regeneration needs a step-up and invalidates every previous code', async () => {
    const { identity, browser, secret, recoveryCodes } = await userWithMfa(api);
    for (let i = 0; i < 4; i += 1) {
      api.clock.advance(4 * 60_000);
      await browser.request('GET', '/auth/session');
    }
    expect(errorCode(await browser.request('POST', '/mfa/recovery-codes/regenerate', {}))).toBe('STEP_UP_REQUIRED');
    await browser.request('POST', '/auth/step-up', { password: identity.password, code: totpCode(secret, api.clock) });
    const regenerated = await browser.request('POST', '/mfa/recovery-codes/regenerate', {});
    expect(regenerated.status).toBe(200);
    const fresh = regenerated.body['recoveryCodes'] as string[];
    expect(fresh).toHaveLength(10);
    expect(fresh.some((c) => recoveryCodes.includes(c))).toBe(false);
    expect((await recoveryLogin(identity, String(recoveryCodes[3]))).response.status).toBe(401);
    expect((await recoveryLogin(identity, String(fresh[0]))).response.status).toBe(200);
  });
});
