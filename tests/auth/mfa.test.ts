import { PREAUTH_COOKIE, SESSION_COOKIE } from '@ciphermesh/shared';
import { Secret } from 'otpauth';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { TotpSecretBox } from '../../apps/api/src/auth/totp-secret-box';
import { TEST_AUTH_KEYS } from '../helpers/api';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import {
  Browser,
  errorCode,
  signedInUser,
  startAuthApi,
  totpCode,
  userWithMfa,
  type AuthTestApi,
} from '../helpers/auth';

// CM-T019 (DF-01, DF-02): TOTP enrollment, the MFA login step and its bypass resistance.
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

const sessionStatus = async (b: Browser) => (await b.request('GET', '/auth/session')).status;

describe('TOTP enrollment', () => {
  it('requires a recent step-up before a secret is issued', async () => {
    const { browser } = await signedInUser(api);
    const response = await browser.request('POST', '/mfa/totp/enroll', {});
    expect(response.status).toBe(401);
    expect(errorCode(response)).toBe('STEP_UP_REQUIRED');
  });

  it('is not active until a valid code confirms it; a wrong code changes nothing', async () => {
    const { identity, browser } = await signedInUser(api);
    await browser.request('POST', '/auth/step-up', { password: identity.password });
    const enroll = await browser.request('POST', '/mfa/totp/enroll', {});
    expect(enroll.status).toBe(200);
    expect(String(enroll.body['otpauthUri'])).toMatch(/^otpauth:\/\/totp\/CipherMesh:/);
    const info = await browser.request('GET', '/auth/session');
    expect((info.body['user'] as { mfaEnabled: boolean }).mfaEnabled).toBe(false);
    expect((await new Browser(api).login(identity)).body).toEqual({ status: 'authenticated' }); // still no MFA

    const wrong = await browser.request('POST', '/mfa/totp/confirm', { code: '000000' });
    expect(wrong.status).toBe(401);
    expect(errorCode(wrong)).toBe('INVALID_CODE');
    expect((await new Browser(api).login(identity)).body).toEqual({ status: 'authenticated' });
  });

  it('confirmation enables MFA, returns ten recovery codes once, rotates this session and revokes others', async () => {
    const { identity, browser } = await signedInUser(api);
    const other = new Browser(api);
    await other.login(identity);
    await browser.request('POST', '/auth/step-up', { password: identity.password });
    const enroll = await browser.request('POST', '/mfa/totp/enroll', {});
    const before = String(browser.session);
    const confirm = await browser.request('POST', '/mfa/totp/confirm', {
      code: totpCode(String(enroll.body['secret']), api.clock),
    });
    expect(confirm.status).toBe(200);
    expect(confirm.body['recoveryCodes']).toHaveLength(10);
    expect(browser.session).not.toBe(before);
    expect(await sessionStatus(browser)).toBe(200);
    expect(await sessionStatus(other)).toBe(401);
    const info = await browser.request('GET', '/auth/session');
    expect((info.body['user'] as { mfaEnabled: boolean }).mfaEnabled).toBe(true);
    expect((info.body['session'] as { mfaVerifiedAt: string | null }).mfaVerifiedAt).not.toBeNull();
  });

  it('stores the TOTP secret only encrypted under the server key, bound to the user (CP-11)', async () => {
    const { identity, secret } = await userWithMfa(api);
    const { rows } = await db.query<{ id: string; enc: Buffer; key_id: string; row: string }>(
      `SELECT u.id, u.mfa_totp_secret_enc AS enc, u.mfa_totp_key_id AS key_id, row_to_json(u)::text AS row
         FROM users u WHERE email = $1`,
      [identity.email],
    );
    const row = rows[0];
    const raw = Buffer.from(Secret.fromBase32(secret).bytes);
    expect(row?.enc).toHaveLength(48);
    expect(row?.enc.includes(raw)).toBe(false);
    expect(row?.row).not.toContain(secret);
    expect(row?.key_id).toBe(TEST_AUTH_KEYS.TOTP_ENCRYPTION_KEY_ID);
    const box = new TotpSecretBox(TEST_AUTH_KEYS.TOTP_ENCRYPTION_KEY, TEST_AUTH_KEYS.TOTP_ENCRYPTION_KEY_ID);
    expect(box.open(String(row?.id), String(row?.key_id), row?.enc ?? Buffer.alloc(0)).equals(raw)).toBe(true);
  });

  it('refuses a second enrollment while MFA is enabled', async () => {
    const { identity, browser, secret } = await userWithMfa(api);
    await browser.request('POST', '/auth/step-up', { password: identity.password, code: totpCode(secret, api.clock) });
    const again = await browser.request('POST', '/mfa/totp/enroll', {});
    expect(again.status).toBe(409);
    expect(errorCode(again)).toBe('MFA_STATE_CONFLICT');
  });
});

describe('MFA login step', () => {
  it('issues only a short-lived pre-authentication cookie after the password, never a session', async () => {
    const { identity } = await userWithMfa(api);
    const browser = new Browser(api);
    const login = await browser.login(identity);
    expect(login.body).toEqual({ status: 'mfa_required' });
    expect(browser.session).toBeUndefined();
    expect(login.setCookies.find((c) => c.startsWith(PREAUTH_COOKIE))).toMatch(
      /^__Host-cm_preauth=[A-Za-z0-9_-]{43}; Max-Age=300; Path=\/; Secure; HttpOnly; SameSite=Strict$/,
    );
  });

  it('cannot be bypassed: the pre-authentication token opens no authenticated endpoint', async () => {
    const { identity } = await userWithMfa(api);
    const browser = new Browser(api);
    await browser.login(identity);
    const preAuth = String(browser.preAuth);
    expect(await sessionStatus(browser)).toBe(401);
    expect((await browser.request('GET', '/auth/sessions')).status).toBe(401);
    expect((await browser.request('POST', '/auth/logout', {})).status).toBe(401);
    // Presenting the pre-authentication token as a session token does not work either.
    const swapped = new Browser(api);
    swapped.cookies.set(SESSION_COOKIE, preAuth);
    expect(await sessionStatus(swapped)).toBe(401);
    // And the MFA step without the pre-authentication state is refused.
    const noState = await new Browser(api).request('POST', '/auth/mfa/verify', { code: '123456' });
    expect(noState.status).toBe(401);
  });

  it('completes with a valid code, replaces the pre-authentication state and is single use', async () => {
    const { identity, secret } = await userWithMfa(api);
    const browser = new Browser(api);
    await browser.login(identity);
    const preAuth = String(browser.preAuth);
    const verify = await browser.request('POST', '/auth/mfa/verify', { code: totpCode(secret, api.clock) });
    expect(verify.status).toBe(200);
    expect(browser.session).toBeDefined();
    expect(browser.preAuth).toBeUndefined();
    expect(await sessionStatus(browser)).toBe(200);
    const replay = new Browser(api);
    replay.cookies.set(PREAUTH_COOKIE, preAuth);
    api.clock.advance(30_000);
    expect((await replay.request('POST', '/auth/mfa/verify', { code: totpCode(secret, api.clock) })).status).toBe(401);
  });

  it('allows at most five code attempts per pre-authentication state', async () => {
    const { identity, secret } = await userWithMfa(api);
    const browser = new Browser(api);
    await browser.login(identity);
    for (let i = 0; i < 5; i += 1) {
      expect(errorCode(await browser.request('POST', '/auth/mfa/verify', { code: '000000' }))).toBe('INVALID_CODE');
    }
    const sixth = await browser.request('POST', '/auth/mfa/verify', { code: totpCode(secret, api.clock) });
    expect([401, 429]).toContain(sixth.status);
    expect(browser.session).toBeUndefined();
  });

  it('expires the pre-authentication state after five minutes', async () => {
    const { identity, secret } = await userWithMfa(api);
    const browser = new Browser(api);
    await browser.login(identity);
    api.clock.advance(5 * 60_000 + 1000);
    const late = await browser.request('POST', '/auth/mfa/verify', { code: totpCode(secret, api.clock) });
    expect(late.status).toBe(401);
    expect(errorCode(late)).toBe('UNAUTHENTICATED');
  });

  it('accepts one step of clock drift either way, nothing wider, and never the same step twice', async () => {
    const { identity, secret } = await userWithMfa(api);
    // The confirmation consumed an earlier step; move on so that "now - 1 step" is unused.
    api.clock.advance(30_000);
    const attempt = async (offset: number) => {
      const browser = new Browser(api);
      await browser.login(identity);
      return (await browser.request('POST', '/auth/mfa/verify', { code: totpCode(secret, api.clock, offset) })).status;
    };
    expect(await attempt(-2)).toBe(401);
    expect(await attempt(2)).toBe(401);
    expect(await attempt(-1)).toBe(200);
    expect(await attempt(-1)).toBe(401); // replay of a used step
    expect(await attempt(0)).toBe(200);
    expect(await attempt(0)).toBe(401); // replay within the same step
    expect(await attempt(1)).toBe(200);
  });

  it('lets exactly one of two concurrent completions of the same state win', async () => {
    const { identity, secret } = await userWithMfa(api);
    const browser = new Browser(api);
    await browser.login(identity);
    const code = totpCode(secret, api.clock);
    const twin = new Browser(api);
    twin.cookies.set(PREAUTH_COOKIE, String(browser.preAuth));
    const results = await Promise.all([
      browser.request('POST', '/auth/mfa/verify', { code }),
      twin.request('POST', '/auth/mfa/verify', { code }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });
});

describe('disabling MFA', () => {
  it('requires a step-up that includes a current TOTP code, then revokes other sessions', async () => {
    const { identity, browser, secret } = await userWithMfa(api);
    const other = new Browser(api);
    await other.login(identity);
    await other.request('POST', '/auth/mfa/verify', { code: totpCode(secret, api.clock) });
    // Let the step-up from the enrollment expire (15 minutes), keeping the session active.
    for (let i = 0; i < 4; i += 1) {
      api.clock.advance(4 * 60_000);
      expect(await sessionStatus(browser)).toBe(200);
      expect(await sessionStatus(other)).toBe(200);
    }
    expect(errorCode(await browser.request('POST', '/mfa/totp/disable', {}))).toBe('STEP_UP_REQUIRED');
    const passwordOnly = await browser.request('POST', '/auth/step-up', { password: identity.password });
    expect(passwordOnly.status).toBe(401);
    const stepUp = await browser.request('POST', '/auth/step-up', {
      password: identity.password,
      code: totpCode(secret, api.clock),
    });
    expect(stepUp.status).toBe(200);
    expect((await browser.request('POST', '/mfa/totp/disable', {})).status).toBe(200);
    expect(await sessionStatus(other)).toBe(401);
    expect((await new Browser(api).login(identity)).body).toEqual({ status: 'authenticated' });
    const { rows } = await db.query('SELECT mfa_totp_secret_enc FROM users WHERE email = $1', [identity.email]);
    expect(rows).toEqual([{ mfa_totp_secret_enc: null }]);
  });
});
