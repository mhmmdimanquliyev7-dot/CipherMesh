import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SECURITY_EVENTS } from '../../apps/api/src/auth/security-events';
import { Browser, newIdentity, startAuthApi, totpCode, userWithMfa, type AuthTestApi } from '../helpers/auth';

// INV-10 for authentication: after every flow has run, no password, TOTP secret, otpauth URI,
// recovery code, session or pre-authentication token appears in the log or in security events.
let api: AuthTestApi;
const secrets: string[] = [];

beforeAll(async () => {
  api = await startAuthApi();
  const user = await userWithMfa(api);
  secrets.push(user.identity.password, user.secret, ...user.recoveryCodes, String(user.browser.session));

  const mfaLogin = new Browser(api);
  await mfaLogin.login(user.identity);
  secrets.push(String(mfaLogin.preAuth));
  await mfaLogin.request('POST', '/auth/mfa/verify', { code: '000000' });
  await mfaLogin.request('POST', '/auth/mfa/verify', { code: totpCode(user.secret, api.clock) });
  secrets.push(String(mfaLogin.session));

  const recovery = new Browser(api);
  await recovery.login(user.identity);
  await recovery.request('POST', '/auth/mfa/recovery', { recoveryCode: String(user.recoveryCodes[0]) });
  secrets.push(String(recovery.session));

  api.clock.advance(30_000);
  await recovery.request('POST', '/auth/step-up', { password: `${user.identity.password}-typo` });
  await recovery.request('POST', '/auth/step-up', {
    password: user.identity.password,
    code: totpCode(user.secret, api.clock),
  });
  api.clock.advance(30_000);
  const newPassword = newIdentity().password;
  secrets.push(newPassword);
  await recovery.request('POST', '/auth/password', {
    currentPassword: user.identity.password,
    newPassword,
    code: totpCode(user.secret, api.clock),
  });
  await recovery.request('POST', '/auth/logout', {});
  await new Browser(api).login({ email: user.identity.email, password: `${newPassword}-wrong` });
  await new Browser(api).login({ email: newPassword, password: newPassword }); // password typed as email
});
afterAll(() => api.close());

describe('authentication logging', () => {
  it('ran the flows that produce security events', () => {
    const names = new Set(api.events.map((e) => e.name));
    for (const expected of [
      'MFA_ENABLED',
      'LOGIN_SUCCEEDED',
      'MFA_CHALLENGE_FAILED',
      'RECOVERY_CODE_USED',
      'STEP_UP_FAILED',
      'STEP_UP_COMPLETED',
      'PASSWORD_CHANGED',
      'LOGOUT',
      'LOGIN_FAILED',
    ] as const) {
      expect(names.has(expected), expected).toBe(true);
    }
    expect(api.events.every((e) => (SECURITY_EVENTS as readonly string[]).includes(e.name))).toBe(true);
  });

  it('writes no secret into the application log', () => {
    const log = api.logText();
    expect(log.length).toBeGreaterThan(1000);
    for (const secret of secrets) {
      expect(secret.length).toBeGreaterThan(8);
      expect(log).not.toContain(secret);
    }
    expect(log).not.toContain('otpauth://');
    expect(log).not.toContain('__Host-cm_session=');
  });

  it('puts only allowlisted, non-secret facts into security events', () => {
    const serialized = JSON.stringify(api.events);
    for (const secret of secrets) expect(serialized).not.toContain(secret);
    for (const event of api.events) {
      for (const value of Object.values(event.details ?? {})) {
        expect(['string', 'number', 'boolean']).toContain(typeof value);
        if (typeof value === 'string') expect(value.length).toBeLessThan(32);
      }
    }
  });
});
