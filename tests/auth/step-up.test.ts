import { SESSION_COOKIE } from '@ciphermesh/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Browser, errorCode, signedInUser, startAuthApi, type AuthTestApi } from '../helpers/auth';

// CM-T021: step-up re-authentication. The gate is enforced by the server on the session row;
// nothing the client sends can claim a step-up.
let api: AuthTestApi;

beforeAll(async () => {
  api = await startAuthApi();
});
afterAll(() => api.close());

const GATED = '/mfa/totp/enroll';

describe('step-up', () => {
  it('a gated action fails with STEP_UP_REQUIRED, succeeds after a step-up, and fails again after 15 minutes', async () => {
    const { identity, browser } = await signedInUser(api);
    expect(errorCode(await browser.request('POST', GATED, {}))).toBe('STEP_UP_REQUIRED');

    const stepUp = await browser.request('POST', '/auth/step-up', { password: identity.password });
    expect(stepUp.status).toBe(200);
    expect(typeof stepUp.body['stepUpAt']).toBe('string');
    api.clock.advance(14 * 60_000);
    expect((await browser.request('POST', GATED, {})).status).toBe(200);

    api.clock.advance(60_000 + 1);
    expect(errorCode(await browser.request('POST', GATED, {}))).toBe('STEP_UP_REQUIRED');
  });

  it('rotates the session token, so the pre-step-up token stops working (fixation)', async () => {
    const { identity, browser } = await signedInUser(api);
    const before = String(browser.session);
    await browser.request('POST', '/auth/step-up', { password: identity.password });
    expect(browser.session).not.toBe(before);
    const stale = new Browser(api);
    stale.cookies.set(SESSION_COOKIE, before);
    expect((await stale.request('GET', '/auth/session')).status).toBe(401);
  });

  it('a wrong password fails, is recorded, and does not unlock the gate', async () => {
    const { browser } = await signedInUser(api);
    const failed = await browser.request('POST', '/auth/step-up', { password: 'not-my-password-1' });
    expect(failed.status).toBe(401);
    expect(errorCode(failed)).toBe('INVALID_CREDENTIALS');
    expect(api.events.some((e) => e.name === 'STEP_UP_FAILED')).toBe(true);
    expect(errorCode(await browser.request('POST', GATED, {}))).toBe('STEP_UP_REQUIRED');
  });

  it('cannot be claimed by the client: fields and headers that look like a step-up are refused or ignored', async () => {
    const { browser } = await signedInUser(api);
    const forged = await browser.request('POST', GATED, { stepUpAt: new Date().toISOString() });
    expect(forged.status).toBe(400); // unknown body fields are rejected
    const header = await browser.request('POST', GATED, {}, { 'x-step-up': 'true' });
    expect(errorCode(header)).toBe('STEP_UP_REQUIRED');
  });

  it('limits password re-verification per user (10 per 15 minutes)', async () => {
    const { browser } = await signedInUser(api);
    const statuses: number[] = [];
    for (let i = 0; i < 11; i += 1) {
      statuses.push(
        (await browser.request('POST', '/auth/step-up', { password: `guess-${String(i)}-password` })).status,
      );
    }
    expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true);
    expect(statuses[10]).toBe(429);
  });

  it('requires authentication: there is no anonymous step-up', async () => {
    const response = await new Browser(api).request('POST', '/auth/step-up', { password: 'whatever-pass-1' });
    expect(response.status).toBe(401);
    expect(errorCode(response)).toBe('UNAUTHENTICATED');
  });
});
