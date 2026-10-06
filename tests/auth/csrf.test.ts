import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Browser, errorCode, newIdentity, signedInUser, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { TEST_ORIGIN } from '../helpers/api';

// CM-T020 (`csrf` suite, session-and-csrf.md section 8): every state-changing authentication
// request, including registration, login and the MFA step, must come from the CipherMesh origin,
// carry the custom header and use JSON. Rejections happen before any handler runs.
let api: AuthTestApi;

beforeAll(async () => {
  api = await startAuthApi();
});
afterAll(() => api.close());

// Identifiers for the parameterized room routes; the gate rejects before they are looked at.
const PROBE_ROOM = randomUUID();
const PROBE_MEMBER = randomUUID();

const STATE_CHANGING = [
  '/auth/register',
  '/auth/login',
  '/auth/mfa/verify',
  '/auth/mfa/recovery',
  '/auth/logout',
  '/auth/step-up',
  '/auth/password',
  '/auth/sessions/revoke-others',
  '/mfa/totp/enroll',
  '/mfa/totp/disable',
  '/admin/users/disable',
  // Vault and directory (Phase 4): the same gate, before any handler (INV-19).
  '/vault',
  '/vault/rewrap',
  '/vault/reset',
  '/directory/lookup',
  // Rooms (Phase 5): the same gate, before routing, room authorization or any handler.
  '/rooms',
  `/rooms/${PROBE_ROOM}/rename`,
  `/rooms/${PROBE_ROOM}/delete`,
  `/rooms/${PROBE_ROOM}/members/${PROBE_MEMBER}/role`,
  `/rooms/${PROBE_ROOM}/members/${PROBE_MEMBER}/remove`,
  `/rooms/${PROBE_ROOM}/members/${PROBE_MEMBER}/transfer-ownership`,
];

interface Attack {
  readonly label: string;
  readonly headers: Record<string, string>;
  readonly body: string;
  readonly expected: number;
}

const json = JSON.stringify({ email: 'x@example.test', password: 'some-password-1' });
const ATTACKS: Attack[] = [
  {
    label: 'cross-site HTML form post (url-encoded)',
    headers: {
      origin: 'https://evil.example',
      'sec-fetch-site': 'cross-site',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: 'email=x&password=y',
    expected: 403,
  },
  {
    label: 'cross-site form post (multipart)',
    headers: {
      origin: 'https://evil.example',
      'sec-fetch-site': 'cross-site',
      'content-type': 'multipart/form-data; boundary=x',
    },
    body: '--x--',
    expected: 403,
  },
  {
    label: 'cross-site form post (text/plain)',
    headers: { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site', 'content-type': 'text/plain' },
    body: json,
    expected: 403,
  },
  {
    label: 'foreign-origin fetch with JSON and the custom header',
    headers: {
      origin: 'https://evil.example',
      'sec-fetch-site': 'cross-site',
      'content-type': 'application/json',
      'x-ciphermesh-request': '1',
    },
    body: json,
    expected: 403,
  },
  {
    label: 'same-site (sibling subdomain) request',
    headers: {
      origin: 'https://other.ciphermesh.test',
      'sec-fetch-site': 'same-site',
      'content-type': 'application/json',
      'x-ciphermesh-request': '1',
    },
    body: json,
    expected: 403,
  },
  {
    label: 'Origin: null (form under no-referrer, sandboxed frame)',
    headers: { origin: 'null', 'content-type': 'application/json', 'x-ciphermesh-request': '1' },
    body: json,
    expected: 403,
  },
  {
    label: 'neither Sec-Fetch-Site nor Origin',
    headers: { 'content-type': 'application/json', 'x-ciphermesh-request': '1' },
    body: json,
    expected: 403,
  },
  {
    label: 'same origin but without the custom header',
    headers: { origin: TEST_ORIGIN, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
    body: json,
    expected: 403,
  },
  {
    label: 'same origin with the header but a form content type',
    headers: {
      origin: TEST_ORIGIN,
      'sec-fetch-site': 'same-origin',
      'x-ciphermesh-request': '1',
      'content-type': 'text/plain',
    },
    body: json,
    expected: 415,
  },
];

describe('CSRF defences on every state-changing authentication route', () => {
  it.each(STATE_CHANGING.flatMap((path) => ATTACKS.map((attack) => [path, attack.label, attack] as const)))(
    'POST %s: %s is rejected before the handler',
    async (path, _label, attack) => {
      const { browser } = await sharedVictim();
      const response = await fetch(`${api.baseUrl}/api${path}`, {
        method: 'POST',
        headers: {
          ...attack.headers,
          cookie: `__Host-cm_session=${String(browser.session)}`,
          'x-forwarded-for': browser.address,
        },
        body: attack.body,
      });
      expect(response.status).toBe(attack.expected);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe(attack.expected === 403 ? 'ORIGIN_REJECTED' : 'UNSUPPORTED_MEDIA_TYPE');
      expect(response.headers.getSetCookie()).toEqual([]);
      expect(response.headers.get('access-control-allow-origin')).toBeNull();
    },
  );

  it('a cross-site logout attempt has no side effect: the session stays valid', async () => {
    const { browser } = await sharedVictim();
    await fetch(`${api.baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: {
        origin: 'https://evil.example',
        'sec-fetch-site': 'cross-site',
        'content-type': 'application/json',
        cookie: `__Host-cm_session=${String(browser.session)}`,
      },
      body: '{}',
    });
    expect((await browser.request('GET', '/auth/session')).status).toBe(200);
  });

  it('prevents login CSRF: a cross-site login sets no cookie for the attacker account', async () => {
    const attacker = newIdentity();
    await new Browser(api).register(attacker);
    const response = await fetch(`${api.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        origin: 'https://evil.example',
        'sec-fetch-site': 'cross-site',
        'content-type': 'application/json',
        'x-ciphermesh-request': '1',
      },
      body: JSON.stringify(attacker),
    });
    expect(response.status).toBe(403);
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it('safe methods change nothing: GET on a state-changing path is not routed', async () => {
    const { browser } = await sharedVictim();
    const get = await browser.request('GET', '/auth/logout');
    expect(get.status).toBe(404);
    expect((await browser.request('GET', '/auth/session')).status).toBe(200);
  });

  it('answers a CORS preflight without granting anything', async () => {
    const response = await fetch(`${api.baseUrl}/api/auth/login`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://evil.example',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'x-ciphermesh-request, content-type',
      },
    });
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect(response.headers.get('access-control-allow-credentials')).toBeNull();
    expect(response.headers.get('access-control-allow-headers')).toBeNull();
  });

  it('accepts the real same-origin request shape', async () => {
    const { browser } = await signedInUser(api);
    expect((await browser.request('POST', '/auth/logout', {})).status).toBe(200);
    expect(errorCode(await browser.request('GET', '/auth/session'))).toBe('UNAUTHENTICATED');
  });
});

let victim: Awaited<ReturnType<typeof signedInUser>> | undefined;
async function sharedVictim() {
  victim ??= await signedInUser(api);
  return victim;
}
