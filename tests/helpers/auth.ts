import { PREAUTH_COOKIE, SESSION_COOKIE } from '@ciphermesh/shared';
import { randomBytes, randomInt } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';
import { inject } from 'vitest';
import { SAME_ORIGIN_HEADERS, startTestApi, type TestApi } from './api';
import { loadDatabaseTestEnv, testDatabase } from './database';
import type { SecurityEvent } from '../../apps/api/src/auth/security-events';

// Helpers for the authentication suites (tests/auth). Every test talks to the real API over HTTP
// with real Argon2id, real sessions in PostgreSQL and the least-privilege cm_api role. Nothing in
// the authentication path is mocked; only the clock is controllable, to test expiry windows.

/** A clock tests can move forward. Starts at the real time. */
export class TestClock {
  private offsetMs = 0;
  now = (): Date => new Date(Date.now() + this.offsetMs);
  advance(ms: number): void {
    this.offsetMs += ms;
  }
}

export interface AuthTestApi extends TestApi {
  readonly clock: TestClock;
  readonly events: SecurityEvent[];
}

export async function startAuthApi(): Promise<AuthTestApi> {
  loadDatabaseTestEnv();
  const clock = new TestClock();
  const events: SecurityEvent[] = [];
  const api = await startTestApi({
    databaseUrl: testDatabase(inject('databaseName')).url('api'),
    testing: { clock: clock.now, events: { record: (event) => events.push(event) } },
  });
  return { ...api, clock, events };
}

/** A random synthetic identity: never a real person, never a committed credential. */
export function newIdentity(): { email: string; password: string; displayName: string } {
  return {
    email: `user-${randomBytes(6).toString('hex')}@example.test`,
    password: `${randomBytes(15).toString('base64url')}!`,
    displayName: 'Synthetic Test User',
  };
}

/**
 * A distinct client address per scenario (IPv6 documentation range, RFC 3849), so per-address
 * limits never leak between tests.
 */
let addressCounter = randomInt(1, 0xffff);
export const newAddress = (): string => `2001:db8::${(addressCounter += 1).toString(16)}`;

interface Response {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly setCookies: readonly string[];
  readonly headers: Headers;
}

/**
 * A minimal browser: a cookie jar for the two authentication cookies and the same-origin headers
 * a real fetch() from the CipherMesh page sends (INV-19).
 */
export class Browser {
  readonly cookies = new Map<string, string>();

  constructor(
    private readonly api: TestApi,
    readonly address: string = newAddress(),
  ) {}

  async request(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {},
  ): Promise<Response> {
    const cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    const response = await fetch(`${this.api.baseUrl}/api${path}`, {
      method,
      headers: {
        ...(method === 'POST' ? { ...SAME_ORIGIN_HEADERS, 'content-type': 'application/json' } : {}),
        'x-forwarded-for': this.address,
        'user-agent': 'CipherMesh test browser',
        ...(cookie === '' ? {} : { cookie }),
        ...extraHeaders,
      },
      ...(method === 'POST' ? { body: JSON.stringify(body ?? {}) } : {}),
    });
    const setCookies = response.headers.getSetCookie();
    for (const header of setCookies) {
      const [pair = '', ...attributes] = header.split(';');
      const index = pair.indexOf('=');
      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      const expired = attributes.some((a) => a.trim().toLowerCase() === 'max-age=0');
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    const text = await response.text();
    return {
      status: response.status,
      body: text === '' ? {} : (JSON.parse(text) as Record<string, unknown>),
      setCookies,
      headers: response.headers,
    };
  }

  get session(): string | undefined {
    return this.cookies.get(SESSION_COOKIE);
  }

  get preAuth(): string | undefined {
    return this.cookies.get(PREAUTH_COOKIE);
  }

  register(identity: { email: string; password: string; displayName: string }) {
    return this.request('POST', '/auth/register', identity);
  }

  login(identity: { email: string; password: string }) {
    return this.request('POST', '/auth/login', { email: identity.email, password: identity.password });
  }
}

export const errorCode = (response: { body: Record<string, unknown> }): unknown =>
  (response.body['error'] as { code?: unknown } | undefined)?.code;

/** Registers and logs in a fresh account; returns its browser with a session. */
export async function signedInUser(api: AuthTestApi) {
  const identity = newIdentity();
  const browser = new Browser(api);
  const registered = await browser.register(identity);
  if (registered.status !== 201) throw new Error(`registration failed: ${String(registered.status)}`);
  const login = await browser.login(identity);
  if (login.status !== 200) throw new Error(`login failed: ${String(login.status)}`);
  return { identity, browser };
}

/** A TOTP code for the base32 secret at the API's (test) time, optionally shifted by steps. */
export function totpCode(base32: string, clock: TestClock, stepOffset = 0): string {
  return TOTP.generate({
    secret: Secret.fromBase32(base32),
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    timestamp: clock.now().getTime() + stepOffset * 30_000,
  });
}

/** Signs in, steps up, enrolls and confirms TOTP; returns the secret and recovery codes. */
export async function userWithMfa(api: AuthTestApi) {
  const { identity, browser } = await signedInUser(api);
  const stepUp = await browser.request('POST', '/auth/step-up', { password: identity.password });
  if (stepUp.status !== 200) throw new Error(`step-up failed: ${String(stepUp.status)}`);
  const enroll = await browser.request('POST', '/mfa/totp/enroll', {});
  const secret = String(enroll.body['secret']);
  const confirm = await browser.request('POST', '/mfa/totp/confirm', { code: totpCode(secret, api.clock) });
  if (confirm.status !== 200) throw new Error(`MFA confirmation failed: ${String(confirm.status)}`);
  // Move past the confirmed time step so the next code is not a replay.
  api.clock.advance(30_000);
  return { identity, browser, secret, recoveryCodes: confirm.body['recoveryCodes'] as string[] };
}
