import { PREAUTH_COOKIE, SESSION_COOKIE } from '@ciphermesh/shared';
import { randomBytes, randomInt } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';
import { inject } from 'vitest';
import { SAME_ORIGIN_HEADERS, startTestApi, type TestApi } from './api';
import { loadDatabaseTestEnv, testDatabase } from './database';
import { storageTestEnv } from './files';
import type { SecurityEvent } from '../../apps/api/src/auth/security-events';
import type { AnyRoute } from '../../apps/api/src/routes/registry';
import type { ObjectStore } from '../../apps/api/src/storage/object-store';

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

/** `routes`: test-only routes, mounted through the registry like production routes (never in production). */
export async function startAuthApi(
  options: { routes?: readonly AnyRoute[]; storage?: ObjectStore; env?: Readonly<Record<string, string>> } = {},
): Promise<AuthTestApi> {
  loadDatabaseTestEnv();
  const clock = new TestClock();
  const events: SecurityEvent[] = [];
  const api = await startTestApi({
    databaseUrl: testDatabase(inject('databaseName')).url('api'),
    // Object storage when the environment configures it (Phase 7; required by the files suites).
    env: { ...storageTestEnv(), ...options.env },
    testing: {
      clock: clock.now,
      events: { record: (event) => events.push(event) },
      ...(options.routes === undefined ? {} : { routes: options.routes }),
      ...(options.storage === undefined ? {} : { storage: options.storage }),
    },
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
// Vitest reloads this module for every test file, but files of one project share a database, and
// the abuse suite counts login attempts by address while other files log in concurrently. A
// counter that restarted per file (even from a random offset) could give two files the same
// address, adding a foreign row to one's count. The address is therefore a group chosen once per
// worker process plus a counter kept on globalThis, which survives the module reloads: no two
// scenarios of one worker share an address, and two workers share a group with probability
// 1 in 65534. One IPv6 group holds at most four hex digits: past 0xffff the address would be
// invalid, the API would key every later request as 'unknown', and the per-address limits would
// trip (observed as a 429 on registration in a full run), so the counter wraps inside 1..0xfffe.
const addressState = globalThis as typeof globalThis & { __cmTestAddress?: { group: number; counter: number } };
addressState.__cmTestAddress ??= { group: randomInt(1, 0xffff), counter: 0 };
export const newAddress = (): string => {
  const state = addressState.__cmTestAddress ?? { group: 1, counter: 0 };
  state.counter = (state.counter % 0xfffe) + 1;
  return `2001:db8::${state.group.toString(16)}:${state.counter.toString(16)}`;
};

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
