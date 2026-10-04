import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { emptyQuerySchema, z } from '@ciphermesh/validation';
import { API_SECURITY_HEADERS } from '../../apps/api/src/http/security-headers';
import { defineRoute } from '../../apps/api/src/routes/registry';
import { SAME_ORIGIN_HEADERS, TEST_ORIGIN, startTestApi, type TestApi } from '../helpers/api';

// Covers T-12 (headers), T-13 (CSRF gate, INV-19), T-15 (information disclosure) and
// principle 7 (no secrets in logs) for the Phase 1 foundation.
const writeRoute = defineRoute({
  method: 'POST',
  path: '/test/write',
  action: 'TEST-WRITE',
  access: { kind: 'public', justification: 'security test' },
  query: emptyQuerySchema,
  body: z.strictObject({}),
  response: z.strictObject({ done: z.boolean() }),
  handler: () => ({ status: 200, body: { done: true } }),
});

let api: TestApi;
beforeAll(async () => {
  api = await startTestApi({
    testing: { routes: [writeRoute], publicAllowlist: [{ method: 'POST', path: '/test/write' }] },
  });
});
afterAll(() => api.close());

const write = (headers: Record<string, string>): Promise<Response> =>
  fetch(`${api.baseUrl}/api/test/write`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: '{}',
  });

describe('security headers', () => {
  it('are present on success and error responses alike', async () => {
    for (const path of ['/api/health', '/api/does-not-exist']) {
      const response = await fetch(`${api.baseUrl}${path}`);
      for (const [name, value] of Object.entries(API_SECURITY_HEADERS)) expect(response.headers.get(name)).toBe(value);
    }
  });

  it('do not disclose the framework or server version', async () => {
    const response = await fetch(`${api.baseUrl}/api/health`);
    expect(response.headers.get('x-powered-by')).toBeNull();
    expect(response.headers.get('server')).toBeNull();
    expect(response.headers.get('etag')).toBeNull();
  });

  it('use a fresh server-generated request ID and ignore client-supplied ones', async () => {
    const response = await fetch(`${api.baseUrl}/api/health`, { headers: { 'x-request-id': 'attacker-chosen' } });
    expect(response.headers.get('x-request-id')).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('CORS', () => {
  it('never grants cross-origin access, including to preflight requests', async () => {
    const preflight = await fetch(`${api.baseUrl}/api/test/write`, {
      method: 'OPTIONS',
      headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' },
    });
    expect(preflight.headers.get('access-control-allow-origin')).toBeNull();
    expect(preflight.headers.get('access-control-allow-credentials')).toBeNull();
  });
});

describe('same-origin gate for state-changing requests (INV-19)', () => {
  it('accepts a same-origin request with the CipherMesh header', async () => {
    expect((await write(SAME_ORIGIN_HEADERS)).status).toBe(200);
  });

  it('accepts an exact Origin match when Fetch Metadata is absent', async () => {
    expect((await write({ origin: TEST_ORIGIN, 'x-ciphermesh-request': '1' })).status).toBe(200);
  });

  it.each([
    ['cross-site Fetch Metadata', { 'sec-fetch-site': 'cross-site', 'x-ciphermesh-request': '1' }],
    ['same-site but cross-origin', { 'sec-fetch-site': 'same-site', 'x-ciphermesh-request': '1' }],
    ['a foreign Origin', { origin: 'https://evil.example', 'x-ciphermesh-request': '1' }],
    ['Origin null (form post under no-referrer)', { origin: 'null', 'x-ciphermesh-request': '1' }],
    ['neither Fetch Metadata nor Origin', { 'x-ciphermesh-request': '1' }],
    ['a missing CipherMesh header', { origin: TEST_ORIGIN, 'sec-fetch-site': 'same-origin' }],
  ])('rejects %s with 403 before the body is parsed', async (_label, headers) => {
    const response = await fetch(`${api.baseUrl}/api/test/write`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: '{ this is not even JSON',
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe('ORIGIN_REJECTED');
  });
});

describe('logging', () => {
  it('keeps secrets in headers, query strings and bodies out of the log', async () => {
    await fetch(`${api.baseUrl}/api/health?token=canary-query-token`, {
      headers: { authorization: 'Bearer canary-bearer', cookie: '__Host-cm_session=canary-cookie' },
    });
    await fetch(`${api.baseUrl}/api/test/write`, {
      method: 'POST',
      headers: { ...SAME_ORIGIN_HEADERS, 'content-type': 'application/json' },
      body: '{"password":"canary-body-password"}',
    });
    const log = api.logText();
    expect(log).toContain('request completed');
    expect(log).not.toMatch(/canary-/);
  });
});
