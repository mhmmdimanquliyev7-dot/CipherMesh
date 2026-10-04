import {
  apiErrorBodySchema,
  emptyQuerySchema,
  healthResponseSchema,
  readinessResponseSchema,
  z,
} from '@ciphermesh/validation';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defineRoute } from '../../apps/api/src/routes/registry';
import { SAME_ORIGIN_HEADERS, startTestApi, type TestApi } from '../helpers/api';

// Test-only routes exercise the generic pipeline (validation, projection, error handling).
// They exist only in this test process: createApp refuses them in production.
const testRoutes = [
  defineRoute({
    method: 'POST',
    path: '/test/echo-length',
    action: 'TEST-ECHO',
    access: { kind: 'public', justification: 'integration test' },
    query: emptyQuerySchema,
    body: z.strictObject({ value: z.string().max(10) }),
    response: z.strictObject({ length: z.number() }),
    handler: ({ body }) => ({ status: 200, body: { length: body.value.length } }),
  }),
  defineRoute({
    method: 'GET',
    path: '/test/leaky',
    action: 'TEST-LEAKY',
    access: { kind: 'public', justification: 'integration test' },
    query: emptyQuerySchema,
    body: undefined,
    response: z.strictObject({ ok: z.boolean() }),
    // Returns a field outside its response schema: must never reach the client.
    handler: () => ({ status: 200, body: { ok: true, passwordHash: 'canary-hash' } as { ok: boolean } }),
  }),
  defineRoute({
    method: 'GET',
    path: '/test/crash',
    action: 'TEST-CRASH',
    access: { kind: 'public', justification: 'integration test' },
    query: emptyQuerySchema,
    body: undefined,
    response: z.strictObject({}),
    handler: () => {
      throw new Error('database password canary-internal at /srv/app/db.ts');
    },
  }),
];

let api: TestApi;

beforeAll(async () => {
  api = await startTestApi({
    testing: {
      routes: testRoutes,
      publicAllowlist: [
        { method: 'POST', path: '/test/echo-length' },
        { method: 'GET', path: '/test/leaky' },
        { method: 'GET', path: '/test/crash' },
      ],
    },
  });
});
afterAll(() => api.close());

async function errorOf(response: Response): Promise<z.infer<typeof apiErrorBodySchema>['error']> {
  return apiErrorBodySchema.parse(await response.json()).error;
}

const post = (path: string, body: string, contentType = 'application/json'): Promise<Response> =>
  fetch(`${api.baseUrl}${path}`, {
    method: 'POST',
    headers: { ...SAME_ORIGIN_HEADERS, 'content-type': contentType },
    body,
  });

describe('health and readiness', () => {
  it('GET /api/health returns only a status word', async () => {
    const response = await fetch(`${api.baseUrl}/api/health`);
    expect(response.status).toBe(200);
    expect(healthResponseSchema.parse(await response.json())).toEqual({ status: 'ok' });
  });

  it('GET /api/ready reflects the lifecycle state', async () => {
    expect(readinessResponseSchema.parse(await (await fetch(`${api.baseUrl}/api/ready`)).json())).toEqual({
      status: 'ready',
    });
    api.lifecycle.markShuttingDown();
    const response = await fetch(`${api.baseUrl}/api/ready`);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ status: 'not-ready' });
  });

  it('rejects unexpected query parameters instead of ignoring them', async () => {
    const response = await fetch(`${api.baseUrl}/api/health?debug=1`);
    expect(response.status).toBe(400);
    expect(await errorOf(response)).toMatchObject({
      code: 'VALIDATION_FAILED',
      issues: [{ path: '(root)', code: 'unrecognized_keys' }],
    });
  });
});

describe('unknown routes', () => {
  it.each(['/api/unknown', '/api/health/extra', '/', '/.env'])('%s returns the generic 404 body', async (path) => {
    const response = await fetch(`${api.baseUrl}${path}`);
    expect(response.status).toBe(404);
    expect(await errorOf(response)).toMatchObject({ code: 'NOT_FOUND', message: 'Resource not found' });
  });

  it('answers an unregistered method on a known path with 404', async () => {
    const response = await post('/api/health', '{}');
    expect(response.status).toBe(404);
  });
});

describe('request bodies', () => {
  it('accepts a valid JSON body and validates it', async () => {
    const response = await post('/api/test/echo-length', '{"value":"abc"}');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ length: 3 });
  });

  it('rejects malformed JSON with 400 INVALID_JSON', async () => {
    const response = await post('/api/test/echo-length', '{"value": ');
    expect(response.status).toBe(400);
    expect(await errorOf(response)).toMatchObject({ code: 'INVALID_JSON' });
  });

  it('rejects JSON scalars at the top level (strict parsing)', async () => {
    const response = await post('/api/test/echo-length', '"just a string"');
    expect(response.status).toBe(400);
  });

  it('rejects bodies over the limit with 413 before validation', async () => {
    const response = await post('/api/test/echo-length', JSON.stringify({ value: 'x'.repeat(200 * 1024) }));
    expect(response.status).toBe(413);
    expect(await errorOf(response)).toMatchObject({ code: 'PAYLOAD_TOO_LARGE' });
  });

  it.each(['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x'])(
    'rejects %s with 415',
    async (type) => {
      const response = await post('/api/test/echo-length', '{"value":"abc"}', type);
      expect(response.status).toBe(415);
      expect(await errorOf(response)).toMatchObject({ code: 'UNSUPPORTED_MEDIA_TYPE' });
    },
  );

  it('rejects a non-UTF-8 charset with 415', async () => {
    const response = await post('/api/test/echo-length', '{"value":"abc"}', 'application/json; charset=latin1');
    expect(response.status).toBe(415);
  });

  it('rejects unknown fields and reports paths and codes only', async () => {
    const response = await post('/api/test/echo-length', '{"value":"abc","role":"admin"}');
    expect(response.status).toBe(400);
    const error = await errorOf(response);
    expect(error.code).toBe('VALIDATION_FAILED');
    expect(JSON.stringify(error)).not.toContain('admin');
  });
});

describe('fail-closed responses', () => {
  it('never sends fields outside the response schema', async () => {
    const response = await fetch(`${api.baseUrl}/api/test/leaky`);
    const text = await response.text();
    expect(response.status).toBe(500);
    expect(text).not.toContain('canary-hash');
  });

  it('hides internal error details: no message, stack or path', async () => {
    const response = await fetch(`${api.baseUrl}/api/test/crash`);
    const text = await response.text();
    expect(response.status).toBe(500);
    expect(JSON.parse(text)).toEqual({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        requestId: response.headers.get('x-request-id'),
      },
    });
    expect(text).not.toMatch(/canary-internal|\/srv\/app|at .*\.ts|stack/i);
  });
});
