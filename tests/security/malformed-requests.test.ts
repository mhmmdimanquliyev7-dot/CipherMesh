import { request } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SAME_ORIGIN_HEADERS, startTestApi, type TestApi } from '../helpers/api';

// Hostile request shapes (T-14, T-15, T-26): the API answers with a generic error,
// never crashes, never decompresses, and never leaks internals.
let api: TestApi;
beforeAll(async () => {
  api = await startTestApi();
});
afterAll(() => api.close());

function raw(
  path: string,
  headers: Record<string, string> = {},
  body?: string,
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const { port } = new URL(api.baseUrl);
    const req = request(
      { host: '127.0.0.1', port, path, method: body === undefined ? 'GET' : 'POST', headers },
      (res) => {
        let text = '';
        res.on('data', (chunk: Buffer) => (text += chunk.toString()));
        res.on('end', () => {
          resolve({ status: res.statusCode ?? 0, text });
        });
      },
    );
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

describe('malformed requests', () => {
  it.each(['/api/%E0%A4%A', '/api/health%00', '/api/../../etc/passwd'])('%s gets a generic 404', async (path) => {
    const response = await raw(path);
    expect(response.status).toBe(404);
    expect(response.text).toContain('"code":"NOT_FOUND"');
  });

  it('rejects oversized URLs before routing', async () => {
    const response = await raw(`/api/${'a'.repeat(20_000)}`);
    expect(response.status).toBe(431);
  });

  it('refuses compressed request bodies instead of decompressing them', async () => {
    const response = await raw(
      '/api/health',
      { ...SAME_ORIGIN_HEADERS, 'content-type': 'application/json', 'content-encoding': 'gzip' },
      'not really gzip',
    );
    expect(response.status).toBe(415);
    expect(response.text).toContain('"code":"UNSUPPORTED_MEDIA_TYPE"');
  });

  it('never logs an unhandled error for these requests', () => {
    expect(api.logText()).not.toContain('unhandled error');
  });
});
