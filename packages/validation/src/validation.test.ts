import { describe, expect, it } from 'vitest';
import { apiErrorBodySchema, emptyQuerySchema, healthResponseSchema, parseWith, uuidV4Schema, z } from './index';

describe('strict schemas', () => {
  it('reject unknown keys, including __proto__ created by JSON.parse', () => {
    const polluted: unknown = JSON.parse('{"status":"ok","__proto__":{"admin":true}}');
    expect(parseWith(healthResponseSchema, polluted).success).toBe(false);
    expect(parseWith(emptyQuerySchema, { anything: '1' }).success).toBe(false);
  });

  it('accept exactly the declared shape', () => {
    expect(parseWith(healthResponseSchema, { status: 'ok' })).toEqual({ success: true, data: { status: 'ok' } });
  });
});

describe('validation issues', () => {
  it('contain only paths and codes, never the rejected value', () => {
    const schema = z.strictObject({ password: z.string().min(12), nested: z.strictObject({ token: z.number() }) });
    const result = parseWith(schema, { password: 'hunter2', nested: { token: 'tok_abc123' } });
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.issues).toEqual([
      { path: 'password', code: 'too_small' },
      { path: 'nested.token', code: 'invalid_type' },
    ]);
    const serialized = JSON.stringify(result.issues);
    expect(serialized).not.toContain('hunter2');
    expect(serialized).not.toContain('tok_abc123');
  });

  it('label root-level problems', () => {
    const result = parseWith(healthResponseSchema, 'not an object');
    expect(result).toEqual({ success: false, issues: [{ path: '(root)', code: 'invalid_type' }] });
  });
});

describe('shared boundary schemas', () => {
  it('validate the API error body shape', () => {
    const body = {
      error: { code: 'NOT_FOUND', message: 'Resource not found', requestId: '0b2f6c1e-8d3a-4f5b-9c7d-2e1f0a9b8c7d' },
    };
    expect(parseWith(apiErrorBodySchema, body).success).toBe(true);
    expect(parseWith(apiErrorBodySchema, { error: { ...body.error, code: 'TEAPOT' } }).success).toBe(false);
  });

  it('accept only version 4 UUIDs', () => {
    expect(uuidV4Schema.safeParse('0b2f6c1e-8d3a-4f5b-9c7d-2e1f0a9b8c7d').success).toBe(true);
    expect(uuidV4Schema.safeParse('0b2f6c1e-8d3a-1f5b-9c7d-2e1f0a9b8c7d').success).toBe(false);
  });
});
