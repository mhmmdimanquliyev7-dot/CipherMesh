import { describe, expect, it } from 'vitest';
import { REDACTED, createRedactor, redact } from './redact';

// Every field name required by the Phase 1 brief, plus spelling variants.
const SENSITIVE_FIELDS = [
  'password',
  'passphrase',
  'vaultPassphrase',
  'authorization',
  'cookie',
  'set-cookie',
  'session',
  'sessionToken',
  'accessToken',
  'refreshToken',
  'privateKey',
  'roomKey',
  'fileEncryptionKey',
  'FEK',
  'secret',
  'totpSecret',
  'recoveryCode',
  'presignedUrl',
  'session_token',
  'Session-Token',
  'clientSecret',
  'adminPassword',
  'x-api-key',
  'safetyCode',
  'databaseUrl',
  'DATABASE_URL',
  'MIGRATION_DATABASE_URL',
  'connectionString',
];

describe('redact', () => {
  it.each(SENSITIVE_FIELDS)('redacts the field "%s"', (field) => {
    expect(redact({ [field]: 'canary-value-123' })).toEqual({ [field]: REDACTED });
  });

  it('redacts at any depth and inside arrays', () => {
    const input = { a: { b: [{ c: { password: 'canary-1' } }, { roomKey: 'canary-2' }] } };
    const output = JSON.stringify(redact(input));
    expect(output).not.toContain('canary-1');
    expect(output).not.toContain('canary-2');
  });

  it('redacts whole sensitive objects, not only strings', () => {
    expect(redact({ credentials: { user: 'u', pass: 'canary' } })).toEqual({ credentials: REDACTED });
  });

  it('redacts sensitive values under harmless keys', () => {
    const presigned = 'https://storage.example/o/abc?X-Amz-Credential=AKIA%2F&X-Amz-Signature=deadbeef';
    expect(redact({ url: presigned })).toEqual({ url: REDACTED });
    expect(redact({ header: 'Bearer abc.def.ghi' })).toEqual({ header: REDACTED });
    expect(redact({ note: '-----BEGIN PRIVATE KEY-----\nMIIB...' })).toEqual({ note: REDACTED });
  });

  it('never logs raw bytes, which may be key material', () => {
    expect(redact({ material: new Uint8Array([1, 2, 3]) })).toEqual({ material: '[Binary]' });
    expect(redact({ material: new ArrayBuffer(4) })).toEqual({ material: '[Binary]' });
  });

  it('keeps harmless fields unchanged', () => {
    const input = { requestId: 'r-1', method: 'GET', status: 200, tokenCount: 3 };
    expect(redact(input)).toEqual({ ...input, tokenCount: 3 });
  });

  it('handles circular structures and deep nesting without throwing', () => {
    const loop: Record<string, unknown> = { name: 'loop' };
    loop['self'] = loop;
    expect(redact(loop)).toEqual({ name: 'loop', self: '[Circular]' });
    let deep: Record<string, unknown> = { password: 'canary-deep' };
    for (let i = 0; i < 20; i += 1) deep = { next: deep };
    expect(JSON.stringify(redact(deep))).not.toContain('canary-deep');
  });

  it('serialises errors and redacts sensitive values in their messages', () => {
    const error = new Error('failed with Bearer abc.def');
    const output = redact({ err: error }) as { err: { name: string; message: string } };
    expect(output.err.name).toBe('Error');
    expect(output.err.message).toBe(REDACTED);
  });

  it('supports additional sensitive fields', () => {
    const custom = createRedactor(['envelope']);
    expect(custom({ envelope: 'abc', other: 'ok' })).toEqual({ envelope: REDACTED, other: 'ok' });
  });
});
