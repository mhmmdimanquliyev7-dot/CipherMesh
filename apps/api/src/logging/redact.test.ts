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
  // Authentication fields (Phase 3)
  'passwordConfirmation',
  'oldPassword',
  'newPassword',
  'currentPassword',
  'otp',
  'totp',
  'totpCode',
  'mfaCode',
  'otpauth',
  'otpauthUri',
  'recoveryCode',
  'recoveryCodes',
  'csrfToken',
  'preAuthToken',
  'challenge',
  'set-cookie',
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

  it('redacts URLs that carry credentials, such as database connection strings (CM-T013)', () => {
    const canary = 'canary-db-password';
    for (const value of [
      `postgresql://cm_api:${canary}@db.internal:5432/ciphermesh?sslmode=verify-full`,
      `connect failed for postgres://cm_migrator:${canary}@127.0.0.1:55432/ciphermesh`,
      `redis://:${canary}@cache.example:6379`,
    ]) {
      expect(JSON.stringify(redact({ detail: value }))).not.toContain(canary);
    }
    // URLs without credentials stay readable.
    expect(redact({ link: 'https://example.org/a:b@c' })).toEqual({ link: 'https://example.org/a:b@c' });
  });

  it('redacts authentication secrets wherever they appear as values (Phase 3)', () => {
    const values = [
      'otpauth://totp/CipherMesh:user%40example.test?secret=GEZDGNBVGY3TQOJQ&issuer=CipherMesh',
      '__Host-cm_session=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDE',
      'cookie: theme=dark; __Host-cm_preauth=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDE',
      'used code 7K3M9-QXW2T-4HZ8P-N6VJR yesterday',
    ];
    for (const value of values) expect(redact({ note: value })).toEqual({ note: REDACTED });
    // Ordinary request IDs and error codes stay readable.
    expect(redact({ requestId: '0d78ba41-a490-4ccc-bc46-444556a2aa73', code: 'INVALID_CODE' })).toEqual({
      requestId: '0d78ba41-a490-4ccc-bc46-444556a2aa73',
      code: 'INVALID_CODE',
    });
  });

  it('redacts nested authentication bodies and error objects carrying them', () => {
    const error = Object.assign(new Error('login failed'), {
      body: { email: 'x@example.test', password: 'canary-pw', totp: '654321' },
    });
    const output = JSON.stringify(redact({ err: error, request: { body: { newPassword: 'canary-new' } } }));
    expect(output).not.toContain('canary-pw');
    expect(output).not.toContain('canary-new');
    expect(output).not.toContain('654321');
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
