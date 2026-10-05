/**
 * Central redaction for everything the API logs (INV-10, principle 7).
 *
 * Keys are compared after normalisation (lowercase, letters and digits only), so
 * `sessionToken`, `session_token` and `Session-Token` are treated the same.
 * To protect a new field, add its name to SENSITIVE_KEYS or a suffix to
 * SENSITIVE_KEY_SUFFIXES, and add a case to redact.test.ts.
 */
export const REDACTED = '[REDACTED]';

export const SENSITIVE_KEYS: readonly string[] = [
  'password',
  'passphrase',
  'vaultPassphrase',
  'authorization',
  'proxyAuthorization',
  'cookie',
  'setCookie',
  'session',
  'sessionId',
  'sessionToken',
  'token',
  'accessToken',
  'refreshToken',
  'idToken',
  'apiKey',
  'privateKey',
  'roomKey',
  'roomKeyMaterial',
  'rkm',
  'wrappingKey',
  'fileEncryptionKey',
  'fek',
  'nek',
  'sek',
  'dek',
  'secret',
  'totpSecret',
  'recoveryCode',
  'recoveryCodes',
  'presignedUrl',
  'safetyCode',
  'credentials',
  'databaseUrl',
  'connectionString',
  'dsn',
  // Authentication (Phase 3)
  'passwordConfirmation',
  'otp',
  'totp',
  'totpCode',
  'mfaCode',
  'otpauth',
  'otpauthUri',
  'challenge',
  'preAuth',
  // Vault (Phase 4). The server never receives these values; the names are redacted anyway, so a
  // mistake in a client or a test can never put them into a log (INV-01, INV-10).
  'vaultPassword',
  'vaultKey',
  'vaultRootKey',
  'vrk',
  'kek',
  'keyEncryptionKey',
  'pkwk',
  'privateKeyPkcs8',
  'pkcs8',
  'decryptedPrivateKey',
  'vaultPlaintext',
  'vaultCiphertext',
  'vaultBlob',
  'wrappedEncryptionKey',
  'wrappedSigningKey',
  'encryptedPrivateKey',
  'encryptedSigningPrivateKey',
];

/** Any key ending with one of these is sensitive, e.g. `clientSecret`, `adminPassword`. */
export const SENSITIVE_KEY_SUFFIXES: readonly string[] = [
  'password',
  'passphrase',
  'secret',
  'token',
  'privatekey',
  'apikey',
  'cookie',
  'databaseurl',
  'connectionstring',
  'pkcs8',
];

/** Values that are sensitive regardless of the key they appear under. */
const SENSITIVE_VALUE_PATTERNS: readonly RegExp[] = [
  /X-Amz-(Signature|Credential|Security-Token)=/i, // presigned URLs
  /\bBearer\s+\S+/i, // bearer tokens anywhere, including inside error messages
  /^\s*Basic\s+\S+/i, // basic authorization header values
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/, // PEM private keys
  // Any URL with a password in its user info, e.g. postgresql://role:password@host/db (CM-T013)
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/?#@:]*:[^\s/?#@]*@/i,
  /otpauth:\/\//i, // TOTP enrollment URIs carry the secret (Phase 3)
  /__Host-cm_(session|preauth)=[^;\s]/i, // authentication cookie values in Cookie or Set-Cookie strings
  /\b[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}\b/, // recovery codes as displayed
];

const MAX_DEPTH = 8;

const normalise = (key: string): string => key.toLowerCase().replace(/[^a-z0-9]/g, '');

export function createRedactor(extraKeys: readonly string[] = []): (value: unknown) => unknown {
  const exact = new Set([...SENSITIVE_KEYS, ...extraKeys].map(normalise));
  const isSensitiveKey = (key: string): boolean => {
    const k = normalise(key);
    return exact.has(k) || SENSITIVE_KEY_SUFFIXES.some((suffix) => k.endsWith(suffix));
  };

  const walk = (value: unknown, depth: number, seen: WeakSet<object>): unknown => {
    if (typeof value === 'string') {
      return SENSITIVE_VALUE_PATTERNS.some((pattern) => pattern.test(value)) ? REDACTED : value;
    }
    if (value === null || typeof value !== 'object') {
      return typeof value === 'bigint' ? value.toString() : value;
    }
    // Raw bytes may be key material: never log them.
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return '[Binary]';
    if (seen.has(value)) return '[Circular]';
    if (depth >= MAX_DEPTH) return '[Truncated]';
    seen.add(value);
    if (value instanceof Error) {
      return {
        name: value.name,
        message: walk(value.message, depth + 1, seen),
        stack: typeof value.stack === 'string' ? walk(value.stack, depth + 1, seen) : undefined,
      };
    }
    if (Array.isArray(value)) return value.map((item) => walk(item, depth + 1, seen));
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = isSensitiveKey(key) ? REDACTED : walk(item, depth + 1, seen);
    }
    return out;
  };

  return (value) => walk(value, 0, new WeakSet());
}

export const redact = createRedactor();
