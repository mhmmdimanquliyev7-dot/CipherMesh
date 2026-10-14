import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig, loadWorkerConfig, resolveSecretFiles } from './env';

const CANARY_PASSWORD = 'canary-db-password-123';
const LOCAL_DB = `postgresql://cm_api:${CANARY_PASSWORD}@127.0.0.1:55432/ciphermesh`;
const REMOTE_DB = `postgresql://cm_api:${CANARY_PASSWORD}@db.ciphermesh.example:5432/ciphermesh`;
const KEYS = {
  TOTP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
  TOTP_ENCRYPTION_KEY_ID: 'test-1',
  IDENTIFIER_HMAC_KEY: randomBytes(32).toString('base64url'),
};
const valid = { NODE_ENV: 'development', APP_ORIGIN: 'https://localhost:8443', DATABASE_URL: LOCAL_DB, ...KEYS };
const CANARY_STORAGE_SECRET = 'canary-storage-secret-0123456789';
const STORAGE = {
  STORAGE_ENDPOINT: 'https://storage.example.org',
  STORAGE_BUCKET: 'cm-files',
  STORAGE_ACCESS_KEY_ID: 'runtime-key-1',
  STORAGE_SECRET_ACCESS_KEY: CANARY_STORAGE_SECRET,
};
const production = {
  NODE_ENV: 'production',
  APP_ORIGIN: 'https://example.org',
  DATABASE_URL: `${REMOTE_DB}?sslmode=verify-full`,
  ...KEYS,
  ...STORAGE,
};

function problemsOf(env: Record<string, string | undefined>): string[] {
  try {
    loadConfig(env);
  } catch (error) {
    if (error instanceof ConfigError) return error.problems.map((p) => p.variable);
    throw error;
  }
  return [];
}

describe('loadConfig', () => {
  it('applies safe defaults: loopback host, fixed body limit', () => {
    const config = loadConfig(valid);
    expect(config).toMatchObject({
      nodeEnv: 'development',
      isProduction: false,
      logLevel: 'info',
      bodyLimitBytes: 131072,
    });
    expect(config.api).toEqual({ host: '127.0.0.1', port: 4100 });
    expect(Object.isFrozen(config)).toBe(true);
  });

  it('refuses to start without NODE_ENV or APP_ORIGIN', () => {
    expect(problemsOf({})).toEqual(
      expect.arrayContaining(['NODE_ENV', 'APP_ORIGIN', 'DATABASE_URL', 'TOTP_ENCRYPTION_KEY', 'IDENTIFIER_HMAC_KEY']),
    );
  });

  it.each([
    ['a port out of range', { API_PORT: '70000' }, 'API_PORT'],
    ['a non-numeric port', { API_PORT: 'eighty' }, 'API_PORT'],
    ['an unknown log level', { LOG_LEVEL: 'verbose' }, 'LOG_LEVEL'],
    ['an unknown environment', { NODE_ENV: 'staging' }, 'NODE_ENV'],
    ['an origin with a path', { APP_ORIGIN: 'https://example.org/app' }, 'APP_ORIGIN'],
    ['an origin with another scheme', { APP_ORIGIN: 'ftp://example.org' }, 'APP_ORIGIN'],
  ])('rejects %s', (_label, override, variable) => {
    expect(problemsOf({ ...valid, ...override })).toContain(variable);
  });

  it('requires an https origin in production', () => {
    expect(problemsOf({ ...production, APP_ORIGIN: 'http://example.org' })).toEqual(['APP_ORIGIN']);
    expect(loadConfig(production).isProduction).toBe(true);
  });

  describe('authentication keys (CP-11, CP-12)', () => {
    it.each([
      ['a missing TOTP key', { TOTP_ENCRYPTION_KEY: undefined }, 'TOTP_ENCRYPTION_KEY'],
      ['a short TOTP key', { TOTP_ENCRYPTION_KEY: randomBytes(16).toString('base64url') }, 'TOTP_ENCRYPTION_KEY'],
      [
        'a placeholder TOTP key',
        { TOTP_ENCRYPTION_KEY: 'replace-with-32-random-bytes-base64url-encode' },
        'TOTP_ENCRYPTION_KEY',
      ],
      [
        'a hex instead of base64url key',
        { IDENTIFIER_HMAC_KEY: randomBytes(32).toString('hex') },
        'IDENTIFIER_HMAC_KEY',
      ],
      ['a missing key ID', { TOTP_ENCRYPTION_KEY_ID: undefined }, 'TOTP_ENCRYPTION_KEY_ID'],
      ['a key ID with spaces', { TOTP_ENCRYPTION_KEY_ID: 'key one' }, 'TOTP_ENCRYPTION_KEY_ID'],
      ['the same key for both purposes', { IDENTIFIER_HMAC_KEY: KEYS.TOTP_ENCRYPTION_KEY }, 'IDENTIFIER_HMAC_KEY'],
      ['an unsupported proxy hop count', { TRUST_PROXY_HOPS: '2' }, 'TRUST_PROXY_HOPS'],
    ])('rejects %s', (_label, override, variable) => {
      expect(problemsOf({ ...valid, ...override })).toContain(variable);
    });

    it('never prints the keys through the configuration object or its error', () => {
      const config = loadConfig(valid);
      const rendering = `${JSON.stringify(config)} ${inspect(config, { depth: 10 })}`;
      expect(rendering).not.toContain(KEYS.TOTP_ENCRYPTION_KEY);
      expect(rendering).not.toContain(KEYS.IDENTIFIER_HMAC_KEY);
      try {
        loadConfig({ ...valid, IDENTIFIER_HMAC_KEY: KEYS.TOTP_ENCRYPTION_KEY });
        expect.unreachable();
      } catch (error) {
        expect(String(error)).not.toContain(KEYS.TOTP_ENCRYPTION_KEY);
      }
    });

    it('trusts no proxy unless configured', () => {
      expect(loadConfig(valid).trustProxyHops).toBe(0);
      expect(loadConfig({ ...valid, TRUST_PROXY_HOPS: '1' }).trustProxyHops).toBe(1);
    });
  });

  describe('DATABASE_URL (TB-05, CP-21)', () => {
    it.each([
      ['production without TLS verification', { ...production, DATABASE_URL: REMOTE_DB }],
      ['production with sslmode=require only', { ...production, DATABASE_URL: `${REMOTE_DB}?sslmode=require` }],
      ['production with sslmode=verify-ca', { ...production, DATABASE_URL: `${REMOTE_DB}?sslmode=verify-ca` }],
      ['production to loopback without TLS', { ...production, DATABASE_URL: LOCAL_DB }],
      ['a remote host without TLS in development', { ...valid, DATABASE_URL: REMOTE_DB }],
      ['sslmode=disable to a remote host', { ...valid, DATABASE_URL: `${REMOTE_DB}?sslmode=disable` }],
      ['the migration role', { ...valid, DATABASE_URL: LOCAL_DB.replace('cm_api', 'cm_migrator') }],
      ['an administrator account', { ...valid, DATABASE_URL: LOCAL_DB.replace('cm_api', 'postgres') }],
      ['a missing password', { ...valid, DATABASE_URL: 'postgresql://cm_api@127.0.0.1:55432/ciphermesh' }],
      ['a missing database name', { ...valid, DATABASE_URL: `postgresql://cm_api:${CANARY_PASSWORD}@127.0.0.1:55432` }],
      ['another scheme', { ...valid, DATABASE_URL: LOCAL_DB.replace('postgresql:', 'mysql:') }],
      ['a value that is not a URL', { ...valid, DATABASE_URL: CANARY_PASSWORD }],
    ])('rejects %s', (_label, env) => {
      expect(problemsOf(env)).toEqual(['DATABASE_URL']);
    });

    it('accepts verify-full anywhere and plain connections to loopback outside production', () => {
      expect(problemsOf(valid)).toEqual([]);
      expect(problemsOf({ ...valid, DATABASE_URL: `${REMOTE_DB}?sslmode=verify-full` })).toEqual([]);
      expect(problemsOf(production)).toEqual([]);
    });

    it('never prints the connection string through the configuration object', () => {
      const config = loadConfig(valid);
      expect(config.database.url.reveal()).toBe(LOCAL_DB);
      for (const rendering of [JSON.stringify(config), inspect(config, { depth: 10 }), String(config.database.url)]) {
        expect(rendering).not.toContain(CANARY_PASSWORD);
        expect(rendering).toContain('[REDACTED]');
      }
    });

    it('never echoes the connection string in its error', () => {
      try {
        loadConfig({ ...production, DATABASE_URL: REMOTE_DB });
        expect.unreachable();
      } catch (error) {
        expect(String(error)).toContain('DATABASE_URL');
        expect(String(error)).not.toContain(CANARY_PASSWORD);
        expect(String(error)).not.toContain('db.ciphermesh.example');
      }
    });
  });

  describe('object storage (Phase 7, CM-T037)', () => {
    const LOCAL_STORAGE = { ...STORAGE, STORAGE_ENDPOINT: 'http://127.0.0.1:8333' };

    it('is optional outside production and absent unless configured', () => {
      expect(loadConfig(valid).storage).toBeNull();
      const storage = loadConfig({ ...valid, ...LOCAL_STORAGE }).storage;
      expect(storage).toMatchObject({
        endpoint: 'http://127.0.0.1:8333',
        publicEndpoint: 'http://127.0.0.1:8333',
        region: 'us-east-1',
        bucket: 'cm-files',
        accessKeyId: 'runtime-key-1',
      });
      expect(storage?.secretAccessKey.reveal()).toBe(CANARY_STORAGE_SECRET);
      expect(inspect(storage)).not.toContain(CANARY_STORAGE_SECRET);
      expect(JSON.stringify(storage)).not.toContain(CANARY_STORAGE_SECRET);
    });

    it('keeps a separate public endpoint for presigned URLs', () => {
      const storage = loadConfig({
        ...valid,
        ...LOCAL_STORAGE,
        STORAGE_PUBLIC_ENDPOINT: 'https://127.0.0.1:4174',
      }).storage;
      expect(storage?.publicEndpoint).toBe('https://127.0.0.1:4174');
    });

    it('is required in production, all or nothing everywhere', () => {
      const { STORAGE_ENDPOINT: _e, STORAGE_SECRET_ACCESS_KEY: _s, ...partial } = STORAGE;
      expect(problemsOf({ ...production, ...Object.fromEntries(Object.keys(STORAGE).map((k) => [k, ''])) })).toEqual(
        Object.keys(STORAGE),
      );
      expect(problemsOf({ ...valid, ...partial })).toEqual(['STORAGE_ENDPOINT', 'STORAGE_SECRET_ACCESS_KEY']);
      expect(problemsOf({ ...valid, STORAGE_PUBLIC_ENDPOINT: 'https://127.0.0.1:4174' })).toEqual(Object.keys(STORAGE));
      expect(loadConfig(production).storage?.endpoint).toBe('https://storage.example.org');
    });

    it.each([
      ['production over http', { ...production, STORAGE_ENDPOINT: 'http://storage.example.org' }, 'STORAGE_ENDPOINT'],
      [
        'production presigning http URLs',
        { ...production, STORAGE_PUBLIC_ENDPOINT: 'http://storage.example.org' },
        'STORAGE_PUBLIC_ENDPOINT',
      ],
      [
        'production over http to loopback',
        { ...production, STORAGE_ENDPOINT: 'http://127.0.0.1:8333' },
        'STORAGE_ENDPOINT',
      ],
      [
        'development over http to a remote host',
        { ...valid, ...STORAGE, STORAGE_ENDPOINT: 'http://storage.example.org' },
        'STORAGE_ENDPOINT',
      ],
      [
        'an endpoint with a path',
        { ...valid, ...LOCAL_STORAGE, STORAGE_ENDPOINT: 'http://127.0.0.1:8333/bucket' },
        'STORAGE_ENDPOINT',
      ],
      [
        'an endpoint with credentials',
        { ...valid, ...LOCAL_STORAGE, STORAGE_ENDPOINT: 'http://a:b@127.0.0.1:8333' },
        'STORAGE_ENDPOINT',
      ],
      [
        'a bucket name with a path',
        { ...valid, ...LOCAL_STORAGE, STORAGE_BUCKET: 'cm-files/../other' },
        'STORAGE_BUCKET',
      ],
      [
        'a short secret',
        { ...valid, ...LOCAL_STORAGE, STORAGE_SECRET_ACCESS_KEY: 'short' },
        'STORAGE_SECRET_ACCESS_KEY',
      ],
    ])('rejects %s', (_label, env, variable) => {
      expect(problemsOf(env)).toContain(variable);
    });

    it('refuses presigned URLs on the application host, whatever the port (SF-07-01)', () => {
      const app = { ...valid, APP_ORIGIN: 'https://127.0.0.1:4173', ...LOCAL_STORAGE };
      expect(problemsOf({ ...app, STORAGE_PUBLIC_ENDPOINT: 'https://127.0.0.1:4174' })).toEqual([
        'STORAGE_PUBLIC_ENDPOINT',
      ]);
      expect(problemsOf({ ...app, STORAGE_ENDPOINT: 'http://127.0.0.1:8333' })).toEqual(['STORAGE_ENDPOINT']);
      expect(problemsOf({ ...app, STORAGE_PUBLIC_ENDPOINT: 'https://localhost:4174' })).toEqual([]);
      expect(problemsOf({ ...production, STORAGE_ENDPOINT: 'https://example.org:9000' })).toEqual(['STORAGE_ENDPOINT']);
    });

    it('never echoes the storage secret in its error', () => {
      try {
        loadConfig({ ...production, STORAGE_ENDPOINT: 'http://storage.example.org' });
        expect.unreachable();
      } catch (error) {
        expect(String(error)).toContain('STORAGE_ENDPOINT');
        expect(String(error)).not.toContain(CANARY_STORAGE_SECRET);
      }
    });

    it('applies the same rules to the worker', () => {
      const worker = { NODE_ENV: 'development', WORKER_DATABASE_URL: LOCAL_DB.replace('cm_api', 'cm_worker') };
      expect(loadWorkerConfig(worker).storage).toBeNull();
      expect(loadWorkerConfig({ ...worker, ...LOCAL_STORAGE }).storage?.bucket).toBe('cm-files');
      expect(() => loadWorkerConfig({ ...worker, NODE_ENV: 'production' })).toThrow(ConfigError);
      expect(() => loadWorkerConfig({ ...worker, STORAGE_BUCKET: 'cm-files' })).toThrow(/STORAGE_ENDPOINT/);
    });
  });

  describe('platform status file (ADR-014)', () => {
    it('is absent unless configured, and accepts an absolute path to a JSON file', () => {
      expect(loadConfig(valid).platformStatusFile).toBeNull();
      expect(
        loadConfig({ ...production, PLATFORM_STATUS_FILE: '/run/ciphermesh/status/host-status.json' })
          .platformStatusFile,
      ).toBe('/run/ciphermesh/status/host-status.json');
    });

    it('refuses relative paths, parent references and other file types', () => {
      for (const value of ['status.json', '/run/../etc/passwd.json', '/etc/shadow', '/run/a b.json', 'C:/x.json']) {
        expect(problemsOf({ ...valid, PLATFORM_STATUS_FILE: value }), value).toEqual(['PLATFORM_STATUS_FILE']);
      }
    });
  });

  it('treats empty values as missing', () => {
    expect(loadConfig({ ...valid, API_PORT: '' }).api.port).toBe(4100);
  });

  it('never echoes configuration values in its error', () => {
    try {
      loadConfig({ ...valid, API_PORT: 'canary-secret-value' });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      expect(String(error)).toContain('API_PORT');
      expect(String(error)).not.toContain('canary-secret-value');
    }
  });
});

describe('secrets from files (ADR-014, CM-T071)', () => {
  const files: Record<string, string> = {
    '/run/secrets/database_url': `${LOCAL_DB}\n`,
    '/run/secrets/totp': `${KEYS.TOTP_ENCRYPTION_KEY}\n`,
    '/run/secrets/two-lines': 'a\nb\n',
    '/run/secrets/empty': '\n',
  };
  const read = (path: string): string => {
    const content = files[path];
    if (content === undefined) throw new Error(`ENOENT: ${path}`);
    return content;
  };
  const problemsFor = (env: Record<string, string>): string[] => {
    try {
      resolveSecretFiles(env, read);
    } catch (error) {
      if (error instanceof ConfigError) return error.problems.map((p) => `${p.variable}: ${p.problem}`);
      throw error;
    }
    return [];
  };

  it('reads <NAME>_FILE into <NAME>, without the trailing newline, and removes the _FILE variable', () => {
    const env = resolveSecretFiles(
      {
        NODE_ENV: 'development',
        DATABASE_URL_FILE: '/run/secrets/database_url',
        TOTP_ENCRYPTION_KEY_FILE: '/run/secrets/totp',
      },
      read,
    );
    expect(env['DATABASE_URL']).toBe(LOCAL_DB);
    expect(env['TOTP_ENCRYPTION_KEY']).toBe(KEYS.TOTP_ENCRYPTION_KEY);
    expect(env['DATABASE_URL_FILE']).toBeUndefined();
    const { DATABASE_URL: _url, TOTP_ENCRYPTION_KEY: _totp, ...rest } = valid;
    expect(loadConfig({ ...rest, ...env }).database.url.reveal()).toBe(LOCAL_DB);
  });

  it('refuses both forms, relative paths, unreadable, empty and multi-line files', () => {
    expect(problemsFor({ DATABASE_URL: LOCAL_DB, DATABASE_URL_FILE: '/run/secrets/database_url' })).toEqual([
      'DATABASE_URL_FILE: set either DATABASE_URL or DATABASE_URL_FILE, not both',
    ]);
    expect(problemsFor({ DATABASE_URL_FILE: 'run/secrets/database_url' })).toEqual([
      'DATABASE_URL_FILE: must be an absolute path',
    ]);
    expect(problemsFor({ DATABASE_URL_FILE: '/run/secrets/../etc/shadow' })).toEqual([
      'DATABASE_URL_FILE: must be an absolute path',
    ]);
    expect(problemsFor({ IDENTIFIER_HMAC_KEY_FILE: '/run/secrets/missing' })).toEqual([
      'IDENTIFIER_HMAC_KEY_FILE: could not be read',
    ]);
    expect(problemsFor({ STORAGE_SECRET_ACCESS_KEY_FILE: '/run/secrets/empty' })).toEqual([
      'STORAGE_SECRET_ACCESS_KEY_FILE: must contain one non-empty line',
    ]);
    expect(problemsFor({ WORKER_DATABASE_URL_FILE: '/run/secrets/two-lines' })).toEqual([
      'WORKER_DATABASE_URL_FILE: must contain one non-empty line',
    ]);
  });

  it('never echoes a secret file content or path content in its error', () => {
    try {
      resolveSecretFiles({ DATABASE_URL: 'x', DATABASE_URL_FILE: '/run/secrets/database_url' }, read);
    } catch (error) {
      expect(String(error)).not.toContain(CANARY_PASSWORD);
    }
    expect(() => resolveSecretFiles({ OTHER_FILE: '/etc/passwd' }, read)).not.toThrow();
  });
});
