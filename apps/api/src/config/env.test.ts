import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from './env';

const CANARY_PASSWORD = 'canary-db-password-123';
const LOCAL_DB = `postgresql://cm_api:${CANARY_PASSWORD}@127.0.0.1:55432/ciphermesh`;
const REMOTE_DB = `postgresql://cm_api:${CANARY_PASSWORD}@db.ciphermesh.example:5432/ciphermesh`;
const valid = { NODE_ENV: 'development', APP_ORIGIN: 'https://localhost:8443', DATABASE_URL: LOCAL_DB };
const production = {
  NODE_ENV: 'production',
  APP_ORIGIN: 'https://example.org',
  DATABASE_URL: `${REMOTE_DB}?sslmode=verify-full`,
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
    expect(problemsOf({})).toEqual(expect.arrayContaining(['NODE_ENV', 'APP_ORIGIN', 'DATABASE_URL']));
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
