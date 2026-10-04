import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from './env';

const valid = { NODE_ENV: 'development', APP_ORIGIN: 'https://localhost:8443' };

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
    expect(problemsOf({})).toEqual(expect.arrayContaining(['NODE_ENV', 'APP_ORIGIN']));
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
    expect(problemsOf({ NODE_ENV: 'production', APP_ORIGIN: 'http://example.org' })).toEqual(['APP_ORIGIN']);
    expect(loadConfig({ NODE_ENV: 'production', APP_ORIGIN: 'https://example.org' }).isProduction).toBe(true);
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
