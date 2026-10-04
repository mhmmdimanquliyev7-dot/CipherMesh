import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp, type AppDependencies, type CipherMeshApp } from '../../apps/api/src/app';
import { loadConfig } from '../../apps/api/src/config/env';
import { createDatabase } from '../../apps/api/src/db/client';
import { createLifecycle, type Lifecycle } from '../../apps/api/src/lifecycle';
import { createLogger } from '../../apps/api/src/logging/logger';

export const TEST_ORIGIN = 'https://ciphermesh.test';

/** A syntactically valid API-role URL for tests that never connect. Not a credential. */
export const UNUSED_DATABASE_URL = 'postgresql://cm_api:unused-test-value@127.0.0.1:1/unused';

/**
 * Authentication keys for tests: random per test process, never committed, never reused.
 * Exported so database tests can open TOTP secrets the API sealed.
 */
export const TEST_AUTH_KEYS = Object.freeze({
  TOTP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
  TOTP_ENCRYPTION_KEY_ID: 'test-key-1',
  IDENTIFIER_HMAC_KEY: randomBytes(32).toString('base64url'),
});

export interface TestApi {
  readonly baseUrl: string;
  readonly lifecycle: Lifecycle;
  readonly app: CipherMeshApp;
  /** Every log line the API wrote, as raw text. */
  readonly logText: () => string;
  readonly close: () => Promise<void>;
}

export interface TestApiOptions {
  readonly env?: Readonly<Record<string, string>>;
  readonly testing?: AppDependencies['testing'];
  readonly ready?: boolean;
  /**
   * A real database URL (as cm_api) for authentication tests. Without it the API is built on a
   * database that is never connected, for HTTP-level tests that do not touch accounts.
   */
  readonly databaseUrl?: string;
  /** Readiness of the never-connected database, for HTTP-level readiness tests. */
  readonly databaseReachable?: boolean;
}

/** Boots the real application on an ephemeral loopback port with a captured log. */
export async function startTestApi(options: TestApiOptions = {}): Promise<TestApi> {
  const config = loadConfig({
    NODE_ENV: 'test',
    APP_ORIGIN: TEST_ORIGIN,
    LOG_LEVEL: 'debug',
    DATABASE_URL: options.databaseUrl ?? UNUSED_DATABASE_URL,
    ...TEST_AUTH_KEYS,
    // Tests give every scenario its own client address through X-Forwarded-For, which is how
    // the API sees addresses behind the single Nginx hop in production.
    TRUST_PROXY_HOPS: '1',
    ...options.env,
  });
  const lines: string[] = [];
  const logger = createLogger({ level: config.logLevel, sink: { write: (line) => lines.push(line) } });
  const lifecycle = createLifecycle();
  const real = createDatabase({ url: config.database.url, logger, poolMax: 5 });
  const database =
    options.databaseUrl === undefined
      ? { ...real, ping: () => Promise.resolve(options.databaseReachable ?? true) }
      : real;
  const app = createApp({
    config,
    logger,
    lifecycle,
    database,
    ...(options.testing ? { testing: options.testing } : {}),
  });
  const server: Server = createServer(app.app);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  if (options.ready !== false) lifecycle.markReady();
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${String(port)}`,
    lifecycle,
    app,
    logText: () => lines.join(''),
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
      await real.close();
    },
  };
}

/** Headers a same-origin browser request would carry (INV-19). */
export const SAME_ORIGIN_HEADERS: Readonly<Record<string, string>> = {
  origin: TEST_ORIGIN,
  'sec-fetch-site': 'same-origin',
  'x-ciphermesh-request': '1',
};
