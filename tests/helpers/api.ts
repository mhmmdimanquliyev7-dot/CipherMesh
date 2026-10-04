import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp, type AppDependencies } from '../../apps/api/src/app';
import { loadConfig } from '../../apps/api/src/config/env';
import { createLifecycle, type Lifecycle } from '../../apps/api/src/lifecycle';
import { createLogger } from '../../apps/api/src/logging/logger';

export const TEST_ORIGIN = 'https://ciphermesh.test';

export interface TestApi {
  readonly baseUrl: string;
  readonly lifecycle: Lifecycle;
  /** Every log line the API wrote, as raw text. */
  readonly logText: () => string;
  readonly close: () => Promise<void>;
}

export interface TestApiOptions {
  readonly env?: Readonly<Record<string, string>>;
  readonly testing?: AppDependencies['testing'];
  readonly ready?: boolean;
  /**
   * Readiness of the database dependency for HTTP-level tests that run without PostgreSQL.
   * Only the readiness probe uses it; tests/database exercises the real database client.
   */
  readonly databaseReachable?: boolean;
}

/** A syntactically valid API-role URL for tests that never connect. Not a credential. */
export const UNUSED_DATABASE_URL = 'postgresql://cm_api:unused-test-value@127.0.0.1:1/unused';

/** Boots the real application on an ephemeral loopback port with a captured log. */
export async function startTestApi(options: TestApiOptions = {}): Promise<TestApi> {
  const config = loadConfig({
    NODE_ENV: 'test',
    APP_ORIGIN: TEST_ORIGIN,
    LOG_LEVEL: 'debug',
    DATABASE_URL: UNUSED_DATABASE_URL,
    ...options.env,
  });
  const lines: string[] = [];
  const logger = createLogger({ level: config.logLevel, sink: { write: (line) => lines.push(line) } });
  const lifecycle = createLifecycle();
  const database = { ping: () => Promise.resolve(options.databaseReachable ?? true) };
  const { app } = createApp({
    config,
    logger,
    lifecycle,
    database,
    ...(options.testing ? { testing: options.testing } : {}),
  });
  const server: Server = createServer(app);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  if (options.ready !== false) lifecycle.markReady();
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    lifecycle,
    logText: () => lines.join(''),
    close: () =>
      new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      }),
  };
}

/** Headers a same-origin browser request would carry (INV-19). */
export const SAME_ORIGIN_HEADERS: Readonly<Record<string, string>> = {
  origin: TEST_ORIGIN,
  'sec-fetch-site': 'same-origin',
  'x-ciphermesh-request': '1',
};
