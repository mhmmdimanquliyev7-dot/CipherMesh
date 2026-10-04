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
}

/** Boots the real application on an ephemeral loopback port with a captured log. */
export async function startTestApi(options: TestApiOptions = {}): Promise<TestApi> {
  const config = loadConfig({ NODE_ENV: 'test', APP_ORIGIN: TEST_ORIGIN, LOG_LEVEL: 'debug', ...options.env });
  const lines: string[] = [];
  const logger = createLogger({ level: config.logLevel, sink: { write: (line) => lines.push(line) } });
  const lifecycle = createLifecycle();
  const { app } = createApp({ config, logger, lifecycle, ...(options.testing ? { testing: options.testing } : {}) });
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
