import { API_PREFIX } from '@ciphermesh/shared';
import express, { type Express } from 'express';
import type { AppConfig } from './config/env';
import type { DatabaseHealth } from './db/client';
import { requireJsonBody } from './http/content-type';
import { errorHandler, notFound } from './http/errors';
import { requestId } from './http/request-id';
import { requestLog } from './http/request-log';
import { sameOriginGate } from './http/same-origin';
import { securityHeaders } from './http/security-headers';
import type { Lifecycle } from './lifecycle';
import type { Logger } from './logging/logger';
import { buildRouter, type AnyRoute, type PublicRouteEntry, type RegisteredRoute } from './routes/registry';
import { PUBLIC_ROUTE_ALLOWLIST, systemRoutes } from './routes/system';

export interface AppDependencies {
  readonly config: AppConfig;
  readonly logger: Logger;
  readonly lifecycle: Lifecycle;
  /** Used by the readiness probe only. Route handlers receive data access from Phase 3 on. */
  readonly database: DatabaseHealth;
  /**
   * Extra routes and allowlist entries for tests only. Refused in production, so a
   * deployment can never widen the public surface through this seam.
   */
  readonly testing?: { readonly routes: readonly AnyRoute[]; readonly publicAllowlist: readonly PublicRouteEntry[] };
}

export interface CipherMeshApp {
  readonly app: Express;
  readonly routes: readonly RegisteredRoute[];
}

export function createApp(deps: AppDependencies): CipherMeshApp {
  const { config, logger, lifecycle, database, testing } = deps;
  if (testing !== undefined && config.isProduction) {
    throw new Error('Test routes cannot be registered in production');
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  app.set('query parser', 'simple');
  // The API sits behind exactly one proxy (Nginx) in production. Forwarded headers are not
  // trusted until Phase 3 needs client addresses for rate limiting; see engineering-baseline.md.
  app.set('trust proxy', false);

  app.use(requestId);
  app.use(securityHeaders);
  app.use(requestLog(logger));
  app.use(sameOriginGate(config.appOrigin));
  app.use(requireJsonBody);
  // No client sends compressed bodies, so decompression (and decompression bombs) is refused.
  app.use(express.json({ limit: config.bodyLimitBytes, strict: true, type: 'application/json', inflate: false }));

  const { router, registered } = buildRouter(
    [...systemRoutes(lifecycle, database), ...(testing?.routes ?? [])],
    [...PUBLIC_ROUTE_ALLOWLIST, ...(testing?.publicAllowlist ?? [])],
  );
  app.use(API_PREFIX, router);

  app.use(notFound);
  app.use(errorHandler(logger));
  return { app, routes: registered };
}
