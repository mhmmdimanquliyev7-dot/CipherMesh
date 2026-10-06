import { API_PREFIX } from '@ciphermesh/shared';
import express, { type Express } from 'express';
import { availableParallelism } from 'node:os';
import { createAdminService, type AdminService } from './auth/admin';
import { createIdentifierHasher } from './auth/identifier';
import { ConcurrencyLimiter } from './auth/limits';
import { createPasswordHasher } from './auth/password';
import { logSecurityEventSink, type SecurityEventSink } from './auth/security-events';
import { createAuthService, defaultRateLimits, type AuthRateLimits, type AuthService } from './auth/service';
import { resolveSession } from './auth/sessions';
import { TotpSecretBox } from './auth/totp-secret-box';
import { createRoomAuthorizer } from './authorization/rooms';
import type { AppConfig } from './config/env';
import { authDataAccess } from './db/auth-store';
import { createRoomAccessStore } from './db/room-access-store';
import { accountDataAccess, roomDataAccess } from './db/room-store';
import { vaultDataAccess } from './db/vault-store';
import type { Database } from './db/client';
import { requireJsonBody } from './http/content-type';
import { errorHandler, notFound } from './http/errors';
import { requestId } from './http/request-id';
import { requestLog } from './http/request-log';
import { sameOriginGate } from './http/same-origin';
import { securityHeaders } from './http/security-headers';
import type { Lifecycle } from './lifecycle';
import type { Logger } from './logging/logger';
import { AUTH_PUBLIC_ROUTES, authRoutes } from './routes/auth';
import {
  buildRouter,
  type AnyRoute,
  type Authenticator,
  type PublicRouteEntry,
  type RegisteredRoute,
} from './routes/registry';
import { createReadinessProbe, PUBLIC_ROUTE_ALLOWLIST, systemRoutes } from './routes/system';
import { roomRoutes } from './routes/rooms';
import { vaultRoutes } from './routes/vault';
import { createRoomService } from './rooms/service';
import { createVaultService, defaultVaultRateLimits, type VaultRateLimits, type VaultService } from './vault/service';

export interface AppDependencies {
  readonly config: AppConfig;
  readonly logger: Logger;
  readonly lifecycle: Lifecycle;
  readonly database: Database;
  /**
   * Test seams: extra routes and allowlist entries, a controllable clock, rate limits, and a
   * security-event sink. Refused in production, so a deployment can never widen the public
   * surface or change time through this seam.
   */
  readonly testing?: {
    readonly routes?: readonly AnyRoute[];
    readonly publicAllowlist?: readonly PublicRouteEntry[];
    readonly clock?: () => Date;
    readonly rateLimits?: AuthRateLimits;
    readonly vaultRateLimits?: VaultRateLimits;
    readonly events?: SecurityEventSink;
  };
}

export interface CipherMeshApp {
  readonly app: Express;
  readonly routes: readonly RegisteredRoute[];
  readonly auth: AuthService;
  readonly admin: AdminService;
  readonly vault: VaultService;
}

/** Argon2id computations allowed at once: one per CPU, at most four (CP-05 benchmark). */
const ARGON2_CONCURRENCY = Math.max(1, Math.min(4, availableParallelism()));
const ARGON2_QUEUE = 32;

export function createApp(deps: AppDependencies): CipherMeshApp {
  const { config, logger, lifecycle, database, testing } = deps;
  if (testing !== undefined && config.isProduction) {
    throw new Error('Test seams cannot be used in production');
  }
  const clock = testing?.clock ?? ((): Date => new Date());
  const events = testing?.events ?? logSecurityEventSink(logger);
  const data = authDataAccess(database.prisma);

  const auth = createAuthService({
    store: data.store,
    transaction: data.transaction,
    hasher: createPasswordHasher(new ConcurrencyLimiter(ARGON2_CONCURRENCY, ARGON2_QUEUE)),
    totpBox: new TotpSecretBox(config.auth.totpEncryptionKey.reveal(), config.auth.totpEncryptionKeyId),
    identifierHmac: createIdentifierHasher(config.auth.identifierHmacKey.reveal()),
    events,
    clock,
    limits: testing?.rateLimits ?? defaultRateLimits(() => clock().getTime()),
  });
  // Disabling an account also suspends its room memberships in the same transaction (PA-03).
  const admin = createAdminService({ transaction: accountDataAccess(database.prisma).transaction, events, clock });
  const vaultData = vaultDataAccess(database.prisma);
  const vault = createVaultService({
    store: vaultData.store,
    transaction: vaultData.transaction,
    events,
    clock,
    limits: testing?.vaultRateLimits ?? defaultVaultRateLimits(() => clock().getTime()),
  });
  const authenticator: Authenticator = {
    authenticate: (token) => resolveSession(data.store, token, clock()),
    now: clock,
  };
  // Central room authorization (CM-T029): every room route is checked against the membership
  // stored for the session user and the shared matrix before its handler runs.
  const roomAccess = createRoomAccessStore(database.prisma);
  const rooms = createRoomAuthorizer({ store: roomAccess, events });
  const roomData = roomDataAccess(database.prisma);
  const roomService = createRoomService({ store: roomData.store, transaction: roomData.transaction, events, clock });

  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  app.set('query parser', 'simple');
  // The client address feeds rate limiting and the session list. Forwarded headers are trusted
  // only from the configured number of proxy hops: none locally, the single Nginx hop in
  // production (TB-04). Anything else would let clients choose their own address.
  app.set('trust proxy', config.trustProxyHops === 1 ? 1 : false);

  app.use(requestId);
  app.use(securityHeaders);
  app.use(requestLog(logger));
  app.use(sameOriginGate(config.appOrigin));
  app.use(requireJsonBody);
  // No client sends compressed bodies, so decompression (and decompression bombs) is refused.
  app.use(express.json({ limit: config.bodyLimitBytes, strict: true, type: 'application/json', inflate: false }));

  const { router, registered } = buildRouter(
    [
      ...systemRoutes(lifecycle, createReadinessProbe(database)),
      ...authRoutes(auth, admin),
      ...vaultRoutes(vault),
      ...roomRoutes(roomService, roomAccess),
      ...(testing?.routes ?? []),
    ],
    [...PUBLIC_ROUTE_ALLOWLIST, ...AUTH_PUBLIC_ROUTES, ...(testing?.publicAllowlist ?? [])],
    authenticator,
    rooms,
  );
  app.use(API_PREFIX, router);

  app.use(notFound);
  app.use(errorHandler(logger));
  return { app, routes: registered, auth, admin, vault };
}
