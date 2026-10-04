import { emptyQuerySchema, healthResponseSchema, readinessResponseSchema } from '@ciphermesh/validation';
import type { DatabaseHealth } from '../db/client';
import type { Lifecycle } from '../lifecycle';
import { defineRoute, type AnyRoute, type PublicRouteEntry } from './registry';

/**
 * The complete list of routes reachable without authentication. Adding an entry needs a
 * security review (authorization model, principle 1 deny by default). Phase 3 adds
 * registration, login and MFA verification here.
 */
export const PUBLIC_ROUTE_ALLOWLIST: readonly PublicRouteEntry[] = Object.freeze([
  { method: 'GET', path: '/health' },
  { method: 'GET', path: '/ready' },
]);

/**
 * Liveness and readiness. They reveal a status word only: no versions, hostnames,
 * dependency details, uptime or configuration.
 */
export function systemRoutes(lifecycle: Lifecycle, database: DatabaseHealth): readonly AnyRoute[] {
  return [
    defineRoute({
      method: 'GET',
      path: '/health',
      action: 'SYS-HEALTH',
      access: { kind: 'public', justification: 'Liveness probe for the container runtime and Nginx' },
      query: emptyQuerySchema,
      body: undefined,
      response: healthResponseSchema,
      handler: () => ({ status: 200, body: { status: 'ok' as const } }),
    }),
    defineRoute({
      method: 'GET',
      path: '/ready',
      action: 'SYS-READY',
      access: {
        kind: 'public',
        justification: 'Readiness probe: false before listening, during shutdown and while PostgreSQL is unreachable',
      },
      query: emptyQuerySchema,
      body: undefined,
      response: readinessResponseSchema,
      // The answer is a status word only; why the database is unreachable goes to the log.
      handler: async () =>
        lifecycle.isReady() && (await database.ping())
          ? { status: 200, body: { status: 'ready' as const } }
          : { status: 503, body: { status: 'not-ready' as const } },
    }),
  ];
}
