import { emptyQuerySchema, healthResponseSchema, readinessResponseSchema } from '@ciphermesh/validation';
import type { DatabaseHealth } from '../db/client';
import type { Lifecycle } from '../lifecycle';
import { defineRoute, type AnyRoute, type PublicRouteEntry } from './registry';

/**
 * System routes reachable without authentication. Adding a public route needs a security review
 * (authorization model, principle 1 deny by default). The authentication entry points are listed
 * in routes/auth.ts (AUTH_PUBLIC_ROUTES).
 */
export const PUBLIC_ROUTE_ALLOWLIST: readonly PublicRouteEntry[] = Object.freeze([
  { method: 'GET', path: '/health' },
  { method: 'GET', path: '/ready' },
]);

/**
 * Readiness is public and unauthenticated, so its database check is cached: however often the
 * probe is called, at most one database query runs per interval, and concurrent probes share the
 * query in flight. This removes an unauthenticated database amplification path (Phase 2 review).
 */
export function createReadinessProbe(
  database: DatabaseHealth,
  ttlMs = 2_000,
  now: () => number = Date.now,
): DatabaseHealth {
  let cached: { at: number; result: Promise<boolean> } | undefined;
  return {
    ping: () => {
      const t = now();
      if (cached === undefined || t - cached.at >= ttlMs) cached = { at: t, result: database.ping() };
      return cached.result;
    },
  };
}

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
