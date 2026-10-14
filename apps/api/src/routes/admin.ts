import {
  PLATFORM_COMPONENT_IDS,
  SECURITY_METRICS,
  type PlatformComponentId,
  type PlatformState,
} from '@ciphermesh/shared';
import { emptyQuerySchema, securityDashboardResponseSchema } from '@ciphermesh/validation';
import type { DashboardStore } from '../db/dashboard-store';
import { defineRoute, type AnyRoute } from './registry';

/**
 * Platform security dashboard (Phase 14, CM-T061, CM-T062). PA-01: platform administrators only,
 * enforced by the registry's administrator gate; everyone else receives the generic 404. The
 * response is aggregates only (projection by construction: identifiers of metrics and value keys,
 * non-negative integers). It is a GET and changes nothing. Metrics that need the deferred audit
 * ledger are reported NOT_IMPLEMENTED with no value, never as zero.
 */

/**
 * What the API can state about each platform component from this request alone. The database is
 * HEALTHY because the aggregate queries of this response completed; a failure fails the request
 * instead. Components the API does not observe are NOT_VERIFIED or NOT_CONNECTED, never healthy.
 */
const PLATFORM: Readonly<Record<PlatformComponentId, PlatformState>> = {
  api: 'HEALTHY',
  database: 'HEALTHY',
  'object-storage': 'NOT_VERIFIED',
  worker: 'NOT_VERIFIED',
  cloud: 'NOT_CONNECTED',
};

export function adminRoutes(
  store: DashboardStore,
  clock: () => Date,
  environment: 'development' | 'test' | 'production',
): readonly AnyRoute[] {
  return [
    defineRoute({
      method: 'GET',
      path: '/admin/security-dashboard',
      action: 'PA-01-DASHBOARD',
      access: { kind: 'authenticated', requires: { platformAdmin: true } },
      query: emptyQuerySchema,
      body: undefined,
      response: securityDashboardResponseSchema,
      handler: async () => {
        const now = clock();
        const aggregates = await store.aggregates(now);
        return {
          status: 200,
          body: {
            computedAt: now.toISOString(),
            environment,
            platform: PLATFORM_COMPONENT_IDS.map((id) => ({ id, state: PLATFORM[id] })),
            metrics: SECURITY_METRICS.map((metric) => {
              if (metric.availability === 'NOT_IMPLEMENTED') {
                return { id: metric.id, status: 'NOT_IMPLEMENTED' as const, values: [] };
              }
              // A value the store did not compute fails the request: no placeholder zero.
              const values = aggregates[metric.id];
              return {
                id: metric.id,
                status: 'AVAILABLE' as const,
                values: metric.values.map(({ key }) => {
                  const value = values?.[key];
                  if (value === undefined) throw new Error(`Dashboard value ${metric.id}.${key} was not computed`);
                  return { key, value };
                }),
              };
            }),
          },
        };
      },
    }),
  ];
}
