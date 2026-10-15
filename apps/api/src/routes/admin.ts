import { PLATFORM_COMPONENT_IDS, SECURITY_METRICS } from '@ciphermesh/shared';
import { emptyQuerySchema, securityDashboardResponseSchema } from '@ciphermesh/validation';
import type { DashboardStore } from '../db/dashboard-store';
import { platformStatus } from '../platform/status';
import type { ObjectStore } from '../storage/object-store';
import { defineRoute, type AnyRoute } from './registry';

/**
 * Platform security dashboard (Phase 14, CM-T061, CM-T062). PA-01: platform administrators only,
 * enforced by the registry's administrator gate; everyone else receives the generic 404. The
 * response is aggregates only (projection by construction: identifiers of metrics and value keys,
 * non-negative integers). It is a GET and changes nothing. Metrics that need the deferred audit
 * ledger are reported NOT_IMPLEMENTED with no value, never as zero.
 */

/**
 * Platform components (Cloud Deployment workstream, ADR-014): the database is HEALTHY because the
 * aggregate queries of this response completed (a failure fails the request instead); object
 * storage is probed with the runtime credential; the worker and the cloud host come from the host
 * status file on the VM, with freshness limits (platform/status.ts). Nothing unobserved is healthy.
 */
export interface PlatformSources {
  /** The read-only host status file; null when the API is not on the cloud VM. */
  readonly statusFile: string | null;
  readonly storage: ObjectStore;
}

export function adminRoutes(
  store: DashboardStore,
  clock: () => Date,
  environment: 'development' | 'test' | 'production',
  sources: PlatformSources,
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
        const platform = await platformStatus({ statusFile: sources.statusFile, storage: sources.storage, now });
        return {
          status: 200,
          body: {
            computedAt: now.toISOString(),
            environment,
            platform: PLATFORM_COMPONENT_IDS.map((id) => {
              const { state, checkedAt, reasons } = platform.components[id];
              return { id, state, checkedAt, reasons: [...reasons] };
            }),
            deployment: platform.deployment,
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
