import { PLATFORM_COMPONENT_IDS, PLATFORM_STATES, SECURITY_METRIC_IDS } from '@ciphermesh/shared';
import { isoTimestampSchema } from './schemas';
import { z } from './zod';

/**
 * GET /admin/security-dashboard (PA-01, Phase 14, CM-T061, CM-T062): aggregates only. The response
 * carries metric identifiers, value keys and non-negative integers, and the platform component
 * states; there is no field that could hold a room name, a user, content or key material.
 */
const metricValueSchema = z.strictObject({
  key: z.string().regex(/^[A-Za-z0-9_]{1,40}$/),
  value: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
});

export const securityMetricSchema = z.strictObject({
  id: z.enum(SECURITY_METRIC_IDS),
  status: z.enum(['AVAILABLE', 'NOT_IMPLEMENTED']),
  values: z.array(metricValueSchema).max(16),
});

export const securityDashboardResponseSchema = z.strictObject({
  computedAt: isoTimestampSchema,
  environment: z.enum(['development', 'test', 'production']),
  platform: z
    .array(z.strictObject({ id: z.enum(PLATFORM_COMPONENT_IDS), state: z.enum(PLATFORM_STATES) }))
    .length(PLATFORM_COMPONENT_IDS.length),
  metrics: z.array(securityMetricSchema).length(SECURITY_METRIC_IDS.length),
});
export type SecurityDashboardResponse = z.infer<typeof securityDashboardResponseSchema>;
