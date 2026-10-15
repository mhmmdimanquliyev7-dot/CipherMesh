import {
  PLATFORM_COMPONENT_IDS,
  PLATFORM_REASONS,
  PLATFORM_SERVICES,
  PLATFORM_STATES,
  SECURITY_METRIC_IDS,
} from '@ciphermesh/shared';
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

/** A short measured word from the host (state, region, shape): no spaces, no markup. */
const shortWordSchema = z.string().regex(/^[A-Za-z0-9._:-]{1,64}$/);
const percentSchema = z.number().min(0).max(100);

/**
 * The measured state of one component, with when it was measured and why (fixed reason codes;
 * Cloud Deployment workstream, ADR-014). checkedAt is null when nothing was measured.
 */
export const platformComponentSchema = z.strictObject({
  id: z.enum(PLATFORM_COMPONENT_IDS),
  state: z.enum(PLATFORM_STATES),
  checkedAt: isoTimestampSchema.nullable(),
  reasons: z.array(z.enum(PLATFORM_REASONS)).max(PLATFORM_REASONS.length),
});

/**
 * The sanitized host status of the deployment (cm-status-collect on the VM): instance shape and
 * region from the cloud provider's metadata, container states, resource use, certificate expiry
 * and the outcomes of the scheduled jobs. No identifier, address, path or credential.
 */
export const platformDeploymentSchema = z.strictObject({
  checkedAt: isoTimestampSchema,
  provider: z.enum(['oci', 'none']),
  region: shortWordSchema.nullable(),
  shape: shortWordSchema.nullable(),
  ocpus: z.number().min(0).max(1024).nullable(),
  memoryGb: z.number().min(0).max(65536).nullable(),
  architecture: shortWordSchema.nullable(),
  os: shortWordSchema.nullable(),
  release: z
    .string()
    .regex(/^(?:[0-9a-f]{7,40}|rehearsal)$/)
    .nullable(),
  deployedAt: isoTimestampSchema.nullable(),
  services: z
    .array(
      z.strictObject({
        name: z.enum(PLATFORM_SERVICES),
        state: shortWordSchema.nullable(),
        health: shortWordSchema.nullable(),
      }),
    )
    .max(PLATFORM_SERVICES.length),
  diskUsedPercent: percentSchema.nullable(),
  memoryUsedPercent: percentSchema.nullable(),
  hostFirewall: shortWordSchema.nullable(),
  unattendedUpgrades: shortWordSchema.nullable(),
  certificates: z
    .array(
      z.strictObject({
        name: z.enum(['app', 'files']),
        notAfter: isoTimestampSchema.nullable(),
        issuer: shortWordSchema.nullable(),
      }),
    )
    .max(2),
  lastWorkerRun: z.strictObject({ finishedAt: isoTimestampSchema, result: z.enum(['success', 'failure']) }).nullable(),
  lastBackupAt: isoTimestampSchema.nullable(),
  lastRestoreDrill: z.strictObject({ finishedAt: isoTimestampSchema, result: z.enum(['pass', 'fail']) }).nullable(),
});
export type PlatformDeployment = z.infer<typeof platformDeploymentSchema>;

export const securityDashboardResponseSchema = z.strictObject({
  computedAt: isoTimestampSchema,
  environment: z.enum(['development', 'test', 'production']),
  platform: z.array(platformComponentSchema).length(PLATFORM_COMPONENT_IDS.length),
  deployment: platformDeploymentSchema.nullable(),
  metrics: z.array(securityMetricSchema).length(SECURITY_METRIC_IDS.length),
});
export type SecurityDashboardResponse = z.infer<typeof securityDashboardResponseSchema>;
