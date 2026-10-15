import { readFile } from 'node:fs/promises';
import {
  PLATFORM_LIMITS,
  PLATFORM_SERVICES,
  type PlatformComponentId,
  type PlatformReason,
  type PlatformState,
} from '@ciphermesh/shared';
import type { PlatformDeployment } from '@ciphermesh/validation';
import { z } from 'zod';
import { StorageError, type ObjectStore } from '../storage/object-store';

/**
 * Measured platform status for the security dashboard (Cloud Deployment workstream, ADR-014).
 *
 * Sources, and what each may claim:
 *   - this API process and its database queries: api and database (the request itself);
 *   - an authenticated HEAD probe of object storage with the runtime credential: object-storage;
 *   - the host status file written every 5 minutes on the VM by cm-status-collect and mounted
 *     read-only: cloud and worker.
 * The API never runs a command and never forwards text from the file: values are parsed against
 * a strict schema, re-validated by the response schema, and reasons are fixed codes. A file that
 * is missing, malformed or older than PLATFORM_LIMITS.hostStatusMaxAgeMs proves nothing, so the
 * components that depend on it are NOT_VERIFIED, never healthy (security-dashboard.md section 5).
 */

export interface ComponentStatus {
  readonly state: PlatformState;
  readonly checkedAt: string | null;
  readonly reasons: readonly PlatformReason[];
}

export interface PlatformStatus {
  readonly components: Readonly<Record<PlatformComponentId, ComponentStatus>>;
  readonly deployment: PlatformDeployment | null;
}

// Timestamps from the host are UTC, with or without milliseconds; they are re-emitted with them.
const hostTime = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/)
  .refine((value) => !Number.isNaN(Date.parse(value)));
const word = z.string().regex(/^[A-Za-z0-9._:-]{1,64}$/);
const percent = z.number().min(0).max(100);

/** The file written by infrastructure/deployment/bin/cm-status-collect (schema 1). */
export const hostStatusFileSchema = z.object({
  schema: z.literal(1),
  checkedAt: hostTime,
  cloud: z.object({
    provider: z.enum(['oci', 'none']),
    region: word.nullable(),
    shape: word.nullable(),
    ocpus: z.number().min(0).max(1024).nullable(),
    memoryGb: z.number().min(0).max(65536).nullable(),
    architecture: word.nullable(),
    os: word.nullable(),
  }),
  deployment: z
    .object({
      release: z.string().regex(/^(?:[0-9a-f]{7,40}|rehearsal)$/),
      deployedAt: hostTime,
    })
    .nullable(),
  services: z
    .array(z.object({ name: z.enum(PLATFORM_SERVICES), state: word.nullable(), health: word.nullable() }))
    .max(PLATFORM_SERVICES.length),
  host: z.object({
    diskUsedPercent: percent.nullable(),
    dockerDiskUsedPercent: percent.nullable(),
    memoryUsedPercent: percent.nullable(),
    hostFirewall: word.nullable(),
    unattendedUpgrades: word.nullable(),
  }),
  certificates: z
    .array(z.object({ name: z.enum(['app', 'files']), notAfter: hostTime.nullable(), issuer: word.nullable() }))
    .max(2),
  worker: z.object({ finishedAt: hostTime, result: z.enum(['success', 'failure']) }).nullable(),
  backup: z.object({ lastBackupAt: hostTime }).nullable(),
  restoreDrill: z.object({ finishedAt: hostTime, result: z.enum(['pass', 'fail']) }).nullable(),
});
export type HostStatusFile = z.infer<typeof hostStatusFileSchema>;

const iso = (value: string): string => new Date(value).toISOString();
const MAX_FILE_BYTES = 64 * 1024;

/** Reads and parses the host status file; undefined when it is missing or invalid. */
export async function readHostStatus(file: string): Promise<HostStatusFile | undefined> {
  try {
    const text = await readFile(file, 'utf8');
    if (text.length > MAX_FILE_BYTES) return undefined;
    const parsed = hostStatusFileSchema.safeParse(JSON.parse(text));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

const NOT_VERIFIED = (reasons: readonly PlatformReason[]): ComponentStatus => ({
  state: 'NOT_VERIFIED',
  checkedAt: null,
  reasons,
});

/**
 * The cloud and worker states and the sanitized deployment block, from the host status file.
 * `file` is null when no status file is configured (development and tests), undefined when it is
 * configured but missing or invalid.
 */
export function evaluateHostStatus(
  file: HostStatusFile | null | undefined,
  now: Date,
): { cloud: ComponentStatus; worker: ComponentStatus; deployment: PlatformDeployment | null } {
  if (file === null) {
    return {
      cloud: { state: 'NOT_CONNECTED', checkedAt: null, reasons: [] },
      worker: NOT_VERIFIED([]),
      deployment: null,
    };
  }
  if (file === undefined) {
    return {
      cloud: NOT_VERIFIED(['STATUS_UNREADABLE']),
      worker: NOT_VERIFIED(['STATUS_UNREADABLE']),
      deployment: null,
    };
  }
  const checkedAt = Date.parse(file.checkedAt);
  const age = now.getTime() - checkedAt;
  // Older than allowed, or from the future beyond clock skew: proves nothing about now.
  const fresh = age <= PLATFORM_LIMITS.hostStatusMaxAgeMs && age >= -2 * 60_000;
  const deployment = projectDeployment(file);
  if (!fresh) {
    return { cloud: NOT_VERIFIED(['STATUS_STALE']), worker: NOT_VERIFIED(['STATUS_STALE']), deployment };
  }

  const reasons: PlatformReason[] = [];
  const healthy = (name: string) =>
    file.services.some(
      (s) => s.name === name && s.state === 'running' && (s.health === 'healthy' || s.health === 'none'),
    );
  if (!PLATFORM_SERVICES.every(healthy)) reasons.push('SERVICE_UNHEALTHY');
  const { diskUsedPercent, dockerDiskUsedPercent, memoryUsedPercent, hostFirewall } = file.host;
  if ([diskUsedPercent, dockerDiskUsedPercent].some((p) => p === null || p > PLATFORM_LIMITS.diskMaxPercent)) {
    reasons.push('DISK_PRESSURE');
  }
  if (memoryUsedPercent === null || memoryUsedPercent > PLATFORM_LIMITS.memoryMaxPercent)
    reasons.push('MEMORY_PRESSURE');
  const minimum = now.getTime() + PLATFORM_LIMITS.certificateMinDays * 24 * 60 * 60_000;
  const certificateOk = (name: 'app' | 'files') =>
    file.certificates.some((c) => c.name === name && c.notAfter !== null && Date.parse(c.notAfter) > minimum);
  if (!certificateOk('app') || !certificateOk('files')) reasons.push('CERTIFICATE_EXPIRING');
  if (hostFirewall !== 'active') reasons.push('HOST_FIREWALL_INACTIVE');

  let cloud: ComponentStatus;
  if (file.cloud.provider !== 'oci') {
    // A local Docker host (the rehearsal): never a connected cloud. The host firewall belongs to
    // the cloud VM; Docker Desktop publishes only on loopback, so its absence is not a warning here.
    const local = reasons.filter((reason) => reason !== 'HOST_FIREWALL_INACTIVE');
    cloud = { state: 'NOT_CONNECTED', checkedAt: iso(file.checkedAt), reasons: ['NOT_A_CLOUD_HOST', ...local] };
  } else {
    cloud = { state: reasons.length === 0 ? 'HEALTHY' : 'DEGRADED', checkedAt: iso(file.checkedAt), reasons };
  }

  let worker: ComponentStatus;
  if (file.worker === null) worker = NOT_VERIFIED(['WORKER_NO_RUN']);
  else if (now.getTime() - Date.parse(file.worker.finishedAt) > PLATFORM_LIMITS.workerMaxAgeMs) {
    worker = NOT_VERIFIED(['WORKER_STALE']);
  } else if (file.worker.result === 'failure') {
    worker = { state: 'DEGRADED', checkedAt: iso(file.worker.finishedAt), reasons: ['WORKER_FAILED'] };
  } else worker = { state: 'HEALTHY', checkedAt: iso(file.worker.finishedAt), reasons: [] };

  return { cloud, worker, deployment };
}

function projectDeployment(file: HostStatusFile): PlatformDeployment {
  return {
    checkedAt: iso(file.checkedAt),
    provider: file.cloud.provider,
    region: file.cloud.region,
    shape: file.cloud.shape,
    ocpus: file.cloud.ocpus,
    memoryGb: file.cloud.memoryGb,
    architecture: file.cloud.architecture,
    os: file.cloud.os,
    release: file.deployment?.release ?? null,
    deployedAt: file.deployment === null ? null : iso(file.deployment.deployedAt),
    services: file.services.map(({ name, state, health }) => ({ name, state, health })),
    diskUsedPercent: file.host.diskUsedPercent,
    memoryUsedPercent: file.host.memoryUsedPercent,
    hostFirewall: file.host.hostFirewall,
    unattendedUpgrades: file.host.unattendedUpgrades,
    certificates: file.certificates.map(({ name, notAfter, issuer }) => ({
      name,
      notAfter: notAfter === null ? null : iso(notAfter),
      issuer,
    })),
    lastWorkerRun:
      file.worker === null ? null : { finishedAt: iso(file.worker.finishedAt), result: file.worker.result },
    lastBackupAt: file.backup === null ? null : iso(file.backup.lastBackupAt),
    lastRestoreDrill:
      file.restoreDrill === null
        ? null
        : { finishedAt: iso(file.restoreDrill.finishedAt), result: file.restoreDrill.result },
  };
}

/**
 * Storage reachability with the runtime credential: a HEAD of a key that is never written (object
 * keys come from the CSPRNG, newObjectKey). "Not found" and "found" both prove that storage
 * answered and accepted the signature; a refusal of the credential is DEGRADED.
 */
const PROBE_KEY = `f/${'0'.repeat(43)}`;

export async function probeStorage(storage: ObjectStore, now: Date): Promise<ComponentStatus> {
  if (!storage.available) return { state: 'NOT_CONFIGURED', checkedAt: null, reasons: [] };
  try {
    await storage.head(PROBE_KEY);
    return { state: 'HEALTHY', checkedAt: now.toISOString(), reasons: [] };
  } catch (error) {
    const denied = error instanceof StorageError && (error.status === 401 || error.status === 403);
    return {
      state: denied ? 'DEGRADED' : 'UNAVAILABLE',
      checkedAt: now.toISOString(),
      reasons: [denied ? 'PROBE_DENIED' : 'PROBE_FAILED'],
    };
  }
}

/** Everything the dashboard reports about the platform, for one request. */
export async function platformStatus(options: {
  readonly statusFile: string | null;
  readonly storage: ObjectStore;
  readonly now: Date;
}): Promise<PlatformStatus> {
  const { now } = options;
  const host = evaluateHostStatus(options.statusFile === null ? null : await readHostStatus(options.statusFile), now);
  const measured = { state: 'HEALTHY' as const, checkedAt: now.toISOString(), reasons: [] };
  return {
    components: {
      api: measured,
      database: measured,
      'object-storage': await probeStorage(options.storage, now),
      worker: host.worker,
      cloud: host.cloud,
    },
    deployment: host.deployment,
  };
}
