/**
 * Platform security dashboard (Phase 14, CM-T061, CM-T062; docs/architecture/security-dashboard.md).
 * The metric catalogue is shared by the API, which computes the values, and the web client, which
 * shows each value with its definition. Principles: real data only, no composite score, aggregates
 * only (no room names, content, member lists or per-user activity), PLATFORM_ADMIN only (PA-01).
 *
 * Metrics that need the hash-chained audit ledger (Phase 12, deferred by the project owner on
 * 2026-10-13) are declared NOT_IMPLEMENTED: the API returns no value for them and the client says
 * why. Security events go to the redacted application log until then, never to a table that a
 * dashboard could count.
 */

export const SECURITY_METRIC_IDS = [
  'SD-01',
  'SD-02',
  'SD-03',
  'SD-04',
  'SD-05',
  'SD-06',
  'SD-07',
  'SD-08',
  'SD-09',
  'SD-10',
  'SD-11',
  'SD-12',
  'SD-13',
  'SD-14',
  'SD-15',
] as const;
export type SecurityMetricId = (typeof SECURITY_METRIC_IDS)[number];

export interface SecurityMetricDefinition {
  readonly id: SecurityMetricId;
  readonly title: string;
  readonly definition: string;
  /** The value keys the API returns, in display order, with their labels. Empty when not implemented. */
  readonly values: readonly { readonly key: string; readonly label: string }[];
  readonly availability: 'AVAILABLE' | 'NOT_IMPLEMENTED';
  /** Why a metric is not implemented. */
  readonly reason?: string;
  /** Values that need attention when non-zero (security-dashboard.md section 4); never turned into a score. */
  readonly attention?: readonly string[];
}

const LEDGER_DEFERRED =
  'Needs the hash-chained audit ledger (Phase 12), which is deferred. These events are written only to the redacted application log, so there is nothing to count.';

export const SECURITY_METRICS: readonly SecurityMetricDefinition[] = Object.freeze([
  {
    id: 'SD-01',
    title: 'Encrypted files',
    definition: 'Files with status AVAILABLE, and the total size of their ciphertext in bytes.',
    values: [
      { key: 'files', label: 'Available files' },
      { key: 'ciphertextBytes', label: 'Ciphertext bytes' },
    ],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-02',
    title: 'Secure rooms',
    definition: 'Rooms with status ACTIVE.',
    values: [{ key: 'rooms', label: 'Active rooms' }],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-03',
    title: 'Security-policy distribution',
    definition: 'ACTIVE rooms per security profile.',
    values: [
      { key: 'STANDARD', label: 'Standard' },
      { key: 'CONFIDENTIAL', label: 'Confidential' },
      { key: 'RESTRICTED', label: 'Restricted' },
    ],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-04',
    title: 'Expiring secrets',
    definition: 'ACTIVE secrets whose expiry falls within the next 24 hours, and within the next 7 days.',
    values: [
      { key: 'within24h', label: 'Within 24 hours' },
      { key: 'within7d', label: 'Within 7 days' },
    ],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-05',
    title: 'Failed login attempts',
    definition:
      'Login attempts with an outcome other than SUCCESS in the last 24 hours and 7 days; distinct source addresses among the 7-day failures; accounts currently throttled.',
    values: [
      { key: 'failed24h', label: 'Failed, 24 hours' },
      { key: 'failed7d', label: 'Failed, 7 days' },
      { key: 'sources7d', label: 'Distinct sources, 7 days' },
      { key: 'throttledAccounts', label: 'Throttled accounts' },
    ],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-06',
    title: 'MFA coverage',
    definition:
      'ACTIVE users with MFA enabled, out of all ACTIVE users; ACTIVE members of CONFIDENTIAL or RESTRICTED rooms without MFA, who those rooms refuse (PC-01).',
    values: [
      { key: 'withMfa', label: 'Users with MFA' },
      { key: 'activeUsers', label: 'Active users' },
      { key: 'blockedMembers', label: 'Members blocked for missing MFA' },
    ],
    availability: 'AVAILABLE',
    attention: ['blockedMembers'],
  },
  {
    id: 'SD-07',
    title: 'Key rotations',
    definition: 'Room key versions created in the last 30 days for a reason other than INITIAL, by reason.',
    values: [
      { key: 'total', label: 'Rotations, 30 days' },
      { key: 'MEMBER_REMOVED', label: 'Member removed' },
      { key: 'MEMBER_LEFT', label: 'Member left' },
      { key: 'MEMBER_SUSPENDED', label: 'Member suspended' },
      { key: 'MEMBER_DELETED', label: 'Member deleted' },
      { key: 'IDENTITY_KEY_COMPROMISED', label: 'Identity compromised' },
      { key: 'CRYPTOPERIOD_EXPIRED', label: 'Cryptoperiod ended' },
      { key: 'WRAP_LIMIT_REACHED', label: 'Wrap limit' },
      { key: 'MANUAL', label: 'Manual' },
      { key: 'POLICY_CHANGE', label: 'Profile change' },
    ],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-08',
    title: 'Rooms write-locked for rekey',
    definition:
      'ACTIVE rooms in REKEY_REQUIRED or REKEYING; the age in hours of the oldest lock; rekey operations abandoned (lease expired) in the last 7 days.',
    values: [
      { key: 'lockedRooms', label: 'Locked rooms' },
      { key: 'oldestLockHours', label: 'Oldest lock, hours' },
      { key: 'abandoned7d', label: 'Abandoned operations, 7 days' },
    ],
    availability: 'AVAILABLE',
    attention: ['lockedRooms', 'abandoned7d'],
  },
  {
    id: 'SD-09',
    title: 'Active sessions',
    definition: 'Sessions that are neither revoked nor past their idle or absolute expiry.',
    values: [{ key: 'sessions', label: 'Active sessions' }],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-10',
    title: 'Audit integrity status',
    definition: 'Result, time and range of the latest audit-chain verification; the latest anchored checkpoint.',
    values: [],
    availability: 'NOT_IMPLEMENTED',
    reason:
      'The hash-chained audit ledger and its verification runs (Phase 12) are deferred. No integrity status exists to report.',
  },
  {
    id: 'SD-11',
    title: 'Profile downgrades',
    definition: 'Security-profile downgrade events in the last 30 days.',
    values: [],
    availability: 'NOT_IMPLEMENTED',
    reason: LEDGER_DEFERRED,
  },
  {
    id: 'SD-12',
    title: 'Key-commitment mismatch reports',
    definition: 'Room-key rejection reports from members’ browsers in the last 30 days (expected to be zero).',
    values: [],
    availability: 'NOT_IMPLEMENTED',
    reason: LEDGER_DEFERRED,
  },
  {
    id: 'SD-13',
    title: 'Vault adoption',
    definition: 'ACTIVE users with an ACTIVE identity key pair, out of all ACTIVE users.',
    values: [
      { key: 'withVault', label: 'Users with a vault' },
      { key: 'activeUsers', label: 'Active users' },
    ],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-14',
    title: 'Invitations awaiting approval',
    definition: 'Invitations with status PENDING_APPROVAL (an admin invited; the owner has not approved yet).',
    values: [{ key: 'pendingApproval', label: 'Awaiting approval' }],
    availability: 'AVAILABLE',
  },
  {
    id: 'SD-15',
    title: 'Room Safety Code reports',
    definition: 'Recorded Safety Code comparisons and mismatch reports in the last 30 days.',
    values: [],
    availability: 'NOT_IMPLEMENTED',
    reason: LEDGER_DEFERRED,
  },
] satisfies readonly SecurityMetricDefinition[]);

/**
 * Provider-neutral platform status (the contract the cloud workstream connects to). A state is
 * reported only with its basis; a component the API cannot observe is NOT_VERIFIED, never healthy.
 */
export const PLATFORM_COMPONENT_IDS = ['api', 'database', 'object-storage', 'worker', 'cloud'] as const;
export type PlatformComponentId = (typeof PLATFORM_COMPONENT_IDS)[number];

export const PLATFORM_STATES = [
  'HEALTHY',
  'DEGRADED',
  'UNAVAILABLE',
  'NOT_CONFIGURED',
  'NOT_VERIFIED',
  'NOT_CONNECTED',
] as const;
export type PlatformState = (typeof PLATFORM_STATES)[number];

export const PLATFORM_COMPONENTS: Readonly<
  Record<
    PlatformComponentId,
    { readonly name: string; readonly basis: Readonly<Partial<Record<PlatformState, string>>> }
  >
> = Object.freeze({
  api: { name: 'API', basis: { HEALTHY: 'This response was produced by the API.' } },
  database: {
    name: 'PostgreSQL',
    basis: { HEALTHY: 'The aggregate queries of this response completed against the database.' },
  },
  'object-storage': {
    name: 'Object storage',
    basis: {
      HEALTHY: 'The API reached the bucket with its runtime credential for this report (authenticated probe).',
      DEGRADED: 'Storage answered, but refused the runtime credential.',
      UNAVAILABLE: 'Storage did not answer the probe of this report.',
      NOT_CONFIGURED: 'No object storage is configured for this API.',
    },
  },
  worker: {
    name: 'Worker',
    basis: {
      HEALTHY: 'The last scheduled worker run finished successfully within the allowed age.',
      DEGRADED: 'The last scheduled worker run failed.',
      NOT_VERIFIED: 'No recent worker run is recorded; its jobs are verified by tests.',
    },
  },
  cloud: {
    name: 'Cloud deployment',
    basis: {
      HEALTHY:
        'The host status collected on the cloud VM within the allowed age shows every service healthy and no host warning.',
      DEGRADED: 'The host status collected on the cloud VM is recent but shows a warning (see the reasons).',
      NOT_VERIFIED: 'The host status is missing, unreadable or older than allowed, so nothing is claimed.',
      NOT_CONNECTED: 'This API does not run on a cloud host that reported its instance metadata.',
    },
  },
});

/**
 * Why a platform component has its state (Cloud Deployment workstream, ADR-014). Fixed codes only:
 * the API never forwards text from the host, so nothing it reads can reach the browser as words.
 */
export const PLATFORM_REASONS = [
  'STATUS_STALE',
  'STATUS_UNREADABLE',
  'NOT_A_CLOUD_HOST',
  'SERVICE_UNHEALTHY',
  'DISK_PRESSURE',
  'MEMORY_PRESSURE',
  'CERTIFICATE_EXPIRING',
  'HOST_FIREWALL_INACTIVE',
  'WORKER_NO_RUN',
  'WORKER_STALE',
  'WORKER_FAILED',
  'PROBE_DENIED',
  'PROBE_FAILED',
] as const;
export type PlatformReason = (typeof PLATFORM_REASONS)[number];

export const PLATFORM_REASON_TEXT: Readonly<Record<PlatformReason, string>> = Object.freeze({
  STATUS_STALE: 'The last host status is older than allowed.',
  STATUS_UNREADABLE: 'The host status file is missing or not in the expected format.',
  NOT_A_CLOUD_HOST: 'The host reported no cloud instance metadata (a local rehearsal, not a cloud VM).',
  SERVICE_UNHEALTHY: 'A container is not running or not healthy.',
  DISK_PRESSURE: 'A file system is more than 85 % full.',
  MEMORY_PRESSURE: 'Memory use is above 95 %.',
  CERTIFICATE_EXPIRING: 'A TLS certificate is missing or expires within 14 days.',
  HOST_FIREWALL_INACTIVE: 'The host firewall is not active.',
  WORKER_NO_RUN: 'No worker run is recorded.',
  WORKER_STALE: 'The last worker run is older than allowed.',
  WORKER_FAILED: 'The last worker run failed.',
  PROBE_DENIED: 'Storage refused the runtime credential.',
  PROBE_FAILED: 'Storage did not answer.',
});

/** Freshness and thresholds of the measured platform status (docs/deployment/operational-runbook.md). */
export const PLATFORM_LIMITS = Object.freeze({
  /** The collector runs every 5 minutes; three missed runs make the status stale. */
  hostStatusMaxAgeMs: 15 * 60_000,
  /** The worker timer runs every 15 minutes; four missed runs make the worker stale. */
  workerMaxAgeMs: 60 * 60_000,
  certificateMinDays: 14,
  diskMaxPercent: 85,
  memoryMaxPercent: 95,
});

/** Containers whose state the host collector reports (compose.cloud.yml service names). */
export const PLATFORM_SERVICES = ['nginx', 'api', 'postgres', 'object-storage'] as const;
export type PlatformService = (typeof PLATFORM_SERVICES)[number];
