import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { securityDashboardResponseSchema } from '@ciphermesh/validation';
import { afterAll, describe, expect, it } from 'vitest';
import { StorageError, type ObjectStore } from '../storage/object-store';
import { evaluateHostStatus, platformStatus, probeStorage, readHostStatus, type HostStatusFile } from './status';

// Measured platform status (ADR-014): every state needs a fresh measurement; stale, missing or
// malformed host data proves nothing and is never reported as healthy.

const NOW = new Date('2026-10-15T12:00:00.000Z');
const minutesAgo = (m: number) => new Date(NOW.getTime() - m * 60_000).toISOString().replace('.000Z', 'Z');
const daysAhead = (d: number) => new Date(NOW.getTime() + d * 24 * 60 * 60_000).toISOString();

function healthyFile(overrides: Partial<HostStatusFile> = {}): HostStatusFile {
  return {
    schema: 1,
    checkedAt: minutesAgo(2),
    cloud: {
      provider: 'oci',
      region: 'eu-frankfurt-1',
      shape: 'VM.Standard.A1.Flex',
      ocpus: 2,
      memoryGb: 12,
      architecture: 'aarch64',
      os: 'ubuntu-24.04',
    },
    deployment: { release: '0123456789ab', deployedAt: minutesAgo(30) },
    services: ['nginx', 'api', 'postgres', 'object-storage'].map((name) => ({
      name: name as 'nginx',
      state: 'running',
      health: 'healthy',
    })),
    host: {
      diskUsedPercent: 20,
      dockerDiskUsedPercent: 20,
      memoryUsedPercent: 40,
      hostFirewall: 'active',
      unattendedUpgrades: 'active',
    },
    certificates: [
      { name: 'app', notAfter: daysAhead(80), issuer: 'Let-s-Encrypt' },
      { name: 'files', notAfter: daysAhead(80), issuer: 'Let-s-Encrypt' },
    ],
    worker: { finishedAt: minutesAgo(10), result: 'success' },
    backup: { lastBackupAt: minutesAgo(120) },
    restoreDrill: { finishedAt: minutesAgo(100), result: 'pass' },
    ...overrides,
  };
}

describe('host status evaluation', () => {
  it('reports NOT_CONNECTED without a status file, and claims nothing about the worker', () => {
    const result = evaluateHostStatus(null, NOW);
    expect(result.cloud).toEqual({ state: 'NOT_CONNECTED', checkedAt: null, reasons: [] });
    expect(result.worker.state).toBe('NOT_VERIFIED');
    expect(result.deployment).toBeNull();
  });

  it('reports NOT_VERIFIED when the configured file is missing or invalid', () => {
    const result = evaluateHostStatus(undefined, NOW);
    expect(result.cloud).toEqual({ state: 'NOT_VERIFIED', checkedAt: null, reasons: ['STATUS_UNREADABLE'] });
    expect(result.worker.reasons).toEqual(['STATUS_UNREADABLE']);
  });

  it('reports HEALTHY for a fresh, clean status from an OCI instance, with the measurement time', () => {
    const result = evaluateHostStatus(healthyFile(), NOW);
    expect(result.cloud).toEqual({ state: 'HEALTHY', checkedAt: '2026-10-15T11:58:00.000Z', reasons: [] });
    expect(result.worker).toEqual({ state: 'HEALTHY', checkedAt: '2026-10-15T11:50:00.000Z', reasons: [] });
    expect(result.deployment?.shape).toBe('VM.Standard.A1.Flex');
    expect(result.deployment?.lastRestoreDrill).toEqual({ finishedAt: '2026-10-15T10:20:00.000Z', result: 'pass' });
  });

  it('never keeps a previous success: an old status is NOT_VERIFIED, still showing what was last seen', () => {
    const result = evaluateHostStatus(healthyFile({ checkedAt: minutesAgo(16) }), NOW);
    expect(result.cloud).toEqual({ state: 'NOT_VERIFIED', checkedAt: null, reasons: ['STATUS_STALE'] });
    expect(result.worker.state).toBe('NOT_VERIFIED');
    expect(result.deployment?.checkedAt).toBe('2026-10-15T11:44:00.000Z');
  });

  it('treats a status from the future beyond clock skew as stale', () => {
    const future = new Date(NOW.getTime() + 5 * 60_000).toISOString();
    expect(evaluateHostStatus(healthyFile({ checkedAt: future }), NOW).cloud.reasons).toEqual(['STATUS_STALE']);
  });

  it('is DEGRADED with the reasons when a check fails', () => {
    const file = healthyFile();
    const result = evaluateHostStatus(
      {
        ...file,
        services: file.services.map((s) => (s.name === 'api' ? { ...s, health: 'unhealthy' } : s)),
        host: { ...file.host, dockerDiskUsedPercent: 91, memoryUsedPercent: 97, hostFirewall: 'inactive' },
        certificates: [{ name: 'app', notAfter: daysAhead(5), issuer: 'Let-s-Encrypt' }],
      },
      NOW,
    );
    expect(result.cloud.state).toBe('DEGRADED');
    expect(result.cloud.reasons).toEqual([
      'SERVICE_UNHEALTHY',
      'DISK_PRESSURE',
      'MEMORY_PRESSURE',
      'CERTIFICATE_EXPIRING',
      'HOST_FIREWALL_INACTIVE',
    ]);
  });

  it('counts a missing service or unknown measurements as failures, not as fine', () => {
    const file = healthyFile();
    const result = evaluateHostStatus(
      { ...file, services: file.services.slice(1), host: { ...file.host, diskUsedPercent: null } },
      NOW,
    );
    expect(result.cloud.reasons).toEqual(['SERVICE_UNHEALTHY', 'DISK_PRESSURE']);
  });

  it('never reports a host without cloud metadata (the local rehearsal) as a connected cloud', () => {
    const file = healthyFile();
    const result = evaluateHostStatus({ ...file, cloud: { ...file.cloud, provider: 'none' } }, NOW);
    expect(result.cloud.state).toBe('NOT_CONNECTED');
    expect(result.cloud.reasons).toEqual(['NOT_A_CLOUD_HOST']);
  });

  it('reports a local Docker host with its own warnings, but not the cloud firewall', () => {
    const file = healthyFile();
    const result = evaluateHostStatus(
      {
        ...file,
        cloud: { ...file.cloud, provider: 'none', region: null, shape: null },
        host: { ...file.host, hostFirewall: 'not-applicable' },
        services: file.services.map((s) => (s.name === 'nginx' ? { ...s, state: 'exited' } : s)),
      },
      NOW,
    );
    expect(result.cloud.state).toBe('NOT_CONNECTED');
    expect(result.cloud.reasons).toEqual(['NOT_A_CLOUD_HOST', 'SERVICE_UNHEALTHY']);
  });

  it('reports the worker from its last run: failed, stale or missing', () => {
    expect(
      evaluateHostStatus(healthyFile({ worker: { finishedAt: minutesAgo(5), result: 'failure' } }), NOW).worker,
    ).toEqual({ state: 'DEGRADED', checkedAt: '2026-10-15T11:55:00.000Z', reasons: ['WORKER_FAILED'] });
    expect(
      evaluateHostStatus(healthyFile({ worker: { finishedAt: minutesAgo(61), result: 'success' } }), NOW).worker
        .reasons,
    ).toEqual(['WORKER_STALE']);
    expect(evaluateHostStatus(healthyFile({ worker: null }), NOW).worker.reasons).toEqual(['WORKER_NO_RUN']);
  });
});

describe('host status file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cm-status-'));
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });
  const write = (name: string, content: string) => {
    const file = join(dir, name);
    writeFileSync(file, content);
    return file;
  };

  it('parses the collector format and drops fields the API does not use', async () => {
    const extra = { ...healthyFile(), backup: { lastBackupAt: minutesAgo(1), archive: 'name.tar.age', sha256: 'ab' } };
    const parsed = await readHostStatus(write('ok.json', JSON.stringify(extra)));
    expect(parsed?.backup).toEqual({ lastBackupAt: minutesAgo(1) });
  });

  it('rejects text where only measured words are allowed (nothing from the host is forwarded as text)', async () => {
    const file = healthyFile();
    for (const bad of [
      { ...file, cloud: { ...file.cloud, region: '<script>alert(1)</script>' } },
      { ...file, services: [{ name: 'shell', state: 'running', health: 'healthy' }] },
      { ...file, host: { ...file.host, diskUsedPercent: 140 } },
      { ...file, schema: 2 },
      { ...file, checkedAt: 'yesterday' },
    ]) {
      expect(await readHostStatus(write('bad.json', JSON.stringify(bad)))).toBeUndefined();
    }
    expect(await readHostStatus(write('broken.json', '{"schema":1'))).toBeUndefined();
    expect(await readHostStatus(join(dir, 'missing.json'))).toBeUndefined();
  });

  it('produces a response that passes the dashboard response schema', async () => {
    const storage = { available: true, head: () => Promise.resolve(null) } as unknown as ObjectStore;
    const status = await platformStatus({
      statusFile: write('full.json', JSON.stringify(healthyFile())),
      storage,
      now: NOW,
    });
    const body = {
      computedAt: NOW.toISOString(),
      environment: 'production',
      platform: Object.entries(status.components).map(([id, c]) => ({ id, ...c, reasons: [...c.reasons] })),
      deployment: status.deployment,
      metrics: [],
    };
    const parsed = securityDashboardResponseSchema.shape.deployment.safeParse(body.deployment);
    expect(parsed.success).toBe(true);
    expect(status.components.cloud.state).toBe('HEALTHY');
  });
});

describe('storage probe', () => {
  const store = (head: ObjectStore['head']): ObjectStore => ({ available: true, head }) as unknown as ObjectStore;

  it('is HEALTHY when storage answers with the runtime credential (found or not found)', async () => {
    expect(
      (
        await probeStorage(
          store(() => Promise.resolve(null)),
          NOW,
        )
      ).state,
    ).toBe('HEALTHY');
  });

  it('is DEGRADED when the credential is refused and UNAVAILABLE when storage does not answer', async () => {
    expect(
      await probeStorage(
        store(() => Promise.reject(new StorageError(403))),
        NOW,
      ),
    ).toEqual({
      state: 'DEGRADED',
      checkedAt: NOW.toISOString(),
      reasons: ['PROBE_DENIED'],
    });
    expect(
      (
        await probeStorage(
          store(() => Promise.reject(new StorageError())),
          NOW,
        )
      ).reasons,
    ).toEqual(['PROBE_FAILED']);
  });

  it('is NOT_CONFIGURED without storage', async () => {
    const none = { available: false } as unknown as ObjectStore;
    expect((await probeStorage(none, NOW)).state).toBe('NOT_CONFIGURED');
  });
});
