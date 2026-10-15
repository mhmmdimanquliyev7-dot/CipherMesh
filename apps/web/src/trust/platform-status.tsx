'use client';

import {
  PLATFORM_COMPONENTS,
  PLATFORM_REASON_TEXT,
  type PlatformComponentId,
  type PlatformReason,
  type PlatformState,
} from '@ciphermesh/shared';
import type { PlatformDeployment, SecurityDashboardResponse } from '@ciphermesh/validation';
import { Badge, type BadgeTone } from '../components/ui';

/**
 * Measured platform status (Cloud Deployment workstream, ADR-014), shown on the security dashboard
 * and, for platform administrators, on the Deployment & Infrastructure page. Every state is shown
 * with what it is based on, when it was measured and why; a state without a measurement time was
 * not measured. Values come only from the API response schema (fixed codes, short words, numbers).
 */

export const STATE: Readonly<Record<PlatformState, { readonly tone: BadgeTone; readonly label: string }>> = {
  HEALTHY: { tone: 'success', label: 'Healthy' },
  DEGRADED: { tone: 'warning', label: 'Degraded' },
  UNAVAILABLE: { tone: 'danger', label: 'Unavailable' },
  NOT_CONFIGURED: { tone: 'neutral', label: 'Not configured' },
  NOT_VERIFIED: { tone: 'neutral', label: 'Not verified' },
  NOT_CONNECTED: { tone: 'warning', label: 'Not connected' },
};

const time = (value: string | null): string => (value === null ? 'not measured' : new Date(value).toLocaleString());

export function ComponentState({
  component,
}: {
  readonly component: {
    readonly id: PlatformComponentId;
    readonly state: PlatformState;
    readonly checkedAt: string | null;
    readonly reasons: readonly PlatformReason[];
  };
}) {
  const info = PLATFORM_COMPONENTS[component.id];
  const state = STATE[component.state];
  return (
    <li
      className="space-y-1.5 rounded-xl border border-line bg-surface/90 p-4"
      data-testid={`platform-${component.id}`}
      data-state={component.state}
    >
      <p className="flex items-start justify-between gap-2">
        <span className="min-w-0 text-sm font-medium text-white">{info.name}</span>
        <span className="shrink-0 whitespace-nowrap">
          <Badge tone={state.tone}>{state.label}</Badge>
        </span>
      </p>
      <p className="text-xs text-slate-400">{info.basis[component.state] ?? 'Reported by the API.'}</p>
      {component.reasons.length > 0 ? (
        <ul className="list-disc space-y-0.5 pl-4 text-xs text-amber-200/90">
          {component.reasons.map((reason) => (
            <li key={reason}>{PLATFORM_REASON_TEXT[reason]}</li>
          ))}
        </ul>
      ) : null}
      <p className="text-[11px] text-slate-500">Measured: {time(component.checkedAt)}</p>
    </li>
  );
}

export function PlatformComponents({ platform }: { readonly platform: SecurityDashboardResponse['platform'] }) {
  return (
    <ul className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
      {platform.map((component) => (
        <ComponentState key={component.id} component={component} />
      ))}
    </ul>
  );
}

function Row({ label, value }: { readonly label: string; readonly value: string }) {
  return (
    <div className="flex justify-between gap-3 border-b border-line/60 py-1.5 text-xs last:border-0">
      <dt className="text-slate-400">{label}</dt>
      <dd className="text-right font-mono text-slate-200">{value}</dd>
    </div>
  );
}

const or = (value: string | number | null, unit = ''): string => (value === null ? 'not measured' : `${value}${unit}`);

/** The host status measured on the VM, as the API projected it. */
export function DeploymentDetails({ deployment }: { readonly deployment: PlatformDeployment }) {
  const services = deployment.services.map((s) => `${s.name}: ${s.state ?? '?'}/${s.health ?? '?'}`).join(', ');
  return (
    <div className="grid gap-4 lg:grid-cols-3" data-testid="deployment-details">
      <dl className="rounded-xl border border-line bg-surface/90 p-4">
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">Cloud instance</p>
        <Row
          label="Provider"
          value={
            deployment.provider === 'oci'
              ? 'Oracle Cloud Infrastructure'
              : 'None: local Docker host, not a cloud deployment'
          }
        />
        <Row label="Region" value={or(deployment.region)} />
        <Row label="Shape" value={or(deployment.shape)} />
        <Row label="OCPUs / memory" value={`${or(deployment.ocpus)} / ${or(deployment.memoryGb, ' GB')}`} />
        <Row label="Architecture" value={or(deployment.architecture)} />
        <Row label="Operating system" value={or(deployment.os)} />
      </dl>
      <dl className="rounded-xl border border-line bg-surface/90 p-4">
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">Release and services</p>
        <Row label="Release (commit)" value={or(deployment.release)} />
        <Row label="Deployed" value={time(deployment.deployedAt)} />
        <Row label="Containers" value={services || 'none reported'} />
        <Row
          label="Disk / memory used"
          value={`${or(deployment.diskUsedPercent, ' %')} / ${or(deployment.memoryUsedPercent, ' %')}`}
        />
        <Row label="Host firewall" value={or(deployment.hostFirewall)} />
        <Row label="Security updates" value={or(deployment.unattendedUpgrades)} />
      </dl>
      <dl className="rounded-xl border border-line bg-surface/90 p-4">
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">Certificates and jobs</p>
        {deployment.certificates.map((c) => (
          <Row key={c.name} label={`TLS ${c.name} host`} value={`${or(c.issuer)}, until ${time(c.notAfter)}`} />
        ))}
        <Row
          label="Last worker run"
          value={
            deployment.lastWorkerRun === null
              ? 'none'
              : `${deployment.lastWorkerRun.result}, ${time(deployment.lastWorkerRun.finishedAt)}`
          }
        />
        <Row label="Last backup" value={time(deployment.lastBackupAt)} />
        <Row
          label="Last restore drill"
          value={
            deployment.lastRestoreDrill === null
              ? 'none'
              : `${deployment.lastRestoreDrill.result}, ${time(deployment.lastRestoreDrill.finishedAt)}`
          }
        />
      </dl>
      <p className="text-xs text-slate-500 lg:col-span-3">
        Measured on the host at {time(deployment.checkedAt)} by the status collector (every 5 minutes). Instance values
        come from the provider&apos;s instance metadata; no identifier, address or credential is shown.
      </p>
    </div>
  );
}
