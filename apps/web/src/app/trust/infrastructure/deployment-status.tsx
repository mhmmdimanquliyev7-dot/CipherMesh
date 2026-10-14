'use client';

import { PLATFORM_COMPONENTS, PLATFORM_REASON_TEXT } from '@ciphermesh/shared';
import { securityDashboardResponseSchema, type SecurityDashboardResponse } from '@ciphermesh/validation';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { Icon } from '../../../components/icons';
import { Badge } from '../../../components/ui';
import { publicEnv } from '../../../config/public-env';
import { api, ApiError } from '../../../lib/api';
import { STATE } from '../../../trust/platform-status';

/**
 * The deployment status card (Cloud Deployment workstream, ADR-014). The live cloud state is
 * measured on the VM and reported by the API to platform administrators only (PA-01): a visitor
 * without that role is told so, and nothing is claimed for them. The environment shown is the
 * build-time label, stated as such.
 */
type Live =
  | { readonly kind: 'loading' }
  | { readonly kind: 'restricted' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'ready'; readonly data: SecurityDashboardResponse };

export function DeploymentStatus({
  controls,
  configured,
  verified,
}: {
  readonly controls: number;
  readonly configured: number;
  readonly verified: number;
}) {
  const [live, setLive] = useState<Live>({ kind: 'loading' });
  useEffect(() => {
    let active = true;
    api('GET', '/admin/security-dashboard', securityDashboardResponseSchema).then(
      (data) => {
        if (active) setLive({ kind: 'ready', data });
      },
      (error: unknown) => {
        if (!active) return;
        const restricted = error instanceof ApiError && (error.status === 401 || error.status === 404);
        setLive({ kind: restricted ? 'restricted' : 'unavailable' });
      },
    );
    return () => {
      active = false;
    };
  }, []);

  const environment =
    publicEnv.deploymentEnvironment === 'development' ? 'Development build' : 'Cloud demonstration build';
  const cloud = live.kind === 'ready' ? live.data.platform.find((c) => c.id === 'cloud') : undefined;
  const deployment = live.kind === 'ready' ? live.data.deployment : null;
  return (
    <section aria-label="Deployment status" className="grid gap-4 md:grid-cols-3" data-testid="deployment-status">
      <div className="space-y-2 rounded-2xl border border-line bg-surface/90 p-5" data-testid="deployment-live">
        <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-400">
          <Icon name="cloud" className="size-4" />
          Cloud deployment (live)
        </p>
        {cloud === undefined ? (
          <>
            <p className="text-lg font-semibold text-white">
              {live.kind === 'loading'
                ? 'Checking…'
                : live.kind === 'unavailable'
                  ? 'Status unavailable'
                  : 'Administrators only'}
            </p>
            <p className="text-sm text-slate-400">
              The measured status of the cloud host is shown to platform administrators (
              <Link className="underline" href="/trust/dashboard">
                security dashboard
              </Link>
              ). Everyone can run the live checks below, which observe this deployment from the browser.
            </p>
          </>
        ) : (
          <>
            <p className="flex flex-wrap items-center gap-2 text-lg font-semibold text-white">
              <Badge tone={STATE[cloud.state].tone}>{STATE[cloud.state].label}</Badge>
              {deployment?.provider === 'oci' ? `${deployment.shape ?? ''} ${deployment.region ?? ''}` : null}
            </p>
            <p className="text-sm text-slate-400">{PLATFORM_COMPONENTS.cloud.basis[cloud.state]}</p>
            {cloud.reasons.map((reason) => (
              <p key={reason} className="text-xs text-amber-200/90">
                {PLATFORM_REASON_TEXT[reason]}
              </p>
            ))}
            <p className="text-[11px] text-slate-500">
              Measured: {cloud.checkedAt === null ? 'not measured' : new Date(cloud.checkedAt).toLocaleString()}
            </p>
          </>
        )}
      </div>
      <div className="space-y-2 rounded-2xl border border-line bg-surface/90 p-5">
        <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-400">
          <Icon name="browser" className="size-4" />
          This build
        </p>
        <p className="text-lg font-semibold text-white">{environment}</p>
        <p className="text-sm text-slate-400">A label set when the client was built, not a verification.</p>
      </div>
      <div className="space-y-2 rounded-2xl border border-line bg-surface/90 p-5">
        <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-400">
          <Icon name="trust" className="size-4" />
          Cloud-security controls
        </p>
        <p className="flex flex-wrap gap-1.5">
          <Badge tone="info">{controls} designed</Badge>
          <Badge tone="accent">{configured} configured</Badge>
          <Badge tone="success">{verified} verified</Badge>
        </p>
        <p className="text-sm text-slate-400">
          Each control names the environment its configuration and evidence come from (local, CI or cloud).
        </p>
      </div>
    </section>
  );
}
