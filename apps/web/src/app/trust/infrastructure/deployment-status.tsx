'use client';

import { PLATFORM_COMPONENTS } from '@ciphermesh/shared';
import { Icon } from '../../../components/icons';
import { Badge } from '../../../components/ui';
import { publicEnv } from '../../../config/public-env';

/**
 * The deployment status card. The cloud deployment is not connected: the label comes from the
 * shared platform contract (PLATFORM_COMPONENTS.cloud), which the cloud workstream will connect to
 * the provider. The environment shown is the build-time label, stated as such.
 */
export function DeploymentStatus({
  controls,
  configured,
  verified,
}: {
  readonly controls: number;
  readonly configured: number;
  readonly verified: number;
}) {
  const environment =
    publicEnv.deploymentEnvironment === 'development' ? 'Development build' : 'Cloud demonstration build';
  return (
    <section aria-label="Deployment status" className="grid gap-4 md:grid-cols-3" data-testid="deployment-status">
      <div className="space-y-2 rounded-2xl border border-amber-500/30 bg-amber-500/5 p-5">
        <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-amber-200/90">
          <Icon name="cloud" className="size-4" />
          Cloud deployment
        </p>
        <p className="text-lg font-semibold text-white">Not connected</p>
        <p className="text-sm text-slate-400">{PLATFORM_COMPONENTS.cloud.basis.NOT_CONNECTED}</p>
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
        <p className="text-sm text-slate-400">Configured and verified locally or in CI only; none in the cloud yet.</p>
      </div>
    </section>
  );
}
