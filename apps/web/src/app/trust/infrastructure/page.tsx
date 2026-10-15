import type { Metadata } from 'next';
import { Icon } from '../../../components/icons';
import { Badge, Card, PageHeader } from '../../../components/ui';
import { cloud } from '../../../trust/data';
import { CLOUD_CONTROLS, COMPONENTS, type CloudControl, type Scope } from '../../../trust/infrastructure';
import { LiveChecks } from '../../../trust/live-checks';
import { DocumentLink, EvidenceChips, SectionHeading } from '../../../trust/ui';
import { DeploymentStatus } from './deployment-status';

export const metadata: Metadata = { title: 'Deployment & infrastructure' };

/**
 * Deployment & Infrastructure (Phase 14 + Prompt 16.5, CM-T061). Shows the designed cloud
 * architecture, what this browser can observe right now, and a control register that keeps
 * design, configuration and verification apart, each with the environment it was shown in (local,
 * CI or cloud). The live cloud state comes from the API (DeploymentStatus), for administrators only.
 */

const EXPOSURE = {
  public: { tone: 'warning', label: 'Public' },
  private: { tone: 'success', label: 'Private' },
  none: { tone: 'success', label: 'No inbound' },
} as const;

const SCOPE_LABEL: Readonly<Record<Scope, string>> = { local: 'local', ci: 'CI', cloud: 'cloud' };

function ControlRow({ control }: { readonly control: CloudControl }) {
  const { configuration, verification } = control;
  return (
    <li
      className="grid gap-3 px-4 py-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]"
      data-testid="cloud-control"
    >
      <div className="flex items-start gap-3">
        <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-slate-800/80 text-accent-300">
          <Icon name={control.icon} className="size-4" />
        </span>
        <span className="text-sm font-medium text-white">{control.name}</span>
      </div>
      <div className="space-y-1 text-xs">
        <Badge tone="info" icon="layers">
          Designed
        </Badge>
        <p className="text-slate-400">{control.design.text}</p>
        <DocumentLink path={control.design.source}>{control.design.source.split('/').pop()}</DocumentLink>
      </div>
      <div className="space-y-1 text-xs">
        {configuration.state === 'configured' ? (
          <Badge tone="accent" icon="settings">
            Configured ({SCOPE_LABEL[configuration.scope]})
          </Badge>
        ) : (
          <Badge tone="neutral" icon="dashedCircle">
            Not configured
          </Badge>
        )}
        <p className="text-slate-400">{configuration.text}</p>
        {configuration.state === 'configured' ? (
          <p className="flex flex-wrap gap-x-2">
            {configuration.sources.map((source) => (
              <DocumentLink key={source} path={source}>
                {source.split('/').pop()}
              </DocumentLink>
            ))}
          </p>
        ) : null}
      </div>
      <div className="space-y-1 text-xs">
        {verification.state === 'verified' ? (
          <Badge tone="success" icon="checkCircle">
            Verified ({SCOPE_LABEL[verification.scope]})
          </Badge>
        ) : (
          <Badge tone="warning" icon="minusCircle">
            Not verified
          </Badge>
        )}
        <p className="text-slate-400">{verification.text}</p>
        <EvidenceChips ids={verification.state === 'verified' ? verification.evidence : verification.planned} />
      </div>
    </li>
  );
}

export default function InfrastructurePage() {
  const configured = CLOUD_CONTROLS.filter((c) => c.configuration.state === 'configured').length;
  const verified = CLOUD_CONTROLS.filter((c) => c.verification.state === 'verified').length;
  return (
    <div className="space-y-14">
      <PageHeader
        eyebrow="Cloud & cloud security"
        title="Deployment & infrastructure"
        description="The deployment CipherMesh is designed for (an IaaS VM with Nginx and Docker, managed PostgreSQL as PaaS, provider-managed object storage), what this browser can observe now, and which cloud-security controls are designed, configured and verified."
      />

      <DeploymentStatus controls={CLOUD_CONTROLS.length} configured={configured} verified={verified} />

      <section className="space-y-5">
        <SectionHeading id="architecture" eyebrow="Architecture" title="Components and trust boundaries">
          Only Nginx is reachable from the internet. The API, the worker, the database and the object storage are
          private; browsers reach single storage objects through short-lived presigned URLs. Source:{' '}
          <DocumentLink path="docs/cloud/deployment-architecture.md">deployment-architecture.md</DocumentLink>
        </SectionHeading>
        <div className="grid gap-4 rounded-2xl border border-line bg-surface/80 p-5 lg:grid-cols-[minmax(0,0.8fr)_auto_minmax(0,0.9fr)_auto_minmax(0,2.3fr)]">
          {(
            [
              { title: 'Internet', ids: ['browser'] },
              { title: 'Public edge on the VM', ids: ['nginx'] },
              { title: 'Private services', ids: ['api', 'worker', 'postgres', 'storage'] },
            ] as const
          ).map((zone, index) => (
            <div key={zone.title} className="contents">
              {index > 0 ? (
                <div className="flex items-center justify-center text-slate-500" aria-hidden="true">
                  <Icon name="arrowRight" className="size-5 rotate-90 lg:rotate-0" />
                </div>
              ) : null}
              <div className="space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{zone.title}</p>
                <ul className={`grid gap-2 ${zone.ids.length > 1 ? 'sm:grid-cols-2' : ''}`}>
                  {zone.ids.map((id) => {
                    const component = COMPONENTS.find((c) => c.id === id);
                    if (component === undefined) return null;
                    const exposure = EXPOSURE[component.exposure];
                    return (
                      <li key={id} className="space-y-2 rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="flex items-center gap-2 text-sm font-medium text-white">
                            <Icon name={component.icon} className="size-4 text-accent-300" />
                            {component.name}
                          </span>
                          <Badge tone={exposure.tone}>{exposure.label}</Badge>
                        </div>
                        <p className="text-xs text-slate-400">{component.role}</p>
                        <p className="text-[11px] text-slate-500">
                          {component.model} · locally: {component.local}
                        </p>
                      </li>
                    );
                  })}
                </ul>
              </div>
            </div>
          ))}
        </div>
        <div className="overflow-x-auto rounded-xl border border-line">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <caption className="sr-only">Designed network exposure</caption>
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Endpoint
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Exposed to
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Port
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Notes
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {cloud.exposure.map((row) => (
                <tr key={row.endpoint}>
                  <th scope="row" className="px-4 py-2.5 font-medium text-white">
                    {row.endpoint}
                  </th>
                  <td className="px-4 py-2.5 text-slate-300">{row.exposedTo}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-300">{row.port}</td>
                  <td className="px-4 py-2.5 text-slate-400">{row.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-5">
        <SectionHeading id="live" eyebrow="Observed now" title="Live checks from this browser">
          What any visitor can verify about the server that delivered this page.
        </SectionHeading>
        <Card title="This deployment" icon="globe">
          <LiveChecks />
        </Card>
      </section>

      <section className="space-y-5">
        <SectionHeading id="controls" eyebrow="Control register" title="Designed, configured, verified">
          A control is “configured” only when a file in this repository implements it, and “verified” only when a
          captured evidence item shows it working, in the environment named. Nothing is claimed for the cloud before it
          exists.
        </SectionHeading>
        <div className="hidden grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)] gap-3 px-4 text-xs font-medium uppercase tracking-wide text-slate-500 lg:grid">
          <span>Control</span>
          <span>Design</span>
          <span>Configuration</span>
          <span>Verification</span>
        </div>
        <ul className="divide-y divide-slate-800 overflow-hidden rounded-xl border border-line bg-surface/80">
          {CLOUD_CONTROLS.map((control) => (
            <ControlRow key={control.id} control={control} />
          ))}
        </ul>
      </section>

      <section className="space-y-5">
        <SectionHeading id="responsibility" eyebrow="Shared responsibility" title="Who secures what">
          P: provider. C: the CipherMesh team. S: shared (the provider supplies it, the team configures and verifies
          it). Source: <DocumentLink path="docs/cloud/shared-responsibility.md">shared-responsibility.md</DocumentLink>
        </SectionHeading>
        <div className="overflow-x-auto rounded-xl border border-line">
          <table className="w-full min-w-[56rem] text-left text-sm">
            <caption className="sr-only">Shared-responsibility matrix</caption>
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Layer
                </th>
                {cloud.services.map((service) => (
                  <th key={service} scope="col" className="px-4 py-2.5 font-medium">
                    {service}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {cloud.layers.map((row) => (
                <tr key={row.layer}>
                  <th scope="row" className="px-4 py-2.5 font-medium text-white">
                    {row.layer}
                  </th>
                  {row.owners.map((owner, index) => (
                    <td key={`${row.layer}-${String(index)}`} className="px-4 py-2.5 text-xs text-slate-300">
                      {owner}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
