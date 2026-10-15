'use client';

import { SECURITY_METRICS, type SecurityMetricDefinition } from '@ciphermesh/shared';
import { securityDashboardResponseSchema, type SecurityDashboardResponse } from '@ciphermesh/validation';
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import { Icon } from '../components/icons';
import { Alert, Badge, Loading, SecondaryButton } from '../components/ui';
import { api, ApiError, describeError } from '../lib/api';
import { DeploymentDetails, PlatformComponents } from './platform-status';

/**
 * Platform security dashboard (Phase 14, CM-T061, CM-T062). The API decides who may see it (PA-01)
 * and computes every value; this view shows each value with its definition and the time it was
 * computed. No score, no traffic light: values that need action are highlighted individually.
 * The page fetches once and on request; it does not poll.
 */

type View =
  | { readonly kind: 'loading' }
  | { readonly kind: 'signed-out' }
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'failed'; readonly message: string }
  | { readonly kind: 'ready'; readonly data: SecurityDashboardResponse };

const nf = new Intl.NumberFormat('en');

function Metric({
  definition,
  values,
}: {
  readonly definition: SecurityMetricDefinition;
  readonly values: ReadonlyMap<string, number> | undefined;
}) {
  const attention = values !== undefined && (definition.attention ?? []).some((key) => (values.get(key) ?? 0) > 0);
  return (
    <article
      className={`space-y-3 rounded-xl border p-4 ${
        definition.availability === 'NOT_IMPLEMENTED'
          ? 'border-dashed border-slate-700 bg-slate-950/40'
          : attention
            ? 'border-amber-500/40 bg-amber-500/5'
            : 'border-line bg-surface/90'
      }`}
      data-testid={`metric-${definition.id}`}
    >
      <header className="flex items-start justify-between gap-2">
        <div>
          <p className="font-mono text-[11px] text-accent-300">{definition.id}</p>
          <h3 className="text-sm font-semibold text-white">{definition.title}</h3>
        </div>
        {definition.availability === 'NOT_IMPLEMENTED' ? (
          <Badge tone="neutral" icon="dashedCircle">
            Not implemented
          </Badge>
        ) : attention ? (
          <Badge tone="warning" icon="alert">
            Needs attention
          </Badge>
        ) : null}
      </header>
      {values === undefined ? (
        <p className="text-xs leading-relaxed text-slate-400">{definition.reason}</p>
      ) : (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
          {definition.values.map(({ key, label }) => (
            <div key={key}>
              <dt className="text-[11px] uppercase tracking-wide text-slate-500">{label}</dt>
              <dd className="tabular text-lg font-semibold text-white">{nf.format(values.get(key) ?? 0)}</dd>
            </div>
          ))}
        </dl>
      )}
      <p className="border-t border-slate-800 pt-2 text-[11px] leading-relaxed text-slate-500">
        Definition: {definition.definition}
      </p>
    </article>
  );
}

export function DashboardView() {
  const [view, setView] = useState<View>({ kind: 'loading' });

  const load = useCallback(async () => {
    setView({ kind: 'loading' });
    try {
      setView({ kind: 'ready', data: await api('GET', '/admin/security-dashboard', securityDashboardResponseSchema) });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) setView({ kind: 'signed-out' });
      else if (error instanceof ApiError && error.status === 404) setView({ kind: 'forbidden' });
      else setView({ kind: 'failed', message: describeError(error) });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (view.kind === 'loading') return <Loading label="Computing the aggregates…" />;
  if (view.kind === 'signed-out') {
    return (
      <Alert kind="info">
        Sign in with a platform administrator account to see the dashboard.{' '}
        <Link className="font-medium underline" href="/login">
          Sign in
        </Link>
      </Alert>
    );
  }
  if (view.kind === 'forbidden') {
    return (
      <Alert kind="info">
        This dashboard is available to platform administrators only. The server refused the request; nothing was
        computed for this account.
      </Alert>
    );
  }
  if (view.kind === 'failed') return <Alert kind="error">{view.message}</Alert>;

  const { data } = view;
  const byId = new Map(data.metrics.map((metric) => [metric.id, metric]));
  return (
    <div className="space-y-8" data-testid="security-dashboard">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-slate-400">
          Computed by the API at {new Date(data.computedAt).toLocaleString()} ({data.environment} environment).
          Aggregates only: no room names, content, member lists or per-user activity.
        </p>
        <SecondaryButton type="button" onClick={() => void load()}>
          <Icon name="rotate" className="size-4" />
          Compute again
        </SecondaryButton>
      </div>

      <section aria-label="Platform components" className="space-y-3">
        <h2 className="text-lg font-semibold text-white">Platform components</h2>
        <PlatformComponents platform={data.platform} />
      </section>

      {data.deployment === null ? null : (
        <section aria-label="Cloud deployment" className="space-y-3">
          <h2 className="text-lg font-semibold text-white">Cloud deployment</h2>
          <DeploymentDetails deployment={data.deployment} />
        </section>
      )}

      <section aria-label="Security metrics" className="space-y-3">
        <h2 className="text-lg font-semibold text-white">Security metrics</h2>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {SECURITY_METRICS.map((definition) => {
            const metric = byId.get(definition.id);
            const values =
              metric === undefined || metric.status !== 'AVAILABLE'
                ? undefined
                : new Map(metric.values.map((v) => [v.key, v.value]));
            return <Metric key={definition.id} definition={definition} values={values} />;
          })}
        </div>
      </section>
    </div>
  );
}
