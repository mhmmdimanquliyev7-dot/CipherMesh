'use client';

import {
  allControlAssurance,
  computeMetrics,
  ISMS_CATALOGUE,
  policyState,
  recordsOf,
  riskView,
  scopeState,
  isOverdue,
  type PolicyState,
} from '@ciphermesh/shared';
import { useMemo, useState } from 'react';
import { Badge, Card, DetailList, EmptyState, SecondaryButton, Stat } from '../components/ui';
import { DocumentLink } from '../trust/ui';
import { createDecision } from './client';
import { useIsms, type SectionId } from './context';
import { SpecForm, textOf } from './form-kit';
import { ExerciseBadge, fmtTime, GoLink, RatingBadge, roleName, StatusBadge } from './parts';

/** Overview, scope and context, assets, policies and roles (clauses 4, 5 and 6.2; controls 5.1, 5.2, 5.9). */

function useComputed() {
  const { state } = useIsms();
  return useMemo(() => {
    const counted = state.records.filter((r) => r.status !== 'WITHDRAWN');
    const assurance = allControlAssurance(counted, state.now);
    const views = ISMS_CATALOGUE.risks.map((risk) => riskView(risk, counted));
    return { counted, assurance, views, metrics: computeMetrics(state.records, state.now) };
  }, [state]);
}

const LIFECYCLE: readonly { readonly section: SectionId; readonly label: string; readonly clause: string }[] = [
  { section: 'context', label: 'Context & scope', clause: '4' },
  { section: 'assets', label: 'Assets', clause: '5.9' },
  { section: 'risks', label: 'Risk assessment', clause: '6.1.2' },
  { section: 'treatment', label: 'Treatment', clause: '6.1.3' },
  { section: 'soa', label: 'Controls (SoA)', clause: '6.1.3 d' },
  { section: 'assurance', label: 'Verification & evidence', clause: '9.1' },
  { section: 'audits', label: 'Audit', clause: '9.2' },
  { section: 'actions', label: 'Corrective action', clause: '10.2' },
  { section: 'review', label: 'Management review', clause: '9.3' },
  { section: 'improvement', label: 'Improvement', clause: '10.1' },
];

export function OverviewSection() {
  const { state, go } = useIsms();
  const { counted, assurance, views, metrics } = useComputed();
  const applicable = assurance.filter((a) => a.applicability === 'APPLICABLE');
  const verified = applicable.filter((a) => a.state === 'VERIFIED');
  const findings = recordsOf(counted, 'FINDING');
  const openFindings = findings.filter((f) => f.status !== 'CLOSED');
  const overdue = findings.filter((f) => isOverdue(f, state.now));
  const decisions = [
    ...recordsOf(counted, 'RISK_ASSESSMENT').filter((r) => r.status === 'TREATMENT_VERIFIED'),
    ...findings.filter((f) => f.status === 'AWAITING_EFFECTIVENESS'),
    ...recordsOf(counted, 'MANAGEMENT_REVIEW').filter((r) => r.status === 'DRAFT'),
    ...recordsOf(counted, 'INCIDENT').filter((r) => r.status === 'RESOLVED'),
  ];
  const scope = scopeState(counted, state.now);
  const lastVerification = recordsOf(counted, 'CONTROL_VERIFICATION')[0];
  const policies = ISMS_CATALOGUE.policies.map((p) => policyState(p, counted, state.now));
  const byRating = (pick: 'inherent' | 'residual') =>
    (['Critical', 'High', 'Medium', 'Low'] as const).map(
      (rating) => [rating, views.filter((v) => v[pick] === rating).length] as const,
    );
  const exercises = state.records.filter((r) => r.exercise && r.status !== 'WITHDRAWN').length;

  return (
    <div className="space-y-6" data-testid="isms-overview">
      <Card
        title="How this ISMS operates"
        icon="governance"
        description="Each step is a stored record made by an authenticated person; select a step to open it."
      >
        <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          {LIFECYCLE.map((step, index) => (
            <li key={step.section}>
              <button
                type="button"
                onClick={() => {
                  go(step.section);
                }}
                className="w-full rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-left hover:border-accent-400/50"
              >
                <span className="font-mono text-[11px] text-accent-300">
                  {String(index + 1).padStart(2, '0')} · clause {step.clause}
                </span>
                <span className="mt-1 block text-sm font-medium text-white">{step.label}</span>
              </button>
            </li>
          ))}
        </ol>
        <p className="text-xs leading-relaxed text-slate-500">
          A written policy is not an implemented control, an implemented control is not verified until a verification
          record shows it, and a passing test is evidence for one control, not certification. Records marked EXERCISE
          are labelled demonstrations ({exercises} active).
        </p>
      </Card>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="ISMS scope"
          icon="governance"
          value={`Revision ${String(ISMS_CATALOGUE.scope.revision)}`}
          detail={
            scope.latest === undefined
              ? 'No scope review recorded yet'
              : `Reviewed ${fmtTime(scope.latest.createdAt)}: ${scope.state.replace(/_/g, ' ').toLowerCase()}`
          }
        />
        <Stat
          label="Risks in the register"
          icon="risk"
          value={views.length}
          detail={`${String(metrics.find((m) => m.id === 'M-02')?.numerator ?? 0)} with a verified treatment or accepted residual`}
        />
        <Stat
          label="Applicable controls verified"
          icon="checkCircle"
          value={`${String(verified.length)} of ${String(applicable.length)}`}
          detail={`${String(applicable.length - verified.length)} rows awaiting a current verification`}
        />
        <Stat
          label="Open findings"
          icon="alert"
          value={openFindings.length}
          detail={`${String(overdue.length)} corrective action(s) overdue`}
        />
        <Stat
          label="Outstanding decisions"
          icon="signature"
          value={decisions.length}
          detail="Acceptances, closures, reviews and incident closures awaiting PA-08"
        />
        <Stat
          label="Policies effective"
          icon="evidence"
          value={`${String(policies.filter((p) => p.state === 'EFFECTIVE').length)} of ${String(policies.length)}`}
          detail={`${String(policies.filter((p) => p.state === 'DOCUMENTED').length)} documented but not yet adopted`}
        />
        <Stat
          label="Last verification recorded"
          icon="clock"
          value={lastVerification === undefined ? 'None' : lastVerification.code}
          detail={
            lastVerification === undefined ? 'No control verified in the ISMS yet' : fmtTime(lastVerification.createdAt)
          }
        />
        <Stat
          label="Management review"
          icon="members"
          value={metrics.find((m) => m.id === 'M-07')?.display ?? ''}
          detail="Days since the last recorded review"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title="Risk severity (current assessment)"
          icon="risk"
          description="Computed from the register and dated re-assessments with the threat model's 3x3 matrix."
        >
          <DetailList
            items={byRating('inherent').map(([rating, count]) => ({
              term: `Inherent ${rating}`,
              value: (
                <span className="flex items-center gap-2">
                  <RatingBadge rating={rating} /> {count}
                </span>
              ),
            }))}
          />
          <DetailList
            items={byRating('residual').map(([rating, count]) => ({
              term: `Residual ${rating}`,
              value: String(count),
            }))}
          />
        </Card>
        <Card
          title="Measured objectives (clause 9.1)"
          icon="overview"
          description="Definitions from the ISMS manual, section 12; computed when this page loaded."
        >
          <ul className="space-y-2" data-testid="isms-metrics">
            {metrics.map((metric) => {
              const definition = ISMS_CATALOGUE.metrics.find((m) => m.id === metric.id);
              return (
                <li key={metric.id} className="rounded-lg border border-slate-800 p-3">
                  <p className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="text-sm text-slate-200">
                      <span className="mr-2 font-mono text-xs text-accent-300">{metric.id}</span>
                      {definition?.objective}
                    </span>
                    <span className="tabular text-sm font-semibold text-white">{metric.display}</span>
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    {definition?.calculation} Target: {definition?.target}. Limitation: {definition?.limitation}
                  </p>
                </li>
              );
            })}
          </ul>
        </Card>
      </div>
    </div>
  );
}

const SCOPE_LABEL: Readonly<Record<string, string>> = {
  NOT_REVIEWED: 'Not reviewed in the ISMS yet',
  CONFIRMED: 'Confirmed',
  CHANGES_REQUIRED: 'Changes required',
  REVIEW_DUE: 'Review due',
  CHANGED_SINCE_REVIEW: 'Changed since the last review',
};

export function ContextSection() {
  const { state, run } = useIsms();
  const [deciding, setDeciding] = useState(false);
  const scope = scopeState(state.records, state.now);
  const reviews = recordsOf(state.records, 'SCOPE_REVIEW');
  return (
    <div className="space-y-6" data-testid="isms-context">
      <Card
        title={`ISMS scope, revision ${String(ISMS_CATALOGUE.scope.revision)}`}
        icon="governance"
        description={
          <>
            Source: <DocumentLink path="docs/security/isms-control-mapping.md">isms-control-mapping.md</DocumentLink>{' '}
            section 1. Fingerprint {ISMS_CATALOGUE.scope.fingerprint.slice(0, 16)}… (SHA-256 of the text).
          </>
        }
        actions={<Badge tone={scope.state === 'CONFIRMED' ? 'success' : 'warning'}>{SCOPE_LABEL[scope.state]}</Badge>}
      >
        <p className="text-sm leading-relaxed text-slate-200">{ISMS_CATALOGUE.scope.text}</p>
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="py-1 pr-3">ID</th>
              <th className="py-1 pr-3">Boundary</th>
              <th className="py-1 pr-3">Element</th>
              <th className="py-1">Reason</th>
            </tr>
          </thead>
          <tbody>
            {ISMS_CATALOGUE.boundaries.map((b) => (
              <tr key={b.id} className="border-t border-slate-800 align-top">
                <td className="py-1.5 pr-3 font-mono text-xs text-accent-300">{b.id}</td>
                <td className="py-1.5 pr-3 text-slate-300">{b.boundary}</td>
                <td className="py-1.5 pr-3 text-slate-200">{b.element}</td>
                <td className="py-1.5 text-slate-400">{b.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-white">Scope reviews</h3>
          {reviews.length === 0 ? (
            <p className="text-sm text-slate-400">
              No scope review has been recorded. None is shown as done until one is.
            </p>
          ) : (
            <ul className="space-y-1 text-sm">
              {reviews.map((r) => (
                <li key={r.id} className="flex flex-wrap items-center gap-2 text-slate-300">
                  <span className="font-mono text-xs text-accent-300">{r.code}</span>
                  <StatusBadge status={r.status} />
                  <ExerciseBadge record={r} />
                  revision {r.data.scopeRevision}, {r.data.decision.toLowerCase().replace(/_/g, ' ')} by{' '}
                  {r.createdBy.name} on {fmtTime(r.createdAt)}; next review {r.data.nextReviewDate}. {r.data.reason}
                </li>
              ))}
            </ul>
          )}
          {deciding ? (
            <SpecForm
              testId="form-scope-review"
              submitLabel="Record the scope review"
              intro="A decision (PA-08). The reviewed revision and its fingerprint are recorded with your name and the server's time."
              onCancel={() => {
                setDeciding(false);
              }}
              fields={[
                {
                  name: 'decision',
                  label: 'Decision',
                  kind: 'select',
                  options: [
                    { value: 'CONFIRMED', label: 'Confirmed: the scope matches the system' },
                    { value: 'CHANGES_REQUIRED', label: 'Changes required' },
                  ],
                },
                { name: 'nextReviewDate', label: 'Next review date', kind: 'date' },
                { name: 'reason', label: 'Reason', kind: 'textarea' },
                { name: 'exercise', label: 'This is a demonstration exercise', kind: 'checkbox' },
              ]}
              onSubmit={async (values) => {
                await run(
                  createDecision({
                    kind: 'SCOPE_REVIEW',
                    exercise: values['exercise'] === true,
                    input: {
                      decision: textOf(values['decision']),
                      nextReviewDate: textOf(values['nextReviewDate']),
                      reason: textOf(values['reason']),
                    },
                  }),
                );
                setDeciding(false);
              }}
            />
          ) : (
            <SecondaryButton
              type="button"
              onClick={() => {
                setDeciding(true);
              }}
            >
              Record a scope review (decision)
            </SecondaryButton>
          )}
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Internal and external issues (clause 4.1)" icon="layers">
          <ul className="space-y-2 text-sm">
            {ISMS_CATALOGUE.issues.map((issue) => (
              <li key={issue.id} className="rounded-lg border border-slate-800 p-2.5">
                <p className="text-slate-200">
                  <span className="mr-2 font-mono text-xs text-accent-300">{issue.id}</span>
                  <Badge tone={issue.type === 'Internal' ? 'info' : 'violet'}>{issue.type}</Badge> {issue.issue}
                </p>
                <p className="mt-1 text-xs text-slate-400">{issue.effect}</p>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Interested parties (clause 4.2)" icon="members">
          <ul className="space-y-2 text-sm">
            {ISMS_CATALOGUE.parties.map((party) => (
              <li key={party.id} className="rounded-lg border border-slate-800 p-2.5">
                <p className="text-slate-200">
                  <span className="mr-2 font-mono text-xs text-accent-300">{party.id}</span>
                  {party.party}
                </p>
                <p className="mt-1 text-xs text-slate-400">Expects: {party.requirements}</p>
                <p className="text-xs text-slate-500">Addressed by: {party.response}</p>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <Card
        title="Information security objectives (clause 6.2)"
        icon="checkCircle"
        description="Security goals G1 to G7 of the system overview; their measurement is in the Overview."
      >
        <DetailList items={ISMS_CATALOGUE.objectives.map((g) => ({ term: g.id, value: `${g.goal}. ${g.how}` }))} />
      </Card>
    </div>
  );
}

export function AssetsSection() {
  const { state } = useIsms();
  const risksOf = (assetId: string) => ISMS_CATALOGUE.risks.filter((r) => r.assets.includes(assetId)).map((r) => r.id);
  return (
    <Card
      title={`Asset inventory (${String(ISMS_CATALOGUE.assets.length)} assets)`}
      icon="database"
      description={
        <>
          Source: <DocumentLink path="docs/threat-model/threat-model.md">threat-model.md</DocumentLink> section 2
          (control 5.9). Related risks are those whose threat model section names the asset.
        </>
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[56rem] text-left text-sm" data-testid="isms-assets">
          <thead className="text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="py-1 pr-3">ID</th>
              <th className="py-1 pr-3">Asset</th>
              <th className="py-1 pr-3">Category</th>
              <th className="py-1 pr-3">Owner</th>
              <th className="py-1 pr-3">C / I / A</th>
              <th className="py-1 pr-3">Where</th>
              <th className="py-1">Related risks</th>
            </tr>
          </thead>
          <tbody>
            {ISMS_CATALOGUE.assets.map((asset) => (
              <tr key={asset.id} className="border-t border-slate-800 align-top">
                <td className="py-1.5 pr-3 font-mono text-xs text-accent-300">{asset.id}</td>
                <td className="py-1.5 pr-3 text-slate-200">{asset.asset}</td>
                <td className="py-1.5 pr-3 text-slate-400">{asset.category}</td>
                <td className="py-1.5 pr-3 text-slate-400">{asset.owner}</td>
                <td className="py-1.5 pr-3 text-slate-300">
                  {asset.confidentiality} / {asset.integrity} / {asset.availability}
                </td>
                <td className="py-1.5 pr-3 text-xs text-slate-400">{asset.location}</td>
                <td className="py-1.5">
                  <span className="flex flex-wrap gap-1.5">
                    {risksOf(asset.id).map((id) => (
                      <GoLink key={id} section="risks" item={id}>
                        {id}
                      </GoLink>
                    ))}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-slate-500">
        Inventory as documented; {state.records.length} ISMS record(s) reference it.
      </p>
    </Card>
  );
}

const POLICY_TONE: Readonly<Record<PolicyState, 'success' | 'warning' | 'neutral' | 'info'>> = {
  EFFECTIVE: 'success',
  REVIEW_DUE: 'warning',
  CHANGED_SINCE_APPROVAL: 'warning',
  UNDER_REVISION: 'info',
  DOCUMENTED: 'neutral',
  RETIRED: 'neutral',
};

export function PoliciesSection() {
  const { state, run, item } = useIsms();
  const [deciding, setDeciding] = useState<string | undefined>(item?.startsWith('POL-') === true ? item : undefined);
  return (
    <div className="space-y-6" data-testid="isms-policies">
      <Card
        title="Policy register (clause 5.2, control 5.1)"
        icon="evidence"
        description="The lifecycle is computed from policy decisions and the document's current fingerprint: a document that changed after its adoption needs a new review."
      >
        <ul className="space-y-2">
          {ISMS_CATALOGUE.policies.map((policy) => {
            const { state: lifecycle, latest } = policyState(policy, state.records, state.now);
            return (
              <li
                key={policy.id}
                className="space-y-2 rounded-lg border border-slate-800 p-3"
                data-testid={`policy-${policy.id}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm text-slate-200">
                    <span className="mr-2 font-mono text-xs text-accent-300">{policy.id}</span>
                    {policy.title}
                  </p>
                  <Badge tone={POLICY_TONE[lifecycle]}>{lifecycle.replace(/_/g, ' ').toLowerCase()}</Badge>
                </div>
                <p className="text-xs text-slate-400">
                  <DocumentLink path={policy.path}>{policy.path}</DocumentLink> · owner {roleName(policy.owner)} ·
                  review every {policy.reviewDays} days · controls {policy.controls.join(', ')} · risks{' '}
                  {policy.risks.map((r) => (
                    <GoLink key={r} section="risks" item={r}>
                      {r}{' '}
                    </GoLink>
                  ))}
                </p>
                <p className="text-xs text-slate-500">
                  {latest === undefined
                    ? 'No adoption or review recorded.'
                    : `${latest.code}: ${latest.data.decision.replace(/_/g, ' ').toLowerCase()} by ${latest.createdBy.name} on ${fmtTime(latest.createdAt)}, effective ${latest.data.effectiveFrom}, next review ${latest.data.nextReviewDate}${latest.exercise ? ' (exercise)' : ''}. ${latest.data.note}`}
                </p>
                {deciding === policy.id ? (
                  <SpecForm
                    testId="form-policy-review"
                    submitLabel="Record the policy decision"
                    intro="A decision (PA-08): the reviewed document fingerprint is recorded with your name."
                    onCancel={() => {
                      setDeciding(undefined);
                    }}
                    fields={[
                      {
                        name: 'decision',
                        label: 'Decision',
                        kind: 'select',
                        options: [
                          { value: 'ADOPTED', label: 'Adopted' },
                          { value: 'REVIEWED_NO_CHANGE', label: 'Reviewed, no change' },
                          { value: 'CHANGES_REQUIRED', label: 'Changes required' },
                          { value: 'RETIRED', label: 'Retired' },
                        ],
                      },
                      {
                        name: 'effectiveFrom',
                        label: 'Effective from',
                        kind: 'date',
                        initial: state.now.toISOString().slice(0, 10),
                      },
                      { name: 'nextReviewDate', label: 'Next review date', kind: 'date' },
                      { name: 'note', label: 'Note', kind: 'textarea' },
                      { name: 'exercise', label: 'This is a demonstration exercise', kind: 'checkbox' },
                    ]}
                    onSubmit={async (values) => {
                      await run(
                        createDecision({
                          kind: 'POLICY_REVIEW',
                          ref: policy.id,
                          exercise: values['exercise'] === true,
                          input: {
                            decision: textOf(values['decision']),
                            effectiveFrom: textOf(values['effectiveFrom']),
                            nextReviewDate: textOf(values['nextReviewDate']),
                            note: textOf(values['note']),
                          },
                        }),
                      );
                      setDeciding(undefined);
                    }}
                  />
                ) : (
                  <SecondaryButton
                    type="button"
                    onClick={() => {
                      setDeciding(policy.id);
                    }}
                  >
                    Review {policy.id} (decision)
                  </SecondaryButton>
                )}
              </li>
            );
          })}
        </ul>
      </Card>
      <Card
        title="Roles and responsibilities (clause 5.3, control 5.2)"
        icon="members"
        description="Every role is held by the project owner; no record claims independence."
      >
        {ISMS_CATALOGUE.roles.length === 0 ? (
          <EmptyState icon="members" title="No roles documented" />
        ) : (
          <ul className="space-y-2 text-sm">
            {ISMS_CATALOGUE.roles.map((role) => (
              <li key={role.id} className="rounded-lg border border-slate-800 p-2.5">
                <p className="text-slate-200">
                  <span className="mr-2 font-mono text-xs text-accent-300">{role.id}</span>
                  {role.role} · <span className="text-slate-400">{role.heldBy}</span>
                </p>
                <p className="mt-1 text-xs text-slate-400">{role.responsibilities}</p>
                <p className="text-xs text-slate-500">{role.permission}</p>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
