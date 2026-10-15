'use client';

import { isOverdue, recordsOf, type IsmsRecordOf } from '@ciphermesh/shared';
import { useState } from 'react';
import { Badge, Card, DetailList, SecondaryButton } from '../components/ui';
import { EvidenceChip } from '../trust/ui';
import { createRecord } from './client';
import { useIsms } from './context';
import { linesOf, SpecForm, textOf } from './form-kit';
import {
  ExerciseBadge,
  fmtTime,
  GoLink,
  RecordLink,
  roleName,
  StatusBadge,
  statusLabel,
  TransitionPanel,
} from './parts';

/** Internal audit and self-assessment, nonconformity and corrective action (clauses 9.2, 10.2). */

const INDEPENDENCE_TEXT = {
  SELF_ASSESSMENT: 'Self-assessment: the project owner assesses their own work',
  SIMULATED_INTERNAL_AUDIT: 'Simulated internal audit: an educational exercise of the procedure',
  INTERNAL_AUDIT: 'Internal audit by an assigned auditor who did not plan it',
} as const;

export function AuditsSection() {
  const { state, run } = useIsms();
  const [planning, setPlanning] = useState(false);
  const audits = recordsOf(state.records, 'AUDIT');
  return (
    <div className="space-y-6" data-testid="isms-audits">
      <Card
        title="Internal audit and self-assessment (clause 9.2)"
        icon="evidence"
        description="Independence is declared, never inferred: this project has one person, so its audits are self-assessments or simulations. No external certification audit has taken place."
        actions={
          <SecondaryButton
            type="button"
            onClick={() => {
              setPlanning(true);
            }}
          >
            Plan an audit
          </SecondaryButton>
        }
      >
        {planning ? (
          <SpecForm
            testId="form-audit"
            submitLabel="Plan the audit"
            onCancel={() => {
              setPlanning(false);
            }}
            fields={[
              { name: 'title', label: 'Audit title', kind: 'text' },
              { name: 'scope', label: 'Audit scope', kind: 'textarea' },
              { name: 'objective', label: 'Objective', kind: 'textarea' },
              { name: 'criteria', label: 'Criteria (clauses or controls, for example 8.8 or 9.1)', kind: 'lines' },
              {
                name: 'scheduledFor',
                label: 'Scheduled date',
                kind: 'date',
                initial: state.now.toISOString().slice(0, 10),
              },
              {
                name: 'independence',
                label: 'Independence',
                kind: 'select',
                options: Object.entries(INDEPENDENCE_TEXT).map(([value, label]) => ({ value, label })),
                initial: 'SELF_ASSESSMENT',
              },
              {
                name: 'auditorUserId',
                label: 'Assigned auditor',
                kind: 'select',
                options: state.people.map((p) => ({ value: p.userId, label: p.name })),
              },
              { name: 'exercise', label: 'This is a demonstration exercise', kind: 'checkbox' },
            ]}
            onSubmit={async (values) => {
              await run(
                createRecord({
                  kind: 'AUDIT',
                  exercise: values['exercise'] === true,
                  input: {
                    title: textOf(values['title']),
                    scope: textOf(values['scope']),
                    objective: textOf(values['objective']),
                    criteria: linesOf(values['criteria']),
                    scheduledFor: textOf(values['scheduledFor']),
                    independence: textOf(values['independence']),
                    auditorUserId: textOf(values['auditorUserId']),
                  },
                }),
              );
              setPlanning(false);
            }}
          />
        ) : null}
        {audits.length === 0 ? (
          <p className="text-sm text-slate-400">
            No audit has been planned. None is shown as performed until it is recorded.
          </p>
        ) : (
          <ul className="space-y-3">
            {audits.map((audit) => (
              <AuditEntry key={audit.id} audit={audit} />
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function AuditEntry({ audit }: { readonly audit: IsmsRecordOf<'AUDIT'> }) {
  const d = audit.data;
  return (
    <li className="space-y-2 rounded-lg border border-slate-800 p-3" data-testid={`audit-${audit.code}`}>
      <p className="flex flex-wrap items-center gap-2 text-sm text-slate-200">
        <span className="font-mono text-xs text-accent-300">{audit.code}</span>
        {d.title}
        <StatusBadge status={audit.status} />
        <ExerciseBadge record={audit} />
        <Badge tone="neutral">{INDEPENDENCE_TEXT[d.independence]}</Badge>
      </p>
      <DetailList
        items={[
          { term: 'Scope', value: d.scope },
          { term: 'Objective', value: d.objective },
          { term: 'Criteria', value: d.criteria.join(', ') },
          { term: 'Scheduled', value: d.scheduledFor },
          {
            term: 'Planned by / auditor',
            value: `${d.plannedBy.name} / ${d.auditor.name}${d.plannedBy.userId === d.auditor.userId ? ' (the same person: not independent)' : ''}`,
          },
          ...(d.conclusion === undefined
            ? []
            : [{ term: 'Conclusion', value: `${d.conclusion} (${fmtTime(d.completedAt)})` }]),
        ]}
      />
      {d.checks.length === 0 ? null : (
        <ul className="space-y-1.5 border-t border-slate-800 pt-2">
          {d.checks.map((check, index) => (
            <li
              key={`${check.criterion}-${String(index)}`}
              className="flex flex-wrap items-center gap-2 text-xs text-slate-300"
            >
              <span className="font-mono text-accent-300">{check.criterion}</span>
              <Badge tone={check.result === 'CONFORMITY' ? 'success' : 'warning'}>{statusLabel(check.result)}</Badge>
              {check.note}
              {check.evidence.map((id) => (
                <EvidenceChip key={id} id={id} />
              ))}
              {check.finding === null ? null : <RecordLink code={check.finding} />}
              <span className="text-slate-500">
                {check.by.name}, {fmtTime(check.at)}
              </span>
            </li>
          ))}
        </ul>
      )}
      <TransitionPanel record={audit} />
    </li>
  );
}

const STAGES = [
  'OPEN',
  'ANALYZED',
  'ACTION_PLANNED',
  'ACTION_IMPLEMENTED',
  'AWAITING_EFFECTIVENESS',
  'CLOSED',
] as const;

function Stepper({ status }: { readonly status: string }) {
  const at = STAGES.indexOf(status as (typeof STAGES)[number]);
  return (
    <ol className="flex flex-wrap gap-1" aria-label="Corrective action lifecycle">
      {STAGES.map((stage, index) => (
        <li
          key={stage}
          aria-current={index === at ? 'step' : undefined}
          className={`rounded-md border px-2 py-1 text-[11px] ${
            index < at
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
              : index === at
                ? 'border-accent-400/60 bg-accent-500/15 text-white'
                : 'border-slate-800 text-slate-500'
          }`}
        >
          {statusLabel(stage)}
        </li>
      ))}
    </ol>
  );
}

export function ActionsSection() {
  const { state, item, go } = useIsms();
  const [showClosed, setShowClosed] = useState(true);
  // Withdrawn exercises are listed under Exercise records; a link to one still opens it.
  const findings = recordsOf(state.records, 'FINDING');
  const selected = recordsOf(state.records, 'FINDING', { includeWithdrawn: true }).find((f) => f.code === item);
  const shown = findings.filter((f) => showClosed || f.status !== 'CLOSED');
  return (
    <div className="space-y-6" data-testid="isms-actions">
      {selected === undefined ? null : <FindingDetail finding={selected} />}
      <Card
        title={`Findings and corrective actions (${String(findings.length)})`}
        icon="alert"
        description="No status can be set directly: each step is a named change with its own input, checked by the server (ISMS manual, section 10)."
        actions={
          <SecondaryButton
            type="button"
            onClick={() => {
              setShowClosed(!showClosed);
            }}
          >
            {showClosed ? 'Hide closed' : 'Show closed'}
          </SecondaryButton>
        }
      >
        {shown.length === 0 ? (
          <p className="text-sm text-slate-400">
            No finding. Findings come from audit checks, freshness checks, reviews and incidents.
          </p>
        ) : (
          <ul className="space-y-1.5">
            {shown.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-2 text-sm">
                <button
                  type="button"
                  className="font-mono text-xs text-accent-300 hover:underline"
                  onClick={() => {
                    go('actions', f.code);
                  }}
                >
                  {f.code}
                </button>
                <StatusBadge status={f.status} />
                <ExerciseBadge record={f} />
                <Badge tone="neutral">{statusLabel(f.data.classification)}</Badge>
                <span className="text-slate-300">{f.data.observation.slice(0, 120)}</span>
                {isOverdue(f, state.now) ? <Badge tone="danger">Overdue</Badge> : null}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function FindingDetail({ finding }: { readonly finding: IsmsRecordOf<'FINDING'> }) {
  const { state } = useIsms();
  const d = finding.data;
  return (
    <Card
      title={`${finding.code} ${statusLabel(d.classification)}`}
      icon="alert"
      tone={isOverdue(finding, state.now) ? 'danger' : 'default'}
      actions={
        <>
          <StatusBadge status={finding.status} />
          <ExerciseBadge record={finding} />
        </>
      }
    >
      <div className="space-y-4" data-testid={`finding-detail-${finding.code}`}>
        <Stepper status={finding.status} />
        <DetailList
          items={[
            {
              term: 'Source',
              value:
                d.source.ref === null ? (
                  statusLabel(d.source.type)
                ) : (
                  <span>
                    {statusLabel(d.source.type)}{' '}
                    {/^(AUD|MR|INC)-/.test(d.source.ref) ? <RecordLink code={d.source.ref} /> : d.source.ref}
                  </span>
                ),
            },
            { term: 'Criterion', value: d.criterion },
            { term: 'Observation', value: d.observation },
            {
              term: 'Evidence',
              value: (
                <span className="flex flex-wrap gap-1.5">
                  {d.evidence.length === 0 ? 'None cited' : d.evidence.map((id) => <EvidenceChip key={id} id={id} />)}
                </span>
              ),
            },
            { term: 'Responsible', value: roleName(d.responsible) },
            {
              term: 'Related risks and controls',
              value: (
                <span className="flex flex-wrap gap-2">
                  {d.relatedRisks.map((r) => (
                    <GoLink key={r} section="risks" item={r}>
                      {r}
                    </GoLink>
                  ))}
                  {d.relatedControls.map((c) => (
                    <GoLink key={c} section="assurance" item={c}>
                      {c}
                    </GoLink>
                  ))}
                </span>
              ),
            },
            ...(d.analysis === undefined
              ? []
              : [
                  {
                    term: 'Root cause',
                    value: `${d.analysis.rootCause} (${d.analysis.by.name}, ${fmtTime(d.analysis.at)})`,
                  },
                  {
                    term: 'Immediate correction',
                    value: d.analysis.correction === '' ? 'None' : d.analysis.correction,
                  },
                ]),
            ...(d.action === undefined
              ? []
              : [
                  {
                    term: 'Corrective action',
                    value: `${d.action.description} Owner ${roleName(d.action.owner)}, due ${d.action.dueDate}, planned ${fmtTime(d.action.plannedAt)}.`,
                  },
                ]),
            ...(d.implementation === undefined
              ? []
              : [
                  {
                    term: 'Implementation',
                    value: `${d.implementation.note} (${d.implementation.by.name}, ${fmtTime(d.implementation.at)})`,
                  },
                ]),
            ...(d.closureEvidence === undefined
              ? []
              : [
                  {
                    term: 'Closure evidence',
                    value: (
                      <span className="flex flex-wrap gap-2">
                        {d.closureEvidence.verifications.map((code) => (
                          <RecordLink key={code} code={code} />
                        ))}
                        {d.closureEvidence.evidence.map((id) => (
                          <EvidenceChip key={id} id={id} />
                        ))}
                      </span>
                    ),
                  },
                ]),
          ]}
        />
        {d.effectivenessChecks.length === 0 ? null : (
          <ul className="space-y-1 border-t border-slate-800 pt-2 text-xs text-slate-300">
            {d.effectivenessChecks.map((check, index) => (
              <li key={`${check.at}-${String(index)}`}>
                Effectiveness check: <strong>{statusLabel(check.result)}</strong> by {check.by.name} on{' '}
                {fmtTime(check.at)} (
                {check.independentOfImplementer
                  ? 'a different person from the implementer'
                  : 'self-verified: the implementer checked'}
                ). {check.note}
              </li>
            ))}
          </ul>
        )}
        <TransitionPanel record={finding} />
      </div>
    </Card>
  );
}
