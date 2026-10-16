'use client';

import {
  controlAssurance,
  controlById,
  ISMS_CATALOGUE,
  ISMS_LEVELS,
  recordsOf,
  riskMatrix,
  riskRating,
  riskView,
  type IsmsLevel,
  type RiskView,
} from '@ciphermesh/shared';
import { useMemo, useState } from 'react';
import { Badge, Card, DetailList, SecondaryButton } from '../components/ui';
import { DocumentLink, LimitationChip } from '../trust/ui';
import { createRecord } from './client';
import { useIsms } from './context';
import { linesOf, SpecForm, textOf, LEVEL_OPTIONS } from './form-kit';
import {
  AssuranceBadge,
  ExerciseBadge,
  fmtTime,
  GoLink,
  RatingBadge,
  ROLE_OPTIONS,
  StatusBadge,
  statusLabel,
  TransitionPanel,
} from './parts';

/** Risk register, assessment and treatment (clauses 6.1.2, 6.1.3, 8.2, 8.3). */

const CELL_CLASS: Readonly<Record<string, string>> = {
  Low: 'border-emerald-500/30 bg-emerald-500/10',
  Medium: 'border-sky-500/30 bg-sky-500/10',
  High: 'border-amber-500/40 bg-amber-500/10',
  Critical: 'border-rose-500/40 bg-rose-500/15',
};

function HeatMap({
  views,
  basis,
  onCell,
}: {
  readonly views: readonly RiskView[];
  readonly basis: 'inherent' | 'residual';
  readonly onCell: (likelihood: IsmsLevel, impact: IsmsLevel) => void;
}) {
  // Residual: the residual rating is placed on the row and column of the same rating's cell
  // only when a residual assessment exists; otherwise the register's inherent position is shown.
  const placed =
    basis === 'inherent'
      ? views
      : views.map((v) => {
          const residual = v.assessment?.data.residual;
          return residual === undefined ? v : { ...v, likelihood: residual.likelihood, impact: residual.impact };
        });
  const matrix = riskMatrix(placed);
  return (
    <div className="space-y-2" data-testid={`heatmap-${basis}`}>
      <div className="grid grid-cols-[auto_repeat(3,minmax(0,1fr))] gap-1.5 text-center text-xs">
        <span />
        {ISMS_LEVELS.map((impact) => (
          <span key={impact} className="text-slate-500">
            Impact {impact}
          </span>
        ))}
        {[...ISMS_LEVELS].reverse().map((likelihood) => (
          <div key={likelihood} className="contents">
            <span className="self-center pr-1 text-right text-slate-500">Likelihood {likelihood}</span>
            {ISMS_LEVELS.map((impact) => (
              <button
                key={impact}
                type="button"
                onClick={() => {
                  onCell(likelihood, impact);
                }}
                aria-label={`${String(matrix[likelihood][impact])} risks with likelihood ${likelihood} and impact ${impact}`}
                className={`rounded-md border py-3 ${CELL_CLASS[riskRating(likelihood, impact)] ?? ''}`}
              >
                <span className="tabular text-lg font-semibold text-white">{matrix[likelihood][impact]}</span>
                <span className="block text-[10px] text-slate-400">{riskRating(likelihood, impact)}</span>
              </button>
            ))}
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-500">
        {basis === 'inherent'
          ? 'Inherent position: the register, or a dated re-assessment where one exists.'
          : 'Residual position where a verified treatment recorded one; other risks stay at their assessed position (their documented residual rating is in the register).'}
      </p>
    </div>
  );
}

export function RisksSection() {
  const { state, item, go } = useIsms();
  const [basis, setBasis] = useState<'inherent' | 'residual'>('inherent');
  const [cell, setCell] = useState<{ likelihood: IsmsLevel; impact: IsmsLevel } | undefined>();
  const views = useMemo(() => ISMS_CATALOGUE.risks.map((risk) => riskView(risk, state.records)), [state.records]);
  const selected = item === undefined ? undefined : views.find((v) => v.risk.id === item);
  const shown =
    cell === undefined ? views : views.filter((v) => v.likelihood === cell.likelihood && v.impact === cell.impact);

  return (
    <div className="space-y-6" data-testid="isms-risks">
      {selected === undefined ? null : <RiskDetail view={selected} />}
      <Card
        title="Risk matrix"
        icon="risk"
        description={
          <>
            Method: <DocumentLink path="docs/threat-model/threat-model.md">threat-model.md</DocumentLink> section 1
            (likelihood and impact Low, Medium, High). Select a cell to filter the register.
          </>
        }
        actions={
          <div className="flex gap-1.5">
            <SecondaryButton
              type="button"
              onClick={() => {
                setBasis('inherent');
              }}
              aria-pressed={basis === 'inherent'}
            >
              Inherent
            </SecondaryButton>
            <SecondaryButton
              type="button"
              onClick={() => {
                setBasis('residual');
              }}
              aria-pressed={basis === 'residual'}
            >
              Residual
            </SecondaryButton>
          </div>
        }
      >
        <HeatMap
          views={views}
          basis={basis}
          onCell={(likelihood, impact) => {
            setCell({ likelihood, impact });
          }}
        />
      </Card>
      <Card
        title={`Risk register (${String(shown.length)} of ${String(views.length)})`}
        icon="layers"
        actions={
          cell === undefined ? undefined : (
            <SecondaryButton
              type="button"
              onClick={() => {
                setCell(undefined);
              }}
            >
              Show all
            </SecondaryButton>
          )
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[52rem] text-left text-sm" data-testid="risk-register">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-1 pr-3">Risk</th>
                <th className="py-1 pr-3">L / I</th>
                <th className="py-1 pr-3">Inherent</th>
                <th className="py-1 pr-3">Treatment</th>
                <th className="py-1 pr-3">Residual</th>
                <th className="py-1">Operational status</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((v) => (
                <tr key={v.risk.id} className="border-t border-slate-800 align-top">
                  <td className="py-1.5 pr-3">
                    <button
                      type="button"
                      className="text-left text-slate-200 hover:text-white"
                      onClick={() => {
                        go('risks', v.risk.id);
                      }}
                    >
                      <span className="mr-2 font-mono text-xs text-accent-300">{v.risk.id}</span>
                      {v.risk.title}
                    </button>
                  </td>
                  <td className="py-1.5 pr-3 text-slate-400">
                    {v.likelihood} / {v.impact}
                  </td>
                  <td className="py-1.5 pr-3">
                    <RatingBadge rating={v.inherent} />
                  </td>
                  <td className="py-1.5 pr-3 text-slate-400">
                    {v.assessment?.data.treatment?.option ?? v.risk.treatment}
                  </td>
                  <td className="py-1.5 pr-3">
                    <RatingBadge rating={v.residual} />
                    {v.residualSource === 'REGISTER' ? (
                      <span className="ml-1 text-[10px] text-slate-500">documented</span>
                    ) : null}
                  </td>
                  <td className="py-1.5">
                    <StatusBadge status={v.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function RiskDetail({ view }: { readonly view: RiskView }) {
  const { state, run } = useIsms();
  const [assessing, setAssessing] = useState(false);
  const { risk } = view;
  const history = recordsOf(state.records, 'RISK_ASSESSMENT').filter((r) => r.ref === risk.id);
  const open = history.find((r) => !['RESIDUAL_ACCEPTED', 'WITHDRAWN'].includes(r.status));
  const detail = (label: string) => risk.details.find((d) => d.label === label)?.text ?? '';

  return (
    <Card
      title={`${risk.id} ${risk.title}`}
      icon="risk"
      tone={view.inherent === 'Critical' ? 'danger' : 'default'}
      description={`STRIDE: ${detail('STRIDE')}`}
      actions={
        <>
          <RatingBadge rating={view.inherent} prefix="Inherent" />
          <RatingBadge rating={view.residual} prefix="Residual" />
          <StatusBadge status={view.status} />
        </>
      }
    >
      <div data-testid={`risk-detail-${risk.id}`} className="space-y-4">
        <DetailList
          items={[
            { term: 'Threat', value: detail('Threat') },
            { term: 'Scenario', value: detail('Attack scenario') },
            {
              term: 'Affected assets',
              value: (
                <span className="flex flex-wrap gap-2">
                  {risk.assets.map((a) => (
                    <GoLink key={a} section="assets" item={a}>
                      {a} {ISMS_CATALOGUE.assets.find((x) => x.id === a)?.asset}
                    </GoLink>
                  ))}
                </span>
              ),
            },
            { term: 'Existing controls', value: detail('Security controls') },
            { term: 'Documented residual risk', value: `${risk.residual}. ${detail('Residual risk')}` },
            { term: 'Testing strategy', value: detail('Testing strategy') },
            {
              term: 'Assessment source',
              value:
                view.source === 'REGISTER'
                  ? `Documented baseline: likelihood ${risk.likelihood}, impact ${risk.impact}, treatment ${risk.treatment}`
                  : `Re-assessment ${view.assessment?.code ?? ''} by ${view.assessment?.createdBy.name ?? ''} on ${fmtTime(view.assessment?.createdAt)}`,
            },
            {
              term: 'Limitations',
              value:
                risk.limitations.length === 0 ? (
                  'None'
                ) : (
                  <span className="flex flex-wrap gap-1.5">
                    {risk.limitations.map((l) => (
                      <LimitationChip key={l} id={l} />
                    ))}
                  </span>
                ),
            },
          ]}
        />
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-white">Controls treating this risk</h3>
          <ul className="grid gap-2 md:grid-cols-2">
            {view.controls.map((id) => {
              const control = controlById(id);
              if (control === undefined) return null;
              const assurance = controlAssurance(control, state.records, state.now);
              return (
                <li
                  key={id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 p-2.5"
                >
                  <GoLink section="assurance" item={id}>
                    {id} {control.title}
                  </GoLink>
                  <AssuranceBadge state={assurance.state} />
                </li>
              );
            })}
          </ul>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-white">Assessment and treatment records</h3>
          {history.length === 0 ? (
            <p className="text-sm text-slate-400">
              No dated re-assessment yet: the register's documented assessment applies.
            </p>
          ) : (
            history.map((record) => (
              <div
                key={record.id}
                className="space-y-2 rounded-lg border border-slate-800 p-3"
                data-testid={`assessment-${record.code}`}
              >
                <p className="flex flex-wrap items-center gap-2 text-sm text-slate-200">
                  <span className="font-mono text-xs text-accent-300">{record.code}</span>
                  <StatusBadge status={record.status} />
                  <ExerciseBadge record={record} />
                  likelihood {record.data.likelihood}, impact {record.data.impact}
                  <RatingBadge rating={record.data.inherent} prefix="Inherent" />
                  owner {record.data.owner}
                </p>
                <p className="text-xs text-slate-400">
                  {record.data.rationale} Assessed by {record.createdBy.name} on {fmtTime(record.createdAt)}.
                </p>
                {record.data.treatment === undefined ? null : (
                  <p className="text-xs text-slate-300">
                    Treatment {statusLabel(record.data.treatment.option)} by {record.data.treatment.responsible}:{' '}
                    {record.data.treatment.activity} Controls {record.data.treatment.controls.join(', ') || 'none'}
                    {record.data.treatment.targetDate === null ? '' : `, target ${record.data.treatment.targetDate}`}.
                  </p>
                )}
                {record.data.residual === undefined ? null : (
                  <p className="text-xs text-slate-300">
                    Residual {record.data.residual.rating} (likelihood {record.data.residual.likelihood}, impact{' '}
                    {record.data.residual.impact}) verified by {record.data.residual.verifiedBy.name} with{' '}
                    {record.data.residual.verifications.join(', ') || 'no control'}: {record.data.residual.rationale}
                  </p>
                )}
                {record.data.acceptance === undefined ? null : (
                  <p className="text-xs text-slate-300">
                    {record.data.acceptance.decision === 'ACCEPTED' ? 'Accepted' : 'Not accepted'} by{' '}
                    {record.data.acceptance.by.name} (project owner decision, no independent approver) on{' '}
                    {fmtTime(record.data.acceptance.at)}: {record.data.acceptance.note}
                  </p>
                )}
                <TransitionPanel record={record} />
              </div>
            ))
          )}
          {open !== undefined ? null : assessing ? (
            <SpecForm
              testId="form-risk-assessment"
              submitLabel="Record the assessment"
              onCancel={() => {
                setAssessing(false);
              }}
              intro="A dated re-assessment with the threat model's method. The inherent rating is computed by the server."
              fields={[
                { name: 'assets', label: 'Affected assets', kind: 'lines', initial: risk.assets.join('\n') },
                { name: 'threat', label: 'Threat', kind: 'textarea', initial: detail('Threat') },
                { name: 'vulnerability', label: 'Vulnerability or exposure', kind: 'textarea' },
                { name: 'consequences', label: 'Potential consequences', kind: 'textarea' },
                { name: 'owner', label: 'Risk owner', kind: 'select', options: ROLE_OPTIONS, initial: 'ROLE-01' },
                {
                  name: 'likelihood',
                  label: 'Likelihood',
                  kind: 'select',
                  options: LEVEL_OPTIONS,
                  initial: view.likelihood,
                },
                { name: 'impact', label: 'Impact', kind: 'select', options: LEVEL_OPTIONS, initial: view.impact },
                { name: 'rationale', label: 'Assessment rationale', kind: 'textarea' },
                { name: 'exercise', label: 'This is a demonstration exercise', kind: 'checkbox' },
              ]}
              onSubmit={async (values) => {
                await run(
                  createRecord({
                    kind: 'RISK_ASSESSMENT',
                    ref: risk.id,
                    exercise: values['exercise'] === true,
                    input: {
                      assets: linesOf(values['assets']),
                      threat: textOf(values['threat']),
                      vulnerability: textOf(values['vulnerability']),
                      consequences: textOf(values['consequences']),
                      owner: textOf(values['owner']),
                      likelihood: textOf(values['likelihood']),
                      impact: textOf(values['impact']),
                      rationale: textOf(values['rationale']),
                    },
                  }),
                );
                setAssessing(false);
              }}
            />
          ) : (
            <SecondaryButton
              type="button"
              onClick={() => {
                setAssessing(true);
              }}
            >
              Record a re-assessment of {risk.id}
            </SecondaryButton>
          )}
        </div>
      </div>
    </Card>
  );
}

export function TreatmentSection() {
  const { state } = useIsms();
  const assessments = recordsOf(state.records, 'RISK_ASSESSMENT');
  const accepted = ISMS_CATALOGUE.risks.filter((r) => r.treatment.includes('Accept'));
  return (
    <div className="space-y-6" data-testid="isms-treatment">
      <Card
        title="Risk treatment plan (clause 6.1.3)"
        icon="signature"
        description="Operational treatment records. Acceptance of residual risk is a project-owner decision with a step-up; no residual risk is accepted automatically."
      >
        {assessments.length === 0 ? (
          <p className="text-sm text-slate-400">
            No treatment has been recorded yet. Open a risk to assess and treat it.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[56rem] text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="py-1 pr-3">Record</th>
                  <th className="py-1 pr-3">Risk</th>
                  <th className="py-1 pr-3">Option</th>
                  <th className="py-1 pr-3">Controls</th>
                  <th className="py-1 pr-3">Residual</th>
                  <th className="py-1 pr-3">Approver</th>
                  <th className="py-1">Status</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((r) => (
                  <tr key={r.id} className="border-t border-slate-800 align-top">
                    <td className="py-1.5 pr-3 font-mono text-xs text-accent-300">
                      {r.code} <ExerciseBadge record={r} />
                    </td>
                    <td className="py-1.5 pr-3">
                      <GoLink section="risks" item={r.ref}>
                        {r.ref}
                      </GoLink>
                    </td>
                    <td className="py-1.5 pr-3 text-slate-300">{r.data.treatment?.option ?? 'not planned'}</td>
                    <td className="py-1.5 pr-3 text-xs text-slate-400">
                      {r.data.treatment?.controls.join(', ') ?? ''}
                    </td>
                    <td className="py-1.5 pr-3">
                      <RatingBadge rating={r.data.residual?.rating ?? null} />
                    </td>
                    <td className="py-1.5 pr-3 text-xs text-slate-400">
                      {r.data.acceptance === undefined
                        ? 'pending'
                        : `${r.data.acceptance.by.name} (${r.data.acceptance.decision.toLowerCase()})`}
                    </td>
                    <td className="py-1.5">
                      <StatusBadge status={r.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card
        title="Accepted risks and exceptions"
        icon="alert"
        description="Register decisions that include Accept, with their limitation entries; reviewed before the final report. No mechanism disables a security control."
      >
        <ul className="grid gap-2 md:grid-cols-2">
          {accepted.map((risk) => (
            <li key={risk.id} className="space-y-1 rounded-lg border border-slate-800 p-2.5 text-sm">
              <p className="text-slate-200">
                <GoLink section="risks" item={risk.id}>
                  {risk.id}
                </GoLink>{' '}
                {risk.title}
              </p>
              <p className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                <Badge tone="neutral">{risk.treatment}</Badge> residual {risk.residual} ·{' '}
                {risk.limitations.map((l) => (
                  <LimitationChip key={l} id={l} />
                ))}
              </p>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
