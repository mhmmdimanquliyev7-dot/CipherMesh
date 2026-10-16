'use client';

import {
  allControlAssurance,
  ISMS_CATALOGUE,
  notAssessedAnnexNumbers,
  recordsOf,
  type ControlAssurance,
  type EvidenceFreshness,
  type IsmsRecordOf,
} from '@ciphermesh/shared';
import { useMemo, useState } from 'react';
import { Alert, Badge, Card, DetailList, SecondaryButton } from '../components/ui';
import { DocumentLink, EvidenceChip } from '../trust/ui';
import { createRecord, loadDetail } from './client';
import { useIsms } from './context';
import { linesOf, SpecForm, textOf } from './form-kit';
import { AssuranceBadge, ExerciseBadge, fmtTime, GoLink, ROLE_OPTIONS, StatusBadge } from './parts';

/** Statement of Applicability and control assurance with evidence freshness (clauses 6.1.3 d, 9.1). */

const APPLICABILITY_LABEL = {
  APPLICABLE: 'Applicable',
  NOT_APPLICABLE: 'Excluded',
  PROVIDER: 'Transferred to provider',
} as const;

export function SoaSection() {
  const { state } = useIsms();
  const assurance = useMemo(() => allControlAssurance(state.records, state.now), [state]);
  const notAssessed = notAssessedAnnexNumbers();
  const count = (pick: (a: ControlAssurance) => boolean) => assurance.filter(pick).length;
  return (
    <div className="space-y-6" data-testid="isms-soa">
      <Card
        title={`Statement of Applicability (${String(assurance.length)} rows)`}
        icon="layers"
        description={
          <>
            Source: <DocumentLink path="docs/security/isms-control-mapping.md">isms-control-mapping.md</DocumentLink>{' '}
            section 3. Implemented means the design is built; verified means a current verification record shows it.
          </>
        }
      >
        <div className="flex flex-wrap gap-2 text-xs">
          <Badge tone="info">Applicable: {count((a) => a.applicability === 'APPLICABLE')}</Badge>
          <Badge tone="success">Applicable and verified: {count((a) => a.state === 'VERIFIED')}</Badge>
          <Badge tone="warning">
            Applicable, pending verification: {count((a) => a.applicability === 'APPLICABLE' && a.state !== 'VERIFIED')}
          </Badge>
          <Badge tone="neutral">Excluded: {count((a) => a.applicability === 'NOT_APPLICABLE')}</Badge>
          <Badge tone="violet">Provider: {count((a) => a.applicability === 'PROVIDER')}</Badge>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[60rem] text-left text-sm" data-testid="soa-table">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-1 pr-3">Control</th>
                <th className="py-1 pr-3">Applicability</th>
                <th className="py-1 pr-3">Implementation</th>
                <th className="py-1 pr-3">Risks</th>
                <th className="py-1 pr-3">Assurance</th>
                <th className="py-1">Next due</th>
              </tr>
            </thead>
            <tbody>
              {assurance.map((a) => (
                <tr key={a.control.id} className="border-t border-slate-800 align-top">
                  <td className="py-1.5 pr-3">
                    <GoLink section="assurance" item={a.control.id}>
                      {a.control.id}
                    </GoLink>{' '}
                    <span className="text-slate-200">{a.control.title}</span>
                  </td>
                  <td className="py-1.5 pr-3 text-slate-300">{APPLICABILITY_LABEL[a.applicability]}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{a.control.status}</td>
                  <td className="py-1.5 pr-3 text-xs text-slate-400">{a.risks.length}</td>
                  <td className="py-1.5 pr-3">
                    <AssuranceBadge state={a.state} />
                  </td>
                  <td className="py-1.5 text-xs text-slate-400">
                    {a.validUntil === null ? '' : fmtTime(a.validUntil)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card
        title={`Annex A numbers not assessed (${String(notAssessed.length)} of 93)`}
        icon="dashedCircle"
        description="No row of the Statement of Applicability covers these numbers. They are not claimed applicable or implemented; assessing them is an open improvement."
      >
        <p className="font-mono text-xs leading-relaxed text-slate-400">{notAssessed.join(' · ')}</p>
      </Card>
    </div>
  );
}

const FRESHNESS_TONE: Readonly<Record<EvidenceFreshness['state'], 'success' | 'warning' | 'neutral' | 'danger'>> = {
  CURRENT: 'success',
  STALE: 'warning',
  UNDATED: 'warning',
  NOT_CAPTURED: 'neutral',
  UNKNOWN: 'danger',
};

function FreshnessRow({ freshness }: { readonly freshness: EvidenceFreshness }) {
  return (
    <li className="flex flex-wrap items-center gap-2 text-xs text-slate-300" data-testid={`freshness-${freshness.id}`}>
      <EvidenceChip id={freshness.id} />
      <Badge tone={FRESHNESS_TONE[freshness.state]}>{freshness.state.replace(/_/g, ' ').toLowerCase()}</Badge>
      {freshness.captured === null
        ? null
        : `captured ${freshness.captured}, ${freshness.freshnessClass.toLowerCase()} class (${String(freshness.validityDays)} days), ${
            freshness.state === 'CURRENT' ? 'valid until' : 'expired'
          } ${fmtTime(freshness.expires ?? undefined)}`}
    </li>
  );
}

export function AssuranceSection() {
  const { state, go, item } = useIsms();
  const assurance = useMemo(() => allControlAssurance(state.records, state.now), [state]);
  const selected = assurance.find((a) => a.control.id === item);
  const attention = assurance.filter((a) => ['EVIDENCE_STALE', 'VERIFICATION_DUE', 'FAILED'].includes(a.state));
  const verified = assurance.filter((a) => a.state === 'VERIFIED');
  return (
    <div className="space-y-6" data-testid="isms-assurance">
      {selected === undefined ? null : <ControlDetail assurance={selected} />}
      <Card
        title="Controls that need verification"
        icon="alert"
        tone={attention.length > 0 ? 'warning' : 'default'}
        description="Stale evidence, expired verifications and failed checks, computed from the freshness rule of the ISMS manual, section 7."
      >
        {attention.length === 0 ? (
          <p className="text-sm text-slate-400">None at the moment.</p>
        ) : (
          <ul className="space-y-1.5">
            {attention.map((a) => (
              <li key={a.control.id} className="flex flex-wrap items-center gap-2 text-sm">
                <GoLink section="assurance" item={a.control.id}>
                  {a.control.id}
                </GoLink>
                <span className="text-slate-200">{a.control.title}</span>
                <AssuranceBadge state={a.state} />
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title={`Verified controls (${String(verified.length)})`} icon="checkCircle">
        {verified.length === 0 ? (
          <p className="text-sm text-slate-400">No control has a current verification record yet.</p>
        ) : (
          <ul className="space-y-1.5">
            {verified.map((a) => (
              <li key={a.control.id} className="flex flex-wrap items-center gap-2 text-sm">
                <GoLink section="assurance" item={a.control.id}>
                  {a.control.id}
                </GoLink>
                <span className="text-slate-200">{a.control.title}</span>
                <span className="text-xs text-slate-400">
                  {a.latest?.code} · valid until {fmtTime(a.validUntil ?? undefined)}
                </span>
              </li>
            ))}
          </ul>
        )}
        <SecondaryButton
          type="button"
          onClick={() => {
            go('soa');
          }}
        >
          Open the Statement of Applicability
        </SecondaryButton>
      </Card>
    </div>
  );
}

function VerificationEntry({ record }: { readonly record: IsmsRecordOf<'CONTROL_VERIFICATION'> }) {
  const [text, setText] = useState<string | undefined>();
  const d = record.data;
  return (
    <li
      className="space-y-1.5 rounded-lg border border-slate-800 p-3 text-sm"
      data-testid={`verification-${record.code}`}
    >
      <p className="flex flex-wrap items-center gap-2 text-slate-200">
        <span className="font-mono text-xs text-accent-300">{record.code}</span>
        <Badge tone={d.result === 'PASS' ? 'success' : 'danger'}>{d.result}</Badge>
        <StatusBadge status={record.status} />
        <ExerciseBadge record={record} />
        {d.method.replace(/_/g, ' ').toLowerCase()} · {d.environment.replace(/_/g, ' ').toLowerCase()}
      </p>
      <p className="text-xs text-slate-400">
        {d.procedure} Verified by {record.createdBy.name} on {fmtTime(d.verifiedAt)}; valid until{' '}
        {fmtTime(d.validUntil)} ({d.freshnessClass.toLowerCase()} class).
      </p>
      <p className="text-xs text-slate-500">Limitations: {d.limitations}</p>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {d.evidence.map((id) => (
          <EvidenceChip key={id} id={id} />
        ))}
        {d.ciRun === null ? null : (
          <a className="text-accent-300 underline" href={d.ciRun} rel="noreferrer noopener" target="_blank">
            CI run
          </a>
        )}
        {d.attachment === null ? null : (
          <SecondaryButton
            type="button"
            onClick={() =>
              void loadDetail(record.id).then((detail) => {
                const attached = detail.record.data['attachment'] as { text?: unknown } | null;
                setText(typeof attached?.text === 'string' ? attached.text : '');
              })
            }
          >
            Show attached output ({d.attachment.label}, {d.attachment.bytes} bytes, SHA-256{' '}
            {d.attachment.sha256.slice(0, 12)}…)
          </SecondaryButton>
        )}
      </div>
      {text === undefined ? null : (
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md border border-slate-800 bg-slate-950 p-2 font-mono text-[11px] text-slate-300">
          {text}
        </pre>
      )}
    </li>
  );
}

function ControlDetail({ assurance }: { readonly assurance: ControlAssurance }) {
  const { state, run, go } = useIsms();
  const [form, setForm] = useState<'verify' | 'finding' | undefined>();
  const { control } = assurance;
  const verifications = recordsOf(state.records, 'CONTROL_VERIFICATION').filter((r) => r.ref === control.id);
  const findings = recordsOf(state.records, 'FINDING').filter((f) => f.data.relatedControls.includes(control.id));
  const stale = assurance.evidence.filter((e) => e.state === 'STALE' || e.state === 'UNDATED').map((e) => e.id);
  return (
    <Card
      title={`${control.id} ${control.title}`}
      icon="checkCircle"
      tone={['EVIDENCE_STALE', 'VERIFICATION_DUE', 'FAILED'].includes(assurance.state) ? 'warning' : 'default'}
      actions={<AssuranceBadge state={assurance.state} />}
    >
      <div className="space-y-4" data-testid={`control-detail-${control.id}`}>
        <DetailList
          items={[
            { term: 'Theme', value: control.theme },
            { term: 'Statement of Applicability', value: control.status },
            { term: 'Implementation', value: control.implementation },
            { term: 'Responsible', value: 'ROLE-01 ISMS manager and risk owner (project owner)' },
            {
              term: 'Linked risks',
              value: (
                <span className="flex flex-wrap gap-2">
                  {assurance.risks.map((r) => (
                    <GoLink key={r} section="risks" item={r}>
                      {r}
                    </GoLink>
                  ))}
                </span>
              ),
            },
            {
              term: 'Next verification due',
              value: assurance.validUntil === null ? 'Not verified yet' : fmtTime(assurance.validUntil),
            },
          ]}
        />
        <div className="space-y-1.5">
          <h3 className="text-sm font-semibold text-white">Evidence cited by the Statement of Applicability</h3>
          {assurance.evidence.length === 0 ? (
            <p className="text-sm text-slate-400">No evidence item is cited for this row.</p>
          ) : (
            <ul className="space-y-1">
              {assurance.evidence.map((e) => (
                <FreshnessRow key={e.id} freshness={e} />
              ))}
            </ul>
          )}
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-white">Verification records</h3>
          {verifications.length === 0 ? (
            <p className="text-sm text-slate-400">
              None. The control is implemented by design but not verified in the ISMS.
            </p>
          ) : (
            <ul className="space-y-2">
              {verifications.map((r) => (
                <VerificationEntry key={r.id} record={r} />
              ))}
            </ul>
          )}
        </div>
        {findings.length === 0 ? null : (
          <p className="flex flex-wrap items-center gap-2 text-sm text-slate-300">
            Findings on this control:{' '}
            {findings.map((f) => (
              <GoLink key={f.id} section="actions" item={f.code}>
                {f.code} ({f.status.toLowerCase().replace(/_/g, ' ')})
              </GoLink>
            ))}
          </p>
        )}
        {assurance.applicability === 'NOT_APPLICABLE' ? (
          <Alert kind="info">Excluded in the Statement of Applicability; it is not verified.</Alert>
        ) : (
          <div className="flex flex-wrap gap-2">
            <SecondaryButton
              type="button"
              onClick={() => {
                setForm('verify');
              }}
            >
              Record a verification of {control.id}
            </SecondaryButton>
            <SecondaryButton
              type="button"
              onClick={() => {
                setForm('finding');
              }}
            >
              Raise a finding on {control.id}
            </SecondaryButton>
          </div>
        )}
        {form === 'verify' ? (
          <SpecForm
            testId="form-verification"
            submitLabel="Record the verification"
            onCancel={() => {
              setForm(undefined);
            }}
            intro="A PASS needs current support: current evidence items, an attached output (no secrets: the server refuses keys, cookies, presigned URLs and credentials) or a CI run of this repository."
            fields={[
              {
                name: 'method',
                label: 'Method',
                kind: 'select',
                options: ['AUTOMATED_TEST', 'CI_RUN', 'LOCAL_VERIFICATION', 'DOCUMENT_REVIEW', 'MANUAL_INSPECTION'].map(
                  (v) => ({
                    value: v,
                    label: v.replace(/_/g, ' ').toLowerCase(),
                  }),
                ),
              },
              {
                name: 'environment',
                label: 'Environment',
                kind: 'select',
                options: ['LOCAL_DOCKER', 'CI', 'DEVELOPMENT', 'DOCUMENTATION'].map((v) => ({
                  value: v,
                  label: v.replace(/_/g, ' ').toLowerCase(),
                })),
              },
              { name: 'procedure', label: 'Verification procedure', kind: 'textarea' },
              {
                name: 'result',
                label: 'Result',
                kind: 'select',
                options: ['PASS', 'FAIL', 'INCONCLUSIVE'].map((v) => ({ value: v, label: v })),
              },
              {
                name: 'freshnessClass',
                label: 'Freshness class',
                kind: 'select',
                options: ISMS_CATALOGUE.freshness.classes.map((c) => ({
                  value: c.id,
                  label: `${c.id} (${String(c.validityDays)} days)`,
                })),
                initial: 'TECHNICAL',
              },
              {
                name: 'evidence',
                label: 'Evidence items (EV-xx-yy)',
                kind: 'lines',
                optional: true,
                initial: assurance.evidence
                  .filter((e) => e.state === 'CURRENT')
                  .map((e) => e.id)
                  .join('\n'),
              },
              { name: 'ciRun', label: 'GitHub Actions run link', kind: 'text', optional: true },
              { name: 'attachmentLabel', label: 'Attached output label', kind: 'text', optional: true },
              {
                name: 'attachmentText',
                label: 'Attached output (command output, at most 32 KiB)',
                kind: 'textarea',
                optional: true,
              },
              {
                name: 'relatedRisks',
                label: 'Related risks',
                kind: 'lines',
                optional: true,
                initial: assurance.risks.join('\n'),
              },
              { name: 'limitations', label: 'Limitations of this verification', kind: 'textarea' },
              { name: 'exercise', label: 'This is a demonstration exercise', kind: 'checkbox' },
            ]}
            onSubmit={async (values) => {
              const attachmentText = typeof values['attachmentText'] === 'string' ? values['attachmentText'] : '';
              await run(
                createRecord({
                  kind: 'CONTROL_VERIFICATION',
                  ref: control.id,
                  exercise: values['exercise'] === true,
                  input: {
                    method: textOf(values['method']),
                    procedure: textOf(values['procedure']),
                    environment: textOf(values['environment']),
                    result: textOf(values['result']),
                    limitations: textOf(values['limitations']),
                    relatedRisks: linesOf(values['relatedRisks']),
                    evidence: linesOf(values['evidence']),
                    ciRun: textOf(values['ciRun']) === '' ? null : textOf(values['ciRun']),
                    attachment:
                      attachmentText.trim() === ''
                        ? null
                        : { label: textOf(values['attachmentLabel']) || 'Output', text: attachmentText },
                    freshnessClass: textOf(values['freshnessClass']),
                  },
                }),
              );
              setForm(undefined);
            }}
          />
        ) : null}
        {form === 'finding' ? (
          <SpecForm
            testId="form-finding"
            submitLabel="Raise the finding"
            onCancel={() => {
              setForm(undefined);
            }}
            fields={[
              {
                name: 'source',
                label: 'Source',
                kind: 'select',
                options: [
                  { value: 'EVIDENCE_FRESHNESS', label: 'Evidence freshness check' },
                  { value: 'SELF_ASSESSMENT', label: 'Self-assessment' },
                  { value: 'OTHER', label: 'Other' },
                ],
                initial: stale.length > 0 ? 'EVIDENCE_FRESHNESS' : 'SELF_ASSESSMENT',
              },
              {
                name: 'classification',
                label: 'Classification',
                kind: 'select',
                options: [
                  'OBSERVATION',
                  'MINOR_NONCONFORMITY',
                  'MAJOR_NONCONFORMITY',
                  'IMPROVEMENT',
                  'INSUFFICIENT_EVIDENCE',
                ].map((v) => ({
                  value: v,
                  label: v.replace(/_/g, ' ').toLowerCase(),
                })),
              },
              { name: 'responsible', label: 'Responsible', kind: 'select', options: ROLE_OPTIONS, initial: 'ROLE-01' },
              {
                name: 'observation',
                label: 'Observation',
                kind: 'textarea',
                initial:
                  stale.length > 0
                    ? `Evidence ${stale.join(', ')} for ${control.id} is past its freshness rule; the control needs a current verification.`
                    : '',
              },
              {
                name: 'evidence',
                label: 'Evidence examined',
                kind: 'lines',
                optional: true,
                initial: stale.join('\n'),
              },
              {
                name: 'relatedRisks',
                label: 'Related risks',
                kind: 'lines',
                optional: true,
                initial: assurance.risks.join('\n'),
              },
              { name: 'exercise', label: 'This is a demonstration exercise', kind: 'checkbox' },
            ]}
            onSubmit={async (values) => {
              const outcome = await run(
                createRecord({
                  kind: 'FINDING',
                  exercise: values['exercise'] === true,
                  input: {
                    source: { type: textOf(values['source']), ref: control.id },
                    classification: textOf(values['classification']),
                    criterion: control.id,
                    observation: textOf(values['observation']),
                    evidence: linesOf(values['evidence']),
                    responsible: textOf(values['responsible']),
                    relatedRisks: linesOf(values['relatedRisks']),
                    relatedControls: [control.id],
                  },
                }),
              );
              setForm(undefined);
              go('actions', outcome.code);
            }}
          />
        ) : null}
      </div>
    </Card>
  );
}
