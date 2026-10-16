'use client';

import {
  availableTransitions,
  ISMS_CATALOGUE,
  type ControlAssuranceState,
  type IsmsRecord,
  type IsmsRecordOf,
  type IsmsRating,
} from '@ciphermesh/shared';
import { useState, type ReactNode } from 'react';
import { Badge, SecondaryButton, type BadgeTone } from '../components/ui';
import { decision, transition } from './client';
import { useIsms, type SectionId } from './context';
import { linesOf, SpecForm, textOf, LEVEL_OPTIONS, type FieldSpec, type FormValues } from './form-kit';

/** Building blocks of the ISMS Control Center: badges, links and the transition panel. */

export const RATING_TONE: Readonly<Record<IsmsRating, BadgeTone>> = {
  Low: 'success',
  Medium: 'info',
  High: 'warning',
  Critical: 'danger',
};

export function RatingBadge({ rating, prefix }: { readonly rating: IsmsRating | null; readonly prefix?: string }) {
  if (rating === null) return <Badge tone="neutral">{prefix === undefined ? '' : `${prefix} `}not rated</Badge>;
  return (
    <Badge tone={RATING_TONE[rating]}>
      {prefix === undefined ? '' : `${prefix} `}
      {rating}
    </Badge>
  );
}

export const ASSURANCE_LABEL: Readonly<Record<ControlAssuranceState, string>> = {
  VERIFIED: 'Verified (current)',
  VERIFICATION_DUE: 'Verification due',
  FAILED: 'Verification failed',
  EVIDENCE_CURRENT: 'Evidence current, not yet verified',
  EVIDENCE_STALE: 'Evidence stale',
  NO_EVIDENCE: 'No evidence',
  NOT_APPLICABLE: 'Excluded',
  PROVIDER: 'Provider responsibility',
};

const ASSURANCE_TONE: Readonly<Record<ControlAssuranceState, BadgeTone>> = {
  VERIFIED: 'success',
  VERIFICATION_DUE: 'warning',
  FAILED: 'danger',
  EVIDENCE_CURRENT: 'info',
  EVIDENCE_STALE: 'warning',
  NO_EVIDENCE: 'neutral',
  NOT_APPLICABLE: 'neutral',
  PROVIDER: 'violet',
};

export function AssuranceBadge({ state }: { readonly state: ControlAssuranceState }) {
  return (
    <Badge
      tone={ASSURANCE_TONE[state]}
      {...(state === 'VERIFIED'
        ? { icon: 'checkCircle' as const }
        : state === 'NO_EVIDENCE'
          ? { icon: 'dashedCircle' as const }
          : {})}
    >
      {ASSURANCE_LABEL[state]}
    </Badge>
  );
}

const STATUS_TONE: Readonly<Record<string, BadgeTone>> = {
  RESIDUAL_ACCEPTED: 'success',
  TREATMENT_VERIFIED: 'accent',
  CLOSED: 'success',
  COMPLETED: 'success',
  RECORDED: 'success',
  WITHDRAWN: 'neutral',
  DOCUMENTED: 'neutral',
  OPEN: 'warning',
  AWAITING_EFFECTIVENESS: 'accent',
};

export const statusLabel = (status: string): string =>
  status.charAt(0) + status.slice(1).toLowerCase().replace(/_/g, ' ');

export function StatusBadge({ status }: { readonly status: string }) {
  return <Badge tone={STATUS_TONE[status] ?? 'info'}>{statusLabel(status)}</Badge>;
}

export function ExerciseBadge({ record }: { readonly record: Pick<IsmsRecord, 'exercise'> }) {
  return record.exercise ? (
    <Badge tone="violet" title="A labelled demonstration exercise, not a real event">
      EXERCISE
    </Badge>
  ) : null;
}

/** A link to another place of the Control Center (a risk, control, policy or record). */
export function GoLink({
  section,
  item,
  children,
}: {
  readonly section: SectionId;
  readonly item?: string;
  readonly children: ReactNode;
}) {
  const { go } = useIsms();
  return (
    <button
      type="button"
      className="font-mono text-xs text-accent-300 underline-offset-2 hover:underline"
      onClick={() => {
        go(section, item);
      }}
    >
      {children}
    </button>
  );
}

export function RecordLink({ code }: { readonly code: string }) {
  const { state } = useIsms();
  const record = state.records.find((r) => r.code === code);
  const section: SectionId =
    record?.kind === 'FINDING'
      ? 'actions'
      : record?.kind === 'AUDIT'
        ? 'audits'
        : record?.kind === 'CONTROL_VERIFICATION'
          ? 'assurance'
          : record?.kind === 'MANAGEMENT_REVIEW'
            ? 'review'
            : 'improvement';
  return (
    <GoLink section={section} item={record?.kind === 'CONTROL_VERIFICATION' ? record.ref : code}>
      {code}
    </GoLink>
  );
}

export const ROLE_OPTIONS = ISMS_CATALOGUE.roles
  .filter((role) => role.id !== 'ROLE-06')
  .map((role) => ({ value: role.id, label: `${role.id} ${role.role}` }));

export const roleName = (id: string): string => {
  const role = ISMS_CATALOGUE.roles.find((r) => r.id === id);
  return role === undefined ? id : `${role.role} (${role.heldBy})`;
};

export const fmtTime = (iso: string | undefined): string =>
  iso === undefined ? 'not recorded' : `${new Date(iso).toISOString().slice(0, 16).replace('T', ' ')} UTC`;

// ------------------------------------------------------------------------------ transitions

function fieldsFor(record: IsmsRecord, name: string): readonly FieldSpec[] {
  switch (name) {
    case 'plan_treatment': {
      const risk = ISMS_CATALOGUE.risks.find((r) => r.id === record.ref);
      const data = (record as IsmsRecordOf<'RISK_ASSESSMENT'>).data;
      return [
        {
          name: 'option',
          label: 'Treatment option',
          kind: 'select',
          options: ['MITIGATE', 'AVOID', 'TRANSFER', 'ACCEPT'].map((v) => ({ value: v, label: statusLabel(v) })),
        },
        { name: 'responsible', label: 'Responsible party', kind: 'select', options: ROLE_OPTIONS, initial: 'ROLE-02' },
        {
          name: 'controls',
          label: 'Linked controls (Statement of Applicability rows)',
          kind: 'lines',
          initial: (data.treatment?.controls ?? risk?.controls ?? []).join('\n'),
          optional: true,
        },
        { name: 'activity', label: 'Implementation activity', kind: 'textarea' },
        { name: 'targetDate', label: 'Target date', kind: 'date', optional: true },
        { name: 'requiredEvidence', label: 'Required evidence (EV-xx-yy)', kind: 'lines', optional: true },
      ];
    }
    case 'verify_treatment':
      return [
        { name: 'likelihood', label: 'Residual likelihood', kind: 'select', options: LEVEL_OPTIONS, initial: 'Low' },
        { name: 'impact', label: 'Residual impact', kind: 'select', options: LEVEL_OPTIONS, initial: 'High' },
        { name: 'rationale', label: 'Residual risk rationale', kind: 'textarea' },
      ];
    case 'accept_residual':
    case 'reject_residual':
    case 'implement_action':
      return [
        {
          name: 'note',
          label: name === 'implement_action' ? 'Implementation note' : 'Decision note',
          kind: 'textarea',
        },
      ];
    case 'record_check': {
      const audit = (record as IsmsRecordOf<'AUDIT'>).data;
      return [
        {
          name: 'criterion',
          label: 'Criterion',
          kind: 'select',
          options: audit.criteria.map((c) => ({ value: c, label: c })),
        },
        {
          name: 'result',
          label: 'Result',
          kind: 'select',
          options: [
            'CONFORMITY',
            'MINOR_NONCONFORMITY',
            'MAJOR_NONCONFORMITY',
            'OBSERVATION',
            'IMPROVEMENT',
            'INSUFFICIENT_EVIDENCE',
          ].map((v) => ({ value: v, label: statusLabel(v) })),
        },
        { name: 'note', label: 'Observation', kind: 'textarea' },
        { name: 'evidence', label: 'Evidence examined (EV-xx-yy)', kind: 'lines', optional: true },
      ];
    }
    case 'complete':
      return [{ name: 'conclusion', label: 'Audit conclusion', kind: 'textarea' }];
    case 'analyze':
      return [
        { name: 'rootCause', label: 'Root cause', kind: 'textarea' },
        { name: 'correction', label: 'Immediate correction', kind: 'textarea', optional: true },
      ];
    case 'plan_action':
      return [
        { name: 'description', label: 'Corrective action', kind: 'textarea' },
        { name: 'owner', label: 'Action owner', kind: 'select', options: ROLE_OPTIONS },
        { name: 'dueDate', label: 'Due date', kind: 'date' },
      ];
    case 'submit_closure_evidence': {
      const finding = (record as IsmsRecordOf<'FINDING'>).data;
      const planned = finding.action?.plannedAt ?? record.createdAt;
      return [
        {
          name: 'verifications',
          label: 'Verification records (CV-xxx)',
          kind: 'lines',
          optional: true,
          hint: `A PASS of a related control (${finding.relatedControls.join(', ') || 'any'}) recorded after ${fmtTime(planned)}.`,
        },
        { name: 'evidence', label: 'Current evidence items (EV-xx-yy)', kind: 'lines', optional: true },
      ];
    }
    case 'effectiveness_check':
      return [
        {
          name: 'result',
          label: 'Effectiveness',
          kind: 'select',
          options: [
            { value: 'EFFECTIVE', label: 'Effective: close the finding' },
            { value: 'NOT_EFFECTIVE', label: 'Not effective: plan the action again' },
          ],
        },
        { name: 'note', label: 'Effectiveness note', kind: 'textarea' },
      ];
    case 'update_draft': {
      const review = (record as IsmsRecordOf<'MANAGEMENT_REVIEW'>).data;
      return [
        {
          name: 'participants',
          label: 'Participants actually present',
          kind: 'lines',
          initial: review.participants.join('\n'),
        },
        {
          name: 'inputNotes',
          label: 'Notes on the inputs',
          kind: 'textarea',
          optional: true,
          initial: review.inputNotes,
        },
        { name: 'decisions', label: 'Decisions', kind: 'lines', initial: review.decisions.join('\n') },
        {
          name: 'actions',
          label: 'Follow-up actions',
          kind: 'lines',
          optional: true,
          hint: 'One per line: description | ROLE-01 | YYYY-MM-DD',
          initial: review.actions.map((a) => `${a.description} | ${a.owner} | ${a.dueDate}`).join('\n'),
        },
      ];
    }
    case 'contain':
      return [{ name: 'containment', label: 'Containment', kind: 'textarea' }];
    case 'resolve':
      return [{ name: 'recovery', label: 'Recovery', kind: 'textarea' }];
    case 'close_incident':
      return [{ name: 'lessons', label: 'Lessons learned', kind: 'textarea' }];
    case 'withdraw':
      return [{ name: 'reason', label: 'Reason for withdrawing this exercise', kind: 'textarea' }];
    default:
      return [];
  }
}

export function reviewActions(values: FormValues): { description: string; owner: string; dueDate: string }[] {
  return linesOf(String(values['actions'] ?? '').replace(/,/g, ';')).map((line) => {
    const [description = '', owner = 'ROLE-01', dueDate = ''] = line.split('|').map((part) => part.trim());
    return { description: description.replace(/;/g, ','), owner, dueDate };
  });
}

function inputFor(name: string, values: FormValues): Record<string, unknown> {
  const t = (key: string) => textOf(values[key]);
  switch (name) {
    case 'plan_treatment':
      return {
        option: t('option'),
        responsible: t('responsible'),
        controls: linesOf(values['controls']),
        activity: t('activity'),
        targetDate: t('targetDate') === '' ? null : t('targetDate'),
        requiredEvidence: linesOf(values['requiredEvidence']),
      };
    case 'verify_treatment':
      return { likelihood: t('likelihood'), impact: t('impact'), rationale: t('rationale') };
    case 'record_check':
      return { criterion: t('criterion'), result: t('result'), note: t('note'), evidence: linesOf(values['evidence']) };
    case 'submit_closure_evidence':
      return { verifications: linesOf(values['verifications']), evidence: linesOf(values['evidence']) };
    case 'update_draft':
      return {
        participants: linesOf(values['participants']),
        inputNotes: t('inputNotes'),
        decisions: textOf(values['decisions'])
          .split(/\r?\n/)
          .map((d) => d.trim())
          .filter((d) => d !== ''),
        actions: reviewActions(values),
      };
    default: {
      const input: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(values)) input[key] = typeof value === 'string' ? value.trim() : value;
      return input;
    }
  }
}

/** The named transitions possible from the record's status; decisions are marked as such. */
export function TransitionPanel({ record }: { readonly record: IsmsRecord }) {
  const { run } = useIsms();
  const [open, setOpen] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const options = availableTransitions(record);
  if (options.length === 0) {
    return <p className="text-xs text-slate-500">No further change is possible from this status.</p>;
  }
  const active = options.find((o) => o.name === open);
  return (
    <div className="space-y-3" data-testid={`transitions-${record.code}`}>
      <div className="flex flex-wrap gap-2">
        {options.map((option) => (
          <SecondaryButton
            key={option.name}
            type="button"
            onClick={() => {
              setOpen(option.name);
            }}
          >
            {option.label}
            {option.authority === 'decide' ? ' (decision)' : ''}
          </SecondaryButton>
        ))}
      </div>
      {notice === undefined ? null : <p className="text-xs text-emerald-300">{notice}</p>}
      {active === undefined ? null : (
        <SpecForm
          key={`${record.id}-${record.version}-${active.name}`}
          testId={`form-${active.name}`}
          fields={fieldsFor(record, active.name)}
          submitLabel={active.label}
          intro={
            active.authority === 'decide'
              ? 'This is a decision (PA-08): the server asks you to confirm your identity and records you as the approver.'
              : undefined
          }
          onCancel={() => {
            setOpen(undefined);
          }}
          onSubmit={async (values) => {
            const input = inputFor(active.name, values);
            const write =
              active.authority === 'decide'
                ? decision(record, active.name, input)
                : transition(record, active.name, input);
            const outcome = await run(write);
            setOpen(undefined);
            setNotice(
              outcome.created.length > 0
                ? `Recorded. Created: ${outcome.created.join(', ')}.`
                : `Recorded (${outcome.code}).`,
            );
          }}
        />
      )}
    </div>
  );
}
