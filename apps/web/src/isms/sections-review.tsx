'use client';

import { recordsOf, type IsmsRecordOf, type ReviewInputs } from '@ciphermesh/shared';
import { useMemo, useState } from 'react';
import { Badge, Card, DetailList, SecondaryButton } from '../components/ui';
import { createRecord } from './client';
import { useIsms } from './context';
import { linesOf, SpecForm, textOf } from './form-kit';
import {
  ExerciseBadge,
  fmtTime,
  RecordLink,
  reviewActions,
  ROLE_OPTIONS,
  StatusBadge,
  statusLabel,
  TransitionPanel,
} from './parts';

/** Management review (clause 9.3) and continual improvement, incidents, changes, history (clause 10.1). */

function Inputs({ inputs }: { readonly inputs: ReviewInputs }) {
  return (
    <DetailList
      items={[
        { term: 'Computed', value: fmtTime(inputs.computedAt) },
        { term: 'Metrics', value: inputs.metrics.map((m) => `${m.id} ${m.display}`).join(' · ') },
        {
          term: 'Control assurance',
          value: Object.entries(inputs.assurance)
            .map(([state, count]) => `${statusLabel(state)} ${String(count)}`)
            .join(' · '),
        },
        { term: 'Risks awaiting treatment', value: inputs.risksAwaitingTreatment.join(', ') || 'None' },
        { term: 'Risks awaiting acceptance', value: inputs.risksAwaitingAcceptance.join(', ') || 'None' },
        {
          term: 'Open findings',
          value: inputs.openFindings.map((f) => `${f.code} (${statusLabel(f.status)})`).join(', ') || 'None',
        },
        { term: 'Overdue actions', value: inputs.overdueFindings.join(', ') || 'None' },
        {
          term: 'Earlier review actions',
          value:
            inputs.previousActions
              .map((a) => `${a.review}: ${a.description} → ${a.finding ?? 'no finding'} ${statusLabel(a.status)}`)
              .join('; ') || 'None',
        },
        {
          term: 'Stale evidence items',
          value:
            inputs.staleEvidence.length === 0
              ? 'None'
              : `${String(inputs.staleEvidence.length)}: ${inputs.staleEvidence.join(', ')}`,
        },
      ]}
    />
  );
}

function ReviewEntry({ review }: { readonly review: IsmsRecordOf<'MANAGEMENT_REVIEW'> }) {
  const d = review.data;
  return (
    <li className="space-y-3 rounded-lg border border-slate-800 p-3" data-testid={`review-${review.code}`}>
      <p className="flex flex-wrap items-center gap-2 text-sm text-slate-200">
        <span className="font-mono text-xs text-accent-300">{review.code}</span>
        {d.title} · {d.reviewDate}
        <StatusBadge status={review.status} />
        <ExerciseBadge record={review} />
        <Badge tone="neutral">
          {d.format === 'ONE_PERSON_PROJECT_REVIEW' ? 'One-person project review' : 'Project team review'}
        </Badge>
      </p>
      <Inputs inputs={d.inputs} />
      <DetailList
        items={[
          { term: 'Participants present', value: d.participants.join(', ') || 'Not recorded yet' },
          { term: 'Notes on the inputs', value: d.inputNotes === '' ? 'None' : d.inputNotes },
          { term: 'Decisions', value: d.decisions.length === 0 ? 'None yet' : d.decisions.join(' · ') },
          {
            term: 'Follow-up actions',
            value:
              d.actions.length === 0 ? (
                'None'
              ) : (
                <ul className="space-y-1">
                  {d.actions.map((a, i) => (
                    <li key={`${a.description}-${String(i)}`}>
                      {a.description} · {a.owner} · due {a.dueDate}{' '}
                      {a.finding === null ? null : <RecordLink code={a.finding} />}
                    </li>
                  ))}
                </ul>
              ),
          },
          ...(d.recorded === undefined
            ? []
            : [{ term: 'Recorded by', value: `${d.recorded.by.name} on ${fmtTime(d.recorded.at)}` }]),
        ]}
      />
      <TransitionPanel record={review} />
    </li>
  );
}

export function ReviewSection() {
  const { state, run } = useIsms();
  const [drafting, setDrafting] = useState(false);
  const reviews = recordsOf(state.records, 'MANAGEMENT_REVIEW');
  return (
    <div className="space-y-6" data-testid="isms-review">
      <Card
        title="Management review (clause 9.3)"
        icon="members"
        description="The inputs are computed by the server from the records when the draft is created. Participants, decisions and actions are entered by the project owner and recorded as a decision (PA-08); no meeting is recorded that did not happen."
        actions={
          <SecondaryButton
            type="button"
            onClick={() => {
              setDrafting(true);
            }}
          >
            Prepare a management review
          </SecondaryButton>
        }
      >
        {drafting ? (
          <SpecForm
            testId="form-management-review"
            submitLabel="Create the draft with computed inputs"
            onCancel={() => {
              setDrafting(false);
            }}
            fields={[
              { name: 'title', label: 'Review title', kind: 'text', initial: 'ISMS management review' },
              { name: 'reviewDate', label: 'Review date', kind: 'date', initial: state.now.toISOString().slice(0, 10) },
              {
                name: 'format',
                label: 'Format',
                kind: 'select',
                options: [
                  { value: 'ONE_PERSON_PROJECT_REVIEW', label: 'One-person project review' },
                  { value: 'PROJECT_TEAM_REVIEW', label: 'Project team review' },
                ],
              },
              { name: 'participants', label: 'Participants actually present', kind: 'lines', optional: true },
              { name: 'inputNotes', label: 'Notes on the inputs', kind: 'textarea', optional: true },
              { name: 'decisions', label: 'Decisions (one per line)', kind: 'textarea', optional: true },
              {
                name: 'actions',
                label: 'Follow-up actions',
                kind: 'lines',
                optional: true,
                hint: 'One per line: description | ROLE-01 | YYYY-MM-DD',
              },
              { name: 'exercise', label: 'This is a demonstration exercise', kind: 'checkbox' },
            ]}
            onSubmit={async (values) => {
              await run(
                createRecord({
                  kind: 'MANAGEMENT_REVIEW',
                  exercise: values['exercise'] === true,
                  input: {
                    title: textOf(values['title']),
                    reviewDate: textOf(values['reviewDate']),
                    format: textOf(values['format']),
                    participants: linesOf(values['participants']),
                    inputNotes: textOf(values['inputNotes']),
                    decisions: textOf(values['decisions'])
                      .split(/\r?\n/)
                      .map((line) => line.trim())
                      .filter((line) => line !== ''),
                    actions: reviewActions(values),
                  },
                }),
              );
              setDrafting(false);
            }}
          />
        ) : null}
        {reviews.length === 0 ? (
          <p className="text-sm text-slate-400">No management review has been recorded.</p>
        ) : (
          <ul className="space-y-3">
            {reviews.map((r) => (
              <ReviewEntry key={r.id} review={r} />
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

/** Merged pull requests of the cloud and ISMS workstreams with their CI evidence (change control, POL-09). */
const CHANGES: readonly {
  readonly pr: number;
  readonly title: string;
  readonly merge: string;
  readonly ci: string;
  readonly evidence: string;
}[] = [
  {
    pr: 37,
    title: 'Cloud workstream Stage A and the local Docker demonstration',
    merge: 'ac75888',
    ci: 'Run 38719307516: every job passed, Cloud stack (linux/arm64) included',
    evidence: 'EV-17-06, EV-17-09, EV-19-10, EV-19-13',
  },
  {
    pr: 38,
    title: 'Handoff: merge recorded, CI evidence captured',
    merge: 'b643a2b',
    ci: 'Every job passed before the merge',
    evidence: 'EV-17-06, EV-19-10',
  },
];

export function ImprovementSection() {
  const { state, run } = useIsms();
  const [reporting, setReporting] = useState(false);
  const [showWithdrawn, setShowWithdrawn] = useState(false);
  const incidents = recordsOf(state.records, 'INCIDENT');
  const exercises = state.records.filter((r) => r.exercise && (showWithdrawn || r.status !== 'WITHDRAWN'));
  const perDay = useMemo(() => {
    const days = new Map<string, number>();
    for (const entry of state.activity) days.set(entry.at.slice(0, 10), (days.get(entry.at.slice(0, 10)) ?? 0) + 1);
    return [...days.entries()].sort();
  }, [state.activity]);
  return (
    <div className="space-y-6" data-testid="isms-improvement">
      <Card
        title="Activity history (clause 7.5.3)"
        icon="clock"
        description="Every creation and change, with the person, time, previous and new status and the note. An authenticated history kept append-only by the database; not the tamper-evident ledger of ADR-009 (deferred, L-81)."
      >
        <p className="text-xs text-slate-400">
          Management activities per day:{' '}
          {perDay.length === 0 ? 'none yet' : perDay.map(([day, count]) => `${day} ${String(count)}`).join(' · ')}. One
          period of operation, not months of ISMS history.
        </p>
        {state.activity.length === 0 ? (
          <p className="text-sm text-slate-400">No activity yet.</p>
        ) : (
          <ol className="max-h-[28rem] space-y-1.5 overflow-auto" data-testid="isms-activity">
            {state.activity.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-2 text-xs text-slate-300">
                <span className="text-slate-500">{fmtTime(a.at)}</span>
                <RecordLink code={a.code} />
                {a.exercise ? <Badge tone="violet">EXERCISE</Badge> : null}
                <span className="text-slate-200">{a.action.replace(/_/g, ' ')}</span>
                {a.fromStatus === null ? null : <span>{statusLabel(a.fromStatus)} →</span>}
                <StatusBadge status={a.toStatus} />
                <span className="text-slate-400">by {a.actor.name}</span>
                {a.rationale === null ? null : <span className="text-slate-500">“{a.rationale.slice(0, 140)}”</span>}
              </li>
            ))}
          </ol>
        )}
      </Card>

      <Card
        title="Security incidents and exercises (controls 5.24 to 5.27)"
        icon="alert"
        description="No real security incident has occurred. Exercises are labelled EXERCISE everywhere and can be withdrawn after use."
        actions={
          <SecondaryButton
            type="button"
            onClick={() => {
              setReporting(true);
            }}
          >
            Record an incident or exercise
          </SecondaryButton>
        }
      >
        {reporting ? (
          <SpecForm
            testId="form-incident"
            submitLabel="Record"
            onCancel={() => {
              setReporting(false);
            }}
            fields={[
              { name: 'title', label: 'Title', kind: 'text' },
              { name: 'detection', label: 'Detection or source', kind: 'textarea' },
              {
                name: 'classification',
                label: 'Classification',
                kind: 'select',
                options: [
                  { value: 'SECURITY_EVENT', label: 'Security event' },
                  { value: 'SECURITY_INCIDENT', label: 'Security incident' },
                ],
              },
              { name: 'impact', label: 'Impact', kind: 'textarea' },
              { name: 'owner', label: 'Response owner', kind: 'select', options: ROLE_OPTIONS, initial: 'ROLE-03' },
              { name: 'relatedRisks', label: 'Related risks', kind: 'lines', optional: true },
              { name: 'relatedControls', label: 'Related controls', kind: 'lines', optional: true },
              { name: 'exercise', label: 'This is an exercise (not a real incident)', kind: 'checkbox', initial: true },
            ]}
            onSubmit={async (values) => {
              await run(
                createRecord({
                  kind: 'INCIDENT',
                  exercise: values['exercise'] === true,
                  input: {
                    title: textOf(values['title']),
                    detection: textOf(values['detection']),
                    classification: textOf(values['classification']),
                    impact: textOf(values['impact']),
                    owner: textOf(values['owner']),
                    relatedRisks: linesOf(values['relatedRisks']),
                    relatedControls: linesOf(values['relatedControls']),
                  },
                }),
              );
              setReporting(false);
            }}
          />
        ) : null}
        {incidents.length === 0 ? (
          <p className="text-sm text-slate-400">No incident or exercise recorded.</p>
        ) : (
          <ul className="space-y-3">
            {incidents.map((incident) => (
              <li
                key={incident.id}
                className="space-y-2 rounded-lg border border-slate-800 p-3"
                data-testid={`incident-${incident.code}`}
              >
                <p className="flex flex-wrap items-center gap-2 text-sm text-slate-200">
                  <span className="font-mono text-xs text-accent-300">{incident.code}</span>
                  {incident.data.title}
                  <StatusBadge status={incident.status} />
                  <ExerciseBadge record={incident} />
                </p>
                <DetailList
                  items={[
                    { term: 'Detection', value: incident.data.detection },
                    { term: 'Classification', value: statusLabel(incident.data.classification) },
                    { term: 'Impact', value: incident.data.impact },
                    ...(incident.data.containment === undefined
                      ? []
                      : [{ term: 'Containment', value: incident.data.containment }]),
                    ...(incident.data.recovery === undefined
                      ? []
                      : [{ term: 'Recovery', value: incident.data.recovery }]),
                    ...(incident.data.lessons === undefined
                      ? []
                      : [{ term: 'Lessons learned', value: incident.data.lessons }]),
                  ]}
                />
                <TransitionPanel record={incident} />
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card
        title="Change control (control 8.32)"
        icon="signature"
        description="Changes reach main only through pull requests with passing CI (POL-09). Approvals are what GitHub records: a merge by the project owner; no other approval is claimed."
      >
        <ul className="space-y-2 text-sm">
          {CHANGES.map((change) => (
            <li key={change.pr} className="rounded-lg border border-slate-800 p-2.5">
              <a
                className="text-accent-300 underline"
                href={`https://github.com/mhmmdimanquliyev7-dot/CipherMesh/pull/${String(change.pr)}`}
                rel="noreferrer noopener"
                target="_blank"
              >
                Pull request #{change.pr}
              </a>{' '}
              <span className="text-slate-200">{change.title}</span>
              <p className="text-xs text-slate-400">
                Merge commit {change.merge} · {change.ci} · evidence {change.evidence}
              </p>
            </li>
          ))}
        </ul>
      </Card>

      <Card
        title={`Exercise records (${String(exercises.length)})`}
        icon="play"
        description="Labelled demonstration records. Withdrawing one hides it from the views and metrics; its history stays."
        actions={
          <SecondaryButton
            type="button"
            onClick={() => {
              setShowWithdrawn(!showWithdrawn);
            }}
          >
            {showWithdrawn ? 'Hide withdrawn' : 'Show withdrawn'}
          </SecondaryButton>
        }
      >
        {exercises.length === 0 ? (
          <p className="text-sm text-slate-400">No exercise records.</p>
        ) : (
          <ul className="space-y-2">
            {exercises.map((record) => (
              <li key={record.id} className="space-y-1 rounded-lg border border-slate-800 p-2.5 text-sm">
                <p className="flex flex-wrap items-center gap-2">
                  <RecordLink code={record.code} />
                  <StatusBadge status={record.status} />
                  <span className="text-xs text-slate-400">{statusLabel(record.kind)}</span>
                </p>
                <TransitionPanel record={record} />
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
