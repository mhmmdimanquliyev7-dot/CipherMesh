import type { IsmsActor, IsmsRecord } from '@ciphermesh/shared';
import {
  ismsRecordDetailResponseSchema,
  ismsStateResponseSchema,
  ismsWriteResponseSchema,
  type IsmsActivityResponse,
  type IsmsRecordDetailResponse,
  type IsmsWriteResponse,
} from '@ciphermesh/validation';
import { api, ApiError } from '../lib/api';

/**
 * Data access of the ISMS Control Center (ADR-016). The API decides everything (PA-06 to PA-08);
 * this module only loads the state and sends creations and named transitions. A decision that the
 * server refuses with STEP_UP_REQUIRED is surfaced to the page, which asks for the account password
 * and the authentication code and then repeats the same request.
 */

export interface IsmsState {
  readonly now: Date;
  readonly records: readonly IsmsRecord[];
  readonly activity: readonly IsmsActivityResponse[];
  readonly people: readonly IsmsActor[];
}

export async function loadState(): Promise<IsmsState> {
  const data = await api('GET', '/isms/state', ismsStateResponseSchema);
  return {
    now: new Date(data.computedAt),
    // The API validated each record's content per kind when it was written (ADR-016).
    records: data.records as unknown as IsmsRecord[],
    activity: data.activity,
    people: data.people,
  };
}

export async function loadDetail(recordId: string): Promise<IsmsRecordDetailResponse> {
  return api('GET', `/isms/records/${encodeURIComponent(recordId)}`, ismsRecordDetailResponseSchema);
}

export type Write = () => Promise<IsmsWriteResponse>;

export const createRecord =
  (body: unknown): Write =>
  () =>
    api('POST', '/isms/records', ismsWriteResponseSchema, body);

export const createDecision =
  (body: unknown): Write =>
  () =>
    api('POST', '/isms/decisions', ismsWriteResponseSchema, body);

export const transition =
  (record: IsmsRecord, name: string, input: unknown): Write =>
  () =>
    api('POST', `/isms/records/${encodeURIComponent(record.id)}/transitions`, ismsWriteResponseSchema, {
      transition: name,
      expectedVersion: record.version,
      input,
    });

export const decision =
  (record: IsmsRecord, name: string, input: unknown): Write =>
  () =>
    api('POST', `/isms/records/${encodeURIComponent(record.id)}/decisions`, ismsWriteResponseSchema, {
      transition: name,
      expectedVersion: record.version,
      input,
    });

export const needsStepUp = (error: unknown): boolean =>
  error instanceof ApiError && error.status === 401 && error.code === 'STEP_UP_REQUIRED';

/** Plain-language text for the documented condition codes (docs/security/isms-operations.md). */
export const CONDITION_TEXT: Readonly<Record<string, string>> = {
  ASSESSMENT_OPEN: 'This risk already has an open assessment; finish or withdraw it first.',
  CONTROLS_REQUIRED: 'A Mitigate treatment needs at least one applicable control.',
  CONTROL_NOT_APPLICABLE: 'An excluded control cannot be used here.',
  CONTROL_NOT_VERIFIED: 'Every linked control needs a current verification first.',
  RESIDUAL_ABOVE_INHERENT: 'The residual risk cannot be higher than the inherent risk.',
  RESIDUAL_REQUIRED: 'Verify the treatment and reassess the residual risk first.',
  CRITICAL_NOT_ACCEPTABLE: 'A Critical residual risk is never accepted: treat it further.',
  LIMITATION_REQUIRED: 'A High residual risk needs a documented limitation before acceptance.',
  EVIDENCE_NOT_CURRENT: 'A cited evidence item is past its freshness rule.',
  EVIDENCE_NOT_CAPTURED: 'A cited evidence item has not been captured.',
  SUPPORT_REQUIRED: 'A PASS needs current evidence, an attached output or a CI run link.',
  CI_RUN_INVALID: 'Only a GitHub Actions run of this repository can be linked.',
  INDEPENDENCE_NOT_MET: 'An internal audit cannot be performed by the person who planned it.',
  AUDITOR_ONLY: 'Only the assigned auditor can record this internal audit.',
  CRITERION_NOT_IN_SCOPE: 'The criterion is not part of this audit.',
  CHECKS_REQUIRED: 'Record at least one check before completing the audit.',
  AUDIT_FINDINGS_FROM_CHECKS: 'Audit findings are raised by recording an audit check.',
  REVIEW_FINDINGS_FROM_REVIEWS: 'Review actions become findings when the review is recorded.',
  DATE_IN_PAST: 'The date is in the past.',
  DATE_IN_FUTURE: 'The date is in the future.',
  DATE_NOT_IN_FUTURE: 'The next review date must be in the future.',
  VERIFICATION_NOT_ELIGIBLE:
    'Closure evidence must be a PASS of a related control recorded after the action was planned.',
  PARTICIPANTS_REQUIRED: 'Name the participants who were actually present.',
  DECISIONS_REQUIRED: 'Record at least one decision.',
  EXERCISE_ONLY: 'Only exercise records can be withdrawn.',
  AUTHORITY: 'This change needs the decision route.',
  STATUS: 'Not possible from the current status.',
};

export function describeIsmsError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'ISMS_VERSION_CONFLICT') return 'The record changed in the meantime. The view was reloaded.';
    const conditions = error.issues.map((issue) => CONDITION_TEXT[issue.code] ?? issue.code);
    if (conditions.length > 0) return `${error.message}: ${conditions.join(' ')}`;
    return error.message;
  }
  return 'Unexpected error.';
}
