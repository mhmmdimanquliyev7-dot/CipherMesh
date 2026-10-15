import {
  applicabilityOf,
  controlAssurance,
  controlById,
  dayOf,
  endOfDayPlus,
  evidenceFreshness,
  ISMS_FINAL_STATUSES,
  ISMS_STATUSES,
  ratingRank,
  recordsOf,
  reviewInputs,
  riskById,
  riskRating,
  type AuditCheckResult,
  type AuditData,
  type ControlVerificationData,
  type FindingClassification,
  type FindingData,
  type IncidentData,
  type IsmsActor,
  type IsmsCatalogue,
  type IsmsDataByKind,
  type IsmsLevel,
  type IsmsRecord,
  type IsmsRecordKind,
  type IsmsRecordOf,
  type ManagementReviewData,
  type PolicyReviewData,
  type RiskAssessmentData,
  type ScopeReviewData,
  type TreatmentOption,
} from './isms';

/**
 * The workflows of the operational ISMS (docs/security/isms-operations.md sections 6 to 13), as pure
 * functions: given a record, a named transition, its validated input and the context (time, actor,
 * every record, the catalogue), they return the new status and data, or the documented conditions
 * that are not met. The API applies them inside one transaction that has locked the record; no
 * status can be written any other way.
 */

export type IsmsAuthority = 'record' | 'decide';

export const ISMS_REPOSITORY = 'https://github.com/mhmmdimanquliyev7-dot/CipherMesh';
/** A GitHub Actions run (or job) of this repository: the only external link a verification may cite. */
export const CI_RUN_PATTERN =
  /^https:\/\/github\.com\/mhmmdimanquliyev7-dot\/CipherMesh\/actions\/runs\/\d{1,20}(\/job\/\d{1,20})?$/;

export const ATTACHMENT_MAX_BYTES = 32 * 1024;

/**
 * Secret material that must never be stored in an ISMS record (INV-10): private keys, the age
 * identity, session cookies, presigned URLs, credentials in connection strings, tokens and
 * "password = ..." assignments. A match refuses the attachment; the value is never echoed.
 */
const SECRET_PATTERNS: readonly RegExp[] = [
  /AGE-SECRET-KEY-1/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /__Host-cm_(session|preauth)=/,
  /X-Amz-(Signature|Credential)=/i,
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]+@/i,
  /\b(password|passphrase|secret|token)\s*[:=]\s*\S{6,}/i,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
];

/** UTF-8 length of a text in bytes (no TextEncoder: the shared package has no DOM types). */
export function utf8Length(text: string): number {
  let bytes = 0;
  for (const char of text) {
    const point = char.codePointAt(0) ?? 0;
    bytes += point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
  }
  return bytes;
}

export function attachmentProblem(text: string): 'TOO_LARGE' | 'SECRET_MATERIAL' | undefined {
  if (utf8Length(text) > ATTACHMENT_MAX_BYTES) return 'TOO_LARGE';
  return SECRET_PATTERNS.some((pattern) => pattern.test(text)) ? 'SECRET_MATERIAL' : undefined;
}

// ---------------------------------------------------------------------------------- inputs

export interface IsmsCreateInputs {
  readonly RISK_ASSESSMENT: {
    readonly assets: readonly string[];
    readonly threat: string;
    readonly vulnerability: string;
    readonly consequences: string;
    readonly owner: string;
    readonly likelihood: IsmsLevel;
    readonly impact: IsmsLevel;
    readonly rationale: string;
  };
  readonly CONTROL_VERIFICATION: {
    readonly method: ControlVerificationData['method'];
    readonly procedure: string;
    readonly environment: ControlVerificationData['environment'];
    readonly result: ControlVerificationData['result'];
    readonly limitations: string;
    readonly relatedRisks: readonly string[];
    readonly evidence: readonly string[];
    readonly ciRun: string | null;
    readonly attachment: { readonly label: string; readonly text: string } | null;
    readonly freshnessClass: string;
  };
  readonly AUDIT: {
    readonly title: string;
    readonly scope: string;
    readonly objective: string;
    readonly criteria: readonly string[];
    readonly scheduledFor: string;
    readonly independence: AuditData['independence'];
    readonly auditorUserId: string;
  };
  readonly FINDING: {
    readonly source: FindingData['source'];
    readonly classification: FindingClassification;
    readonly criterion: string;
    readonly observation: string;
    readonly evidence: readonly string[];
    readonly responsible: string;
    readonly relatedRisks: readonly string[];
    readonly relatedControls: readonly string[];
  };
  readonly MANAGEMENT_REVIEW: {
    readonly title: string;
    readonly reviewDate: string;
    readonly format: ManagementReviewData['format'];
    readonly participants: readonly string[];
    readonly inputNotes: string;
    readonly decisions: readonly string[];
    readonly actions: readonly { readonly description: string; readonly owner: string; readonly dueDate: string }[];
  };
  readonly SCOPE_REVIEW: {
    readonly decision: ScopeReviewData['decision'];
    readonly reason: string;
    readonly nextReviewDate: string;
  };
  readonly POLICY_REVIEW: {
    readonly decision: PolicyReviewData['decision'];
    readonly effectiveFrom: string;
    readonly nextReviewDate: string;
    readonly note: string;
  };
  readonly INCIDENT: {
    readonly title: string;
    readonly detection: string;
    readonly classification: IncidentData['classification'];
    readonly impact: string;
    readonly owner: string;
    readonly relatedRisks: readonly string[];
    readonly relatedControls: readonly string[];
  };
}

export interface IsmsTransitionInputs {
  readonly plan_treatment: {
    readonly option: TreatmentOption;
    readonly responsible: string;
    readonly controls: readonly string[];
    readonly activity: string;
    readonly targetDate: string | null;
    readonly requiredEvidence: readonly string[];
  };
  readonly verify_treatment: { readonly likelihood: IsmsLevel; readonly impact: IsmsLevel; readonly rationale: string };
  readonly accept_residual: { readonly note: string };
  readonly reject_residual: { readonly note: string };
  readonly start: Record<string, never>;
  readonly record_check: {
    readonly criterion: string;
    readonly result: AuditCheckResult;
    readonly note: string;
    readonly evidence: readonly string[];
  };
  readonly complete: { readonly conclusion: string };
  readonly analyze: { readonly rootCause: string; readonly correction: string };
  readonly plan_action: { readonly description: string; readonly owner: string; readonly dueDate: string };
  readonly implement_action: { readonly note: string };
  readonly submit_closure_evidence: { readonly verifications: readonly string[]; readonly evidence: readonly string[] };
  readonly effectiveness_check: { readonly result: 'EFFECTIVE' | 'NOT_EFFECTIVE'; readonly note: string };
  readonly update_draft: {
    readonly participants: readonly string[];
    readonly inputNotes: string;
    readonly decisions: readonly string[];
    readonly actions: readonly { readonly description: string; readonly owner: string; readonly dueDate: string }[];
  };
  readonly record_review: Record<string, never>;
  readonly contain: { readonly containment: string };
  readonly resolve: { readonly recovery: string };
  readonly close_incident: { readonly lessons: string };
  readonly withdraw: { readonly reason: string };
}

export type IsmsTransitionName = keyof IsmsTransitionInputs;

export interface IsmsTransitionSpec {
  readonly kind: IsmsRecordKind | '*';
  readonly name: IsmsTransitionName;
  readonly from: readonly string[] | '*';
  readonly authority: IsmsAuthority;
  readonly label: string;
}

/** Every named transition, its starting statuses and whether it is a decision (PA-08). */
export const ISMS_TRANSITIONS: readonly IsmsTransitionSpec[] = Object.freeze([
  {
    kind: 'RISK_ASSESSMENT',
    name: 'plan_treatment',
    from: ['ASSESSED', 'TREATMENT_PLANNED'],
    authority: 'record',
    label: 'Plan the treatment',
  },
  {
    kind: 'RISK_ASSESSMENT',
    name: 'verify_treatment',
    from: ['TREATMENT_PLANNED'],
    authority: 'record',
    label: 'Verify the treatment and reassess the residual risk',
  },
  {
    kind: 'RISK_ASSESSMENT',
    name: 'accept_residual',
    from: ['TREATMENT_VERIFIED'],
    authority: 'decide',
    label: 'Accept the residual risk',
  },
  {
    kind: 'RISK_ASSESSMENT',
    name: 'reject_residual',
    from: ['TREATMENT_VERIFIED'],
    authority: 'decide',
    label: 'Do not accept: treat further',
  },
  { kind: 'AUDIT', name: 'start', from: ['PLANNED'], authority: 'record', label: 'Start the audit' },
  { kind: 'AUDIT', name: 'record_check', from: ['IN_PROGRESS'], authority: 'record', label: 'Record a check' },
  { kind: 'AUDIT', name: 'complete', from: ['IN_PROGRESS'], authority: 'record', label: 'Complete the audit' },
  { kind: 'FINDING', name: 'analyze', from: ['OPEN'], authority: 'record', label: 'Record the root-cause analysis' },
  {
    kind: 'FINDING',
    name: 'plan_action',
    from: ['ANALYZED', 'ACTION_PLANNED'],
    authority: 'record',
    label: 'Plan the corrective action',
  },
  {
    kind: 'FINDING',
    name: 'implement_action',
    from: ['ACTION_PLANNED'],
    authority: 'record',
    label: 'Record the implementation',
  },
  {
    kind: 'FINDING',
    name: 'submit_closure_evidence',
    from: ['ACTION_IMPLEMENTED'],
    authority: 'record',
    label: 'Submit closure evidence',
  },
  {
    kind: 'FINDING',
    name: 'effectiveness_check',
    from: ['AWAITING_EFFECTIVENESS'],
    authority: 'decide',
    label: 'Check effectiveness and decide closure',
  },
  { kind: 'MANAGEMENT_REVIEW', name: 'update_draft', from: ['DRAFT'], authority: 'record', label: 'Update the draft' },
  {
    kind: 'MANAGEMENT_REVIEW',
    name: 'record_review',
    from: ['DRAFT'],
    authority: 'decide',
    label: 'Record the management review',
  },
  { kind: 'INCIDENT', name: 'contain', from: ['OPEN'], authority: 'record', label: 'Record containment' },
  { kind: 'INCIDENT', name: 'resolve', from: ['CONTAINED'], authority: 'record', label: 'Record recovery' },
  {
    kind: 'INCIDENT',
    name: 'close_incident',
    from: ['RESOLVED'],
    authority: 'decide',
    label: 'Close with lessons learned',
  },
  { kind: '*', name: 'withdraw', from: '*', authority: 'record', label: 'Withdraw this exercise record' },
] satisfies IsmsTransitionSpec[]);

export function transitionSpec(kind: IsmsRecordKind, name: string): IsmsTransitionSpec | undefined {
  return ISMS_TRANSITIONS.find((t) => t.name === name && (t.kind === kind || t.kind === '*'));
}

/** Transitions that can start from the record's current status (for the Control Center). */
export function availableTransitions(record: IsmsRecord): IsmsTransitionSpec[] {
  return ISMS_TRANSITIONS.filter((t) => {
    if (t.kind !== '*' && t.kind !== record.kind) return false;
    if (t.name === 'withdraw') return record.exercise && record.status !== 'WITHDRAWN';
    return t.from !== '*' && t.from.includes(record.status);
  });
}

/** Creating these kinds is a decision (PA-08); the others are records (PA-07). */
export function creationAuthority(kind: IsmsRecordKind): IsmsAuthority {
  return kind === 'SCOPE_REVIEW' || kind === 'POLICY_REVIEW' ? 'decide' : 'record';
}

// -------------------------------------------------------------------------------- results

export interface WorkflowContext {
  readonly now: Date;
  readonly actor: IsmsActor;
  /** Every record, for conditions that depend on other records (counted and withdrawn). */
  readonly records: readonly IsmsRecord[];
  readonly catalogue: IsmsCatalogue;
  /** Accounts that may be named as auditors (platform administrators): user ID to display name. */
  readonly people: ReadonlyMap<string, string>;
}

export type WorkflowFailureCode = 'ISMS_REFERENCE_UNKNOWN' | 'ISMS_TRANSITION_NOT_ALLOWED' | 'ISMS_CONDITION_NOT_MET';

export interface WorkflowFailure {
  readonly ok: false;
  readonly error: WorkflowFailureCode;
  readonly conditions: readonly string[];
}

/** A record created as a consequence (an audit check's finding, a review's improvement action). */
export interface SpawnedFinding<K extends IsmsRecordKind> {
  readonly ref: string;
  readonly data: FindingData;
  /** Writes the new finding's code into the parent's data. */
  link(parent: IsmsDataByKind[K], code: string): IsmsDataByKind[K];
}

export interface WorkflowSuccess<K extends IsmsRecordKind> {
  readonly ok: true;
  readonly status: string;
  readonly ref: string;
  readonly data: IsmsDataByKind[K];
  readonly spawn: readonly SpawnedFinding<K>[];
}

export type WorkflowResult<K extends IsmsRecordKind> = WorkflowSuccess<K> | WorkflowFailure;

const fail = (error: WorkflowFailureCode, ...conditions: string[]): WorkflowFailure => ({
  ok: false,
  error,
  conditions,
});
const ok = <K extends IsmsRecordKind>(
  status: string,
  ref: string,
  data: IsmsDataByKind[K],
  spawn: readonly SpawnedFinding<K>[] = [],
): WorkflowSuccess<K> => ({ ok: true, status, ref, data, spawn });

// ----------------------------------------------------------------------------- references

function unknownRefs(
  ctx: WorkflowContext,
  refs: {
    readonly risks?: readonly string[];
    readonly controls?: readonly string[];
    readonly evidence?: readonly string[];
    readonly assets?: readonly string[];
    readonly criteria?: readonly string[];
  },
): string[] {
  const c = ctx.catalogue;
  const problems: string[] = [];
  if (refs.risks?.some((id) => riskById(id, c) === undefined) === true) problems.push('RISK_UNKNOWN');
  if (refs.controls?.some((id) => controlById(id, c) === undefined) === true) problems.push('CONTROL_UNKNOWN');
  if (refs.evidence?.some((id) => !c.evidence.some((e) => e.id === id)) === true) problems.push('EVIDENCE_UNKNOWN');
  if (refs.assets?.some((id) => !c.assets.some((a) => a.id === id)) === true) problems.push('ASSET_UNKNOWN');
  if (refs.criteria?.some((id) => !isCriterion(id, c)) === true) problems.push('CRITERION_UNKNOWN');
  return problems;
}

/** A criterion is a management-system clause (as listed in the mapping) or a Statement of Applicability row. */
export function isCriterion(id: string, catalogue: IsmsCatalogue): boolean {
  return (
    controlById(id, catalogue) !== undefined ||
    catalogue.clauses.some((clause) => clause.clause.split(/,\s*/).includes(id) || clause.clause === id)
  );
}

const isPast = (day: string, now: Date): boolean => endOfDayPlus(day, 0).getTime() < now.getTime();
const isFuture = (day: string, now: Date): boolean => day > dayOf(now);

// --------------------------------------------------------------------------------- creation

export function createRecord<K extends IsmsRecordKind>(
  kind: K,
  ref: string,
  input: IsmsCreateInputs[K],
  ctx: WorkflowContext,
  extras: { readonly attachmentSha256?: string } = {},
): WorkflowResult<K> {
  // Each branch narrows `kind`; the casts restate what the branch established.
  switch (kind) {
    case 'RISK_ASSESSMENT':
      return createRiskAssessment(ref, input as IsmsCreateInputs['RISK_ASSESSMENT'], ctx) as WorkflowResult<K>;
    case 'CONTROL_VERIFICATION':
      return createVerification(
        ref,
        input as IsmsCreateInputs['CONTROL_VERIFICATION'],
        ctx,
        extras,
      ) as WorkflowResult<K>;
    case 'AUDIT':
      return createAudit(input as IsmsCreateInputs['AUDIT'], ctx) as WorkflowResult<K>;
    case 'FINDING':
      return createFinding(input as IsmsCreateInputs['FINDING'], ctx) as WorkflowResult<K>;
    case 'MANAGEMENT_REVIEW':
      return createReview(input as IsmsCreateInputs['MANAGEMENT_REVIEW'], ctx) as WorkflowResult<K>;
    case 'SCOPE_REVIEW':
      return createScopeReview(input as IsmsCreateInputs['SCOPE_REVIEW'], ctx) as WorkflowResult<K>;
    case 'POLICY_REVIEW':
      return createPolicyReview(ref, input as IsmsCreateInputs['POLICY_REVIEW'], ctx) as WorkflowResult<K>;
    case 'INCIDENT':
      return createIncident(input as IsmsCreateInputs['INCIDENT'], ctx) as WorkflowResult<K>;
  }
  return fail('ISMS_REFERENCE_UNKNOWN', 'KIND_UNKNOWN');
}

function createRiskAssessment(
  ref: string,
  input: IsmsCreateInputs['RISK_ASSESSMENT'],
  ctx: WorkflowContext,
): WorkflowResult<'RISK_ASSESSMENT'> {
  const unknown = unknownRefs(ctx, { risks: [ref], assets: input.assets });
  if (unknown.length > 0) return fail('ISMS_REFERENCE_UNKNOWN', ...unknown);
  const open = recordsOf(ctx.records, 'RISK_ASSESSMENT').some(
    (r) => r.ref === ref && !ISMS_FINAL_STATUSES.has(r.status),
  );
  if (open) return fail('ISMS_CONDITION_NOT_MET', 'ASSESSMENT_OPEN');
  const data: RiskAssessmentData = {
    assets: [...new Set(input.assets)],
    threat: input.threat,
    vulnerability: input.vulnerability,
    consequences: input.consequences,
    owner: input.owner,
    likelihood: input.likelihood,
    impact: input.impact,
    inherent: riskRating(input.likelihood, input.impact),
    rationale: input.rationale,
  };
  return ok('ASSESSED', ref, data);
}

function createVerification(
  ref: string,
  input: IsmsCreateInputs['CONTROL_VERIFICATION'],
  ctx: WorkflowContext,
  extras: { readonly attachmentSha256?: string },
): WorkflowResult<'CONTROL_VERIFICATION'> {
  const unknown = unknownRefs(ctx, { controls: [ref], risks: input.relatedRisks, evidence: input.evidence });
  if (unknown.length > 0) return fail('ISMS_REFERENCE_UNKNOWN', ...unknown);
  if (!ctx.catalogue.freshness.classes.some((c) => c.id === input.freshnessClass)) {
    return fail('ISMS_REFERENCE_UNKNOWN', 'FRESHNESS_CLASS_UNKNOWN');
  }
  const control = controlById(ref, ctx.catalogue);
  if (control !== undefined && applicabilityOf(control) === 'NOT_APPLICABLE') {
    return fail('ISMS_CONDITION_NOT_MET', 'CONTROL_NOT_APPLICABLE');
  }
  if (input.ciRun !== null && !CI_RUN_PATTERN.test(input.ciRun))
    return fail('ISMS_CONDITION_NOT_MET', 'CI_RUN_INVALID');
  const freshness = input.evidence.map((id) => evidenceFreshness(id, ctx.now, ctx.catalogue));
  if (freshness.some((f) => f.state === 'NOT_CAPTURED' || f.state === 'UNKNOWN')) {
    return fail('ISMS_CONDITION_NOT_MET', 'EVIDENCE_NOT_CAPTURED');
  }
  if (input.result === 'PASS') {
    // A PASS rests on current support; stale evidence cannot verify anything (section 7).
    if (freshness.some((f) => f.state !== 'CURRENT')) return fail('ISMS_CONDITION_NOT_MET', 'EVIDENCE_NOT_CURRENT');
    if (freshness.length === 0 && input.attachment === null && input.ciRun === null) {
      return fail('ISMS_CONDITION_NOT_MET', 'SUPPORT_REQUIRED');
    }
  }
  if (input.attachment !== null && extras.attachmentSha256 === undefined) {
    throw new Error('The attachment digest must be computed by the caller');
  }
  const cls = ctx.catalogue.freshness.classes.find((c) => c.id === input.freshnessClass);
  const own = endOfDayPlus(dayOf(ctx.now), cls?.validityDays ?? 0).getTime();
  const expiries = freshness.map((f) => (f.expires === null ? own : Date.parse(f.expires)));
  const validUntil = new Date(Math.min(own, ...expiries)).toISOString();
  const data: ControlVerificationData = {
    method: input.method,
    procedure: input.procedure,
    environment: input.environment,
    result: input.result,
    limitations: input.limitations,
    relatedRisks: [...new Set(input.relatedRisks)],
    evidence: [...new Set(input.evidence)],
    ciRun: input.ciRun,
    attachment:
      input.attachment === null || extras.attachmentSha256 === undefined
        ? null
        : {
            label: input.attachment.label,
            bytes: utf8Length(input.attachment.text),
            sha256: extras.attachmentSha256,
            text: input.attachment.text,
          },
    freshnessClass: input.freshnessClass,
    verifiedAt: ctx.now.toISOString(),
    validUntil,
  };
  return ok('RECORDED', ref, data);
}

function createAudit(input: IsmsCreateInputs['AUDIT'], ctx: WorkflowContext): WorkflowResult<'AUDIT'> {
  const unknown = unknownRefs(ctx, { criteria: input.criteria });
  const auditorName = ctx.people.get(input.auditorUserId);
  if (auditorName === undefined) unknown.push('USER_UNKNOWN');
  if (unknown.length > 0) return fail('ISMS_REFERENCE_UNKNOWN', ...unknown);
  // Independence is declared, never inferred, and an "internal audit" by its own planner is refused.
  if (input.independence === 'INTERNAL_AUDIT' && input.auditorUserId === ctx.actor.userId) {
    return fail('ISMS_CONDITION_NOT_MET', 'INDEPENDENCE_NOT_MET');
  }
  const data: AuditData = {
    title: input.title,
    scope: input.scope,
    objective: input.objective,
    criteria: [...new Set(input.criteria)],
    scheduledFor: input.scheduledFor,
    independence: input.independence,
    plannedBy: ctx.actor,
    auditor: { userId: input.auditorUserId, name: auditorName ?? '' },
    checks: [],
  };
  return ok('PLANNED', input.criteria.join(', '), data);
}

function createFinding(input: IsmsCreateInputs['FINDING'], ctx: WorkflowContext): WorkflowResult<'FINDING'> {
  const unknown = unknownRefs(ctx, {
    criteria: [input.criterion],
    risks: input.relatedRisks,
    controls: input.relatedControls,
    evidence: input.evidence,
  });
  if (unknown.length > 0) return fail('ISMS_REFERENCE_UNKNOWN', ...unknown);
  // Audit findings come only from audit checks, so every one names its audit and check.
  if (input.source.type === 'AUDIT') return fail('ISMS_CONDITION_NOT_MET', 'AUDIT_FINDINGS_FROM_CHECKS');
  if (input.source.type === 'MANAGEMENT_REVIEW') return fail('ISMS_CONDITION_NOT_MET', 'REVIEW_FINDINGS_FROM_REVIEWS');
  if (input.source.type === 'INCIDENT') {
    const incident = recordsOf(ctx.records, 'INCIDENT').find((r) => r.code === input.source.ref);
    if (incident === undefined) return fail('ISMS_REFERENCE_UNKNOWN', 'INCIDENT_UNKNOWN');
  }
  return ok('OPEN', input.criterion, newFinding(input));
}

function newFinding(input: IsmsCreateInputs['FINDING']): FindingData {
  return {
    source: input.source,
    classification: input.classification,
    criterion: input.criterion,
    observation: input.observation,
    evidence: [...new Set(input.evidence)],
    responsible: input.responsible,
    relatedRisks: [...new Set(input.relatedRisks)],
    relatedControls: [...new Set(input.relatedControls)],
    effectivenessChecks: [],
  };
}

function createReview(
  input: IsmsCreateInputs['MANAGEMENT_REVIEW'],
  ctx: WorkflowContext,
): WorkflowResult<'MANAGEMENT_REVIEW'> {
  if (isFuture(input.reviewDate, ctx.now)) return fail('ISMS_CONDITION_NOT_MET', 'DATE_IN_FUTURE');
  const data: ManagementReviewData = {
    title: input.title,
    reviewDate: input.reviewDate,
    format: input.format,
    participants: input.participants,
    inputs: reviewInputs(ctx.records, ctx.now, ctx.catalogue),
    inputNotes: input.inputNotes,
    decisions: input.decisions,
    actions: input.actions.map((action) => ({ ...action, finding: null })),
  };
  return ok('DRAFT', input.reviewDate, data);
}

function createScopeReview(
  input: IsmsCreateInputs['SCOPE_REVIEW'],
  ctx: WorkflowContext,
): WorkflowResult<'SCOPE_REVIEW'> {
  if (!isFuture(input.nextReviewDate, ctx.now)) return fail('ISMS_CONDITION_NOT_MET', 'DATE_NOT_IN_FUTURE');
  const data: ScopeReviewData = {
    scopeRevision: ctx.catalogue.scope.revision,
    scopeFingerprint: ctx.catalogue.scope.fingerprint,
    decision: input.decision,
    reason: input.reason,
    nextReviewDate: input.nextReviewDate,
  };
  return ok('RECORDED', `scope-r${String(ctx.catalogue.scope.revision)}`, data);
}

function createPolicyReview(
  ref: string,
  input: IsmsCreateInputs['POLICY_REVIEW'],
  ctx: WorkflowContext,
): WorkflowResult<'POLICY_REVIEW'> {
  const policy = ctx.catalogue.policies.find((p) => p.id === ref);
  if (policy === undefined) return fail('ISMS_REFERENCE_UNKNOWN', 'POLICY_UNKNOWN');
  if (!isFuture(input.nextReviewDate, ctx.now)) return fail('ISMS_CONDITION_NOT_MET', 'DATE_NOT_IN_FUTURE');
  const data: PolicyReviewData = {
    documentFingerprint: policy.fingerprint,
    decision: input.decision,
    effectiveFrom: input.effectiveFrom,
    nextReviewDate: input.nextReviewDate,
    note: input.note,
  };
  return ok('RECORDED', ref, data);
}

function createIncident(input: IsmsCreateInputs['INCIDENT'], ctx: WorkflowContext): WorkflowResult<'INCIDENT'> {
  const unknown = unknownRefs(ctx, { risks: input.relatedRisks, controls: input.relatedControls });
  if (unknown.length > 0) return fail('ISMS_REFERENCE_UNKNOWN', ...unknown);
  const data: IncidentData = {
    title: input.title,
    detection: input.detection,
    classification: input.classification,
    impact: input.impact,
    owner: input.owner,
    relatedRisks: [...new Set(input.relatedRisks)],
    relatedControls: [...new Set(input.relatedControls)],
  };
  return ok('OPEN', input.title, data);
}

// ------------------------------------------------------------------------------ transitions

/** Applies a named transition. The caller has checked the authority of the route and the version. */
export function applyTransition(
  record: IsmsRecord,
  name: IsmsTransitionName,
  input: IsmsTransitionInputs[IsmsTransitionName],
  ctx: WorkflowContext,
): WorkflowResult<IsmsRecordKind> {
  const spec = transitionSpec(record.kind, name);
  if (spec === undefined) return fail('ISMS_TRANSITION_NOT_ALLOWED', 'TRANSITION_UNKNOWN');
  if (name === 'withdraw') {
    if (record.status === 'WITHDRAWN') return fail('ISMS_TRANSITION_NOT_ALLOWED', 'STATUS');
    // Real records are never withdrawn; only labelled exercises can be (section 13).
    if (!record.exercise) return fail('ISMS_CONDITION_NOT_MET', 'EXERCISE_ONLY');
    return ok('WITHDRAWN', record.ref, record.data);
  }
  if (spec.from === '*' || !spec.from.includes(record.status)) return fail('ISMS_TRANSITION_NOT_ALLOWED', 'STATUS');
  switch (record.kind) {
    case 'RISK_ASSESSMENT':
      return riskTransition(record, name, input, ctx);
    case 'AUDIT':
      return auditTransition(record, name, input, ctx);
    case 'FINDING':
      return findingTransition(record, name, input, ctx);
    case 'MANAGEMENT_REVIEW':
      return reviewTransition(record, name, input, ctx);
    case 'INCIDENT':
      return incidentTransition(record, name, input);
    default:
      return fail('ISMS_TRANSITION_NOT_ALLOWED', 'TRANSITION_UNKNOWN');
  }
}

type In<N extends IsmsTransitionName> = IsmsTransitionInputs[N];

function riskTransition(
  record: IsmsRecordOf<'RISK_ASSESSMENT'>,
  name: IsmsTransitionName,
  input: In<IsmsTransitionName>,
  ctx: WorkflowContext,
): WorkflowResult<'RISK_ASSESSMENT'> {
  const data = record.data;
  if (name === 'plan_treatment') {
    const plan = input as In<'plan_treatment'>;
    const unknown = unknownRefs(ctx, { controls: plan.controls, evidence: plan.requiredEvidence });
    if (unknown.length > 0) return fail('ISMS_REFERENCE_UNKNOWN', ...unknown);
    if (plan.option === 'MITIGATE' && plan.controls.length === 0)
      return fail('ISMS_CONDITION_NOT_MET', 'CONTROLS_REQUIRED');
    const notApplicable = plan.controls.some((id) => {
      const control = controlById(id, ctx.catalogue);
      return control === undefined || applicabilityOf(control) === 'NOT_APPLICABLE';
    });
    if (notApplicable) return fail('ISMS_CONDITION_NOT_MET', 'CONTROL_NOT_APPLICABLE');
    if (plan.targetDate !== null && isPast(plan.targetDate, ctx.now))
      return fail('ISMS_CONDITION_NOT_MET', 'DATE_IN_PAST');
    return ok('TREATMENT_PLANNED', record.ref, {
      ...data,
      treatment: {
        option: plan.option,
        responsible: plan.responsible,
        controls: [...new Set(plan.controls)],
        activity: plan.activity,
        targetDate: plan.targetDate,
        requiredEvidence: [...new Set(plan.requiredEvidence)],
        plannedAt: ctx.now.toISOString(),
      },
    });
  }
  if (name === 'verify_treatment') {
    const residual = input as In<'verify_treatment'>;
    const controls = data.treatment?.controls ?? [];
    const assurance = controls.map((id) => {
      const control = controlById(id, ctx.catalogue);
      return control === undefined ? undefined : controlAssurance(control, ctx.records, ctx.now, ctx.catalogue);
    });
    if (assurance.some((a) => a?.state !== 'VERIFIED')) return fail('ISMS_CONDITION_NOT_MET', 'CONTROL_NOT_VERIFIED');
    const rating = riskRating(residual.likelihood, residual.impact);
    if (ratingRank(rating) > ratingRank(data.inherent))
      return fail('ISMS_CONDITION_NOT_MET', 'RESIDUAL_ABOVE_INHERENT');
    return ok('TREATMENT_VERIFIED', record.ref, {
      ...data,
      residual: {
        likelihood: residual.likelihood,
        impact: residual.impact,
        rating,
        rationale: residual.rationale,
        verifications: assurance.flatMap((a) => (a?.latest === undefined ? [] : [a.latest.code])),
        verifiedAt: ctx.now.toISOString(),
        verifiedBy: ctx.actor,
      },
    });
  }
  const decision = input as In<'accept_residual'>;
  if (name === 'accept_residual') {
    const rating = data.residual?.rating;
    if (rating === undefined) return fail('ISMS_CONDITION_NOT_MET', 'RESIDUAL_REQUIRED');
    // Section 6: Critical is never accepted; High needs a documented limitation.
    if (rating === 'Critical') return fail('ISMS_CONDITION_NOT_MET', 'CRITICAL_NOT_ACCEPTABLE');
    if (rating === 'High' && (riskById(record.ref, ctx.catalogue)?.limitations.length ?? 0) === 0) {
      return fail('ISMS_CONDITION_NOT_MET', 'LIMITATION_REQUIRED');
    }
    return ok('RESIDUAL_ACCEPTED', record.ref, {
      ...data,
      acceptance: { decision: 'ACCEPTED', note: decision.note, by: ctx.actor, at: ctx.now.toISOString() },
    });
  }
  if (name === 'reject_residual') {
    return ok('TREATMENT_PLANNED', record.ref, {
      ...data,
      acceptance: { decision: 'NOT_ACCEPTED', note: decision.note, by: ctx.actor, at: ctx.now.toISOString() },
    });
  }
  return fail('ISMS_TRANSITION_NOT_ALLOWED', 'TRANSITION_UNKNOWN');
}

const FINDING_OF_CHECK: Readonly<Record<Exclude<AuditCheckResult, 'CONFORMITY'>, FindingClassification>> = {
  MAJOR_NONCONFORMITY: 'MAJOR_NONCONFORMITY',
  MINOR_NONCONFORMITY: 'MINOR_NONCONFORMITY',
  OBSERVATION: 'OBSERVATION',
  IMPROVEMENT: 'IMPROVEMENT',
  INSUFFICIENT_EVIDENCE: 'INSUFFICIENT_EVIDENCE',
};

function auditTransition(
  record: IsmsRecordOf<'AUDIT'>,
  name: IsmsTransitionName,
  input: In<IsmsTransitionName>,
  ctx: WorkflowContext,
): WorkflowResult<'AUDIT'> {
  const data = record.data;
  // An internal audit is performed by its assigned auditor only.
  if (data.independence === 'INTERNAL_AUDIT' && ctx.actor.userId !== data.auditor.userId) {
    return fail('ISMS_CONDITION_NOT_MET', 'AUDITOR_ONLY');
  }
  if (name === 'start') return ok('IN_PROGRESS', record.ref, { ...data, startedAt: ctx.now.toISOString() });
  if (name === 'record_check') {
    const check = input as In<'record_check'>;
    const unknown = unknownRefs(ctx, { evidence: check.evidence });
    if (unknown.length > 0) return fail('ISMS_REFERENCE_UNKNOWN', ...unknown);
    if (!data.criteria.includes(check.criterion)) return fail('ISMS_CONDITION_NOT_MET', 'CRITERION_NOT_IN_SCOPE');
    const index = data.checks.length;
    const next: AuditData = {
      ...data,
      checks: [
        ...data.checks,
        {
          criterion: check.criterion,
          result: check.result,
          note: check.note,
          evidence: [...new Set(check.evidence)],
          finding: null,
          by: ctx.actor,
          at: ctx.now.toISOString(),
        },
      ],
    };
    if (check.result === 'CONFORMITY') return ok('IN_PROGRESS', record.ref, next);
    // Every result other than conformity becomes a finding in the same transaction (section 9).
    const control = controlById(check.criterion, ctx.catalogue);
    const finding: FindingData = {
      source: { type: 'AUDIT', ref: record.code },
      classification: FINDING_OF_CHECK[check.result],
      criterion: check.criterion,
      observation: check.note,
      evidence: [...new Set(check.evidence)],
      responsible: 'ROLE-01',
      relatedRisks: control === undefined ? [] : riskIdsOf(check.criterion, ctx),
      relatedControls: control === undefined ? [] : [check.criterion],
      effectivenessChecks: [],
    };
    return ok('IN_PROGRESS', record.ref, next, [
      {
        ref: check.criterion,
        data: finding,
        link: (parent, code) => ({
          ...parent,
          checks: parent.checks.map((c, i) => (i === index ? { ...c, finding: code } : c)),
        }),
      },
    ]);
  }
  if (name === 'complete') {
    if (data.checks.length === 0) return fail('ISMS_CONDITION_NOT_MET', 'CHECKS_REQUIRED');
    const { conclusion } = input as In<'complete'>;
    return ok('COMPLETED', record.ref, { ...data, conclusion, completedAt: ctx.now.toISOString() });
  }
  return fail('ISMS_TRANSITION_NOT_ALLOWED', 'TRANSITION_UNKNOWN');
}

function riskIdsOf(controlId: string, ctx: WorkflowContext): string[] {
  return ctx.catalogue.risks.filter((r) => r.controls.includes(controlId)).map((r) => r.id);
}

function findingTransition(
  record: IsmsRecordOf<'FINDING'>,
  name: IsmsTransitionName,
  input: In<IsmsTransitionName>,
  ctx: WorkflowContext,
): WorkflowResult<'FINDING'> {
  const data = record.data;
  const at = ctx.now.toISOString();
  switch (name) {
    case 'analyze': {
      const { rootCause, correction } = input as In<'analyze'>;
      return ok('ANALYZED', record.ref, { ...data, analysis: { rootCause, correction, at, by: ctx.actor } });
    }
    case 'plan_action': {
      const action = input as In<'plan_action'>;
      if (isPast(action.dueDate, ctx.now)) return fail('ISMS_CONDITION_NOT_MET', 'DATE_IN_PAST');
      return ok('ACTION_PLANNED', record.ref, { ...data, action: { ...action, plannedAt: at, by: ctx.actor } });
    }
    case 'implement_action': {
      const { note } = input as In<'implement_action'>;
      return ok('ACTION_IMPLEMENTED', record.ref, { ...data, implementation: { note, at, by: ctx.actor } });
    }
    case 'submit_closure_evidence': {
      const support = input as In<'submit_closure_evidence'>;
      const plannedAt = data.action?.plannedAt ?? data.analysis?.at ?? record.createdAt;
      const verifications = support.verifications.map((code) =>
        recordsOf(ctx.records, 'CONTROL_VERIFICATION').find((r) => r.code === code),
      );
      if (verifications.some((v) => v === undefined)) return fail('ISMS_REFERENCE_UNKNOWN', 'VERIFICATION_UNKNOWN');
      const unknown = unknownRefs(ctx, { evidence: support.evidence });
      if (unknown.length > 0) return fail('ISMS_REFERENCE_UNKNOWN', ...unknown);
      // Closure evidence must postdate the plan: a PASS of a related control recorded after it.
      const eligible = verifications.every(
        (v) =>
          v !== undefined &&
          v.data.result === 'PASS' &&
          v.createdAt > plannedAt &&
          (data.relatedControls.length === 0 || data.relatedControls.includes(v.ref)),
      );
      if (!eligible) return fail('ISMS_CONDITION_NOT_MET', 'VERIFICATION_NOT_ELIGIBLE');
      if (support.evidence.some((id) => evidenceFreshness(id, ctx.now, ctx.catalogue).state !== 'CURRENT')) {
        return fail('ISMS_CONDITION_NOT_MET', 'EVIDENCE_NOT_CURRENT');
      }
      if (support.verifications.length + support.evidence.length === 0) {
        return fail('ISMS_CONDITION_NOT_MET', 'SUPPORT_REQUIRED');
      }
      return ok('AWAITING_EFFECTIVENESS', record.ref, {
        ...data,
        closureEvidence: {
          verifications: [...new Set(support.verifications)],
          evidence: [...new Set(support.evidence)],
          at,
          by: ctx.actor,
        },
      });
    }
    case 'effectiveness_check': {
      const check = input as In<'effectiveness_check'>;
      if (check.result === 'EFFECTIVE') {
        // Closure needs every related control verified now, not only at submission (section 10).
        const notVerified = data.relatedControls.some((id) => {
          const control = controlById(id, ctx.catalogue);
          return (
            control === undefined || controlAssurance(control, ctx.records, ctx.now, ctx.catalogue).state !== 'VERIFIED'
          );
        });
        if (notVerified) return fail('ISMS_CONDITION_NOT_MET', 'CONTROL_NOT_VERIFIED');
      }
      const entry = {
        result: check.result,
        note: check.note,
        by: ctx.actor,
        at,
        independentOfImplementer: data.implementation?.by.userId !== ctx.actor.userId,
      };
      const next: FindingData = { ...data, effectivenessChecks: [...data.effectivenessChecks, entry] };
      return check.result === 'EFFECTIVE' ? ok('CLOSED', record.ref, next) : ok('ACTION_PLANNED', record.ref, next);
    }
    default:
      return fail('ISMS_TRANSITION_NOT_ALLOWED', 'TRANSITION_UNKNOWN');
  }
}

function reviewTransition(
  record: IsmsRecordOf<'MANAGEMENT_REVIEW'>,
  name: IsmsTransitionName,
  input: In<IsmsTransitionName>,
  ctx: WorkflowContext,
): WorkflowResult<'MANAGEMENT_REVIEW'> {
  const data = record.data;
  if (name === 'update_draft') {
    const draft = input as In<'update_draft'>;
    return ok('DRAFT', record.ref, {
      ...data,
      participants: draft.participants,
      inputNotes: draft.inputNotes,
      decisions: draft.decisions,
      actions: draft.actions.map((action) => ({ ...action, finding: null })),
    });
  }
  if (name === 'record_review') {
    const problems: string[] = [];
    if (data.participants.length === 0) problems.push('PARTICIPANTS_REQUIRED');
    if (data.decisions.length === 0) problems.push('DECISIONS_REQUIRED');
    if (problems.length > 0) return fail('ISMS_CONDITION_NOT_MET', ...problems);
    // Each follow-up action becomes an improvement finding, so it is tracked to closure.
    const spawn: SpawnedFinding<'MANAGEMENT_REVIEW'>[] = data.actions.map((action, index) => ({
      ref: '9.3',
      data: {
        source: { type: 'MANAGEMENT_REVIEW', ref: record.code },
        classification: 'IMPROVEMENT',
        criterion: '9.3',
        observation: `${action.description} (owner ${action.owner}, due ${action.dueDate})`,
        evidence: [],
        responsible: action.owner,
        relatedRisks: [],
        relatedControls: [],
        effectivenessChecks: [],
      },
      link: (parent, code) => ({
        ...parent,
        actions: parent.actions.map((a, i) => (i === index ? { ...a, finding: code } : a)),
      }),
    }));
    return ok('RECORDED', record.ref, { ...data, recorded: { by: ctx.actor, at: ctx.now.toISOString() } }, spawn);
  }
  return fail('ISMS_TRANSITION_NOT_ALLOWED', 'TRANSITION_UNKNOWN');
}

function incidentTransition(
  record: IsmsRecordOf<'INCIDENT'>,
  name: IsmsTransitionName,
  input: In<IsmsTransitionName>,
): WorkflowResult<'INCIDENT'> {
  const data = record.data;
  if (name === 'contain')
    return ok('CONTAINED', record.ref, { ...data, containment: (input as In<'contain'>).containment });
  if (name === 'resolve') return ok('RESOLVED', record.ref, { ...data, recovery: (input as In<'resolve'>).recovery });
  if (name === 'close_incident')
    return ok('CLOSED', record.ref, { ...data, lessons: (input as In<'close_incident'>).lessons });
  return fail('ISMS_TRANSITION_NOT_ALLOWED', 'TRANSITION_UNKNOWN');
}

/** Every status of a kind is one of the documented ones (used by the database check and tests). */
export function isStatusOf(kind: IsmsRecordKind, status: string): boolean {
  return (ISMS_STATUSES[kind] as readonly string[]).includes(status);
}
