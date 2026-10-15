import { ISMS_CATALOGUE } from './isms-catalogue';

/**
 * Operational ISMS (ADR-016, docs/security/isms-operations.md). Pure functions shared by the API,
 * which enforces them inside its transactions, and the ISMS Control Center, which shows the same
 * computations. Nothing here reads a clock, a database or the network: the caller passes the time,
 * the records and the catalogue. Every state is derived from records and the documents; none is
 * entered by hand.
 */

// ------------------------------------------------------------------------------------ catalogue

export interface IsmsCatalogue {
  readonly sources: readonly string[];
  readonly scope: { readonly revision: number; readonly text: string; readonly fingerprint: string };
  readonly issues: readonly {
    readonly id: string;
    readonly type: string;
    readonly issue: string;
    readonly effect: string;
  }[];
  readonly parties: readonly {
    readonly id: string;
    readonly party: string;
    readonly requirements: string;
    readonly response: string;
  }[];
  readonly boundaries: readonly {
    readonly id: string;
    readonly boundary: string;
    readonly element: string;
    readonly reason: string;
  }[];
  readonly roles: readonly {
    readonly id: string;
    readonly role: string;
    readonly heldBy: string;
    readonly responsibilities: string;
    readonly permission: string;
  }[];
  readonly objectives: readonly { readonly id: string; readonly goal: string; readonly how: string }[];
  readonly policies: readonly CataloguePolicy[];
  readonly freshness: {
    readonly defaultClass: string;
    readonly classes: readonly { readonly id: string; readonly validityDays: number; readonly appliesTo: string }[];
    readonly evidence: Readonly<Record<string, string>>;
  };
  readonly metrics: readonly MetricDefinition[];
  readonly assets: readonly CatalogueAsset[];
  readonly risks: readonly CatalogueRisk[];
  readonly clauses: readonly {
    readonly clause: string;
    readonly requirement: string;
    readonly implementation: string;
  }[];
  readonly controls: readonly CatalogueControl[];
  readonly evidence: readonly CatalogueEvidence[];
}

export interface CataloguePolicy {
  readonly id: string;
  readonly title: string;
  readonly path: string;
  readonly owner: string;
  readonly reviewDays: number;
  readonly controls: readonly string[];
  readonly risks: readonly string[];
  readonly fingerprint: string;
}

export interface MetricDefinition {
  readonly id: string;
  readonly objective: string;
  readonly calculation: string;
  readonly source: string;
  readonly frequency: string;
  readonly owner: string;
  readonly target: string;
  readonly limitation: string;
}

export interface CatalogueAsset {
  readonly id: string;
  readonly asset: string;
  readonly property: string;
  readonly category: string;
  readonly owner: string;
  readonly confidentiality: string;
  readonly integrity: string;
  readonly availability: string;
  readonly location: string;
}

export interface CatalogueRisk {
  readonly id: string;
  readonly title: string;
  readonly threat: string;
  readonly likelihood: string;
  readonly impact: string;
  readonly inherent: string;
  readonly treatment: string;
  readonly residual: string;
  readonly limitations: readonly string[];
  readonly controls: readonly string[];
  readonly assets: readonly string[];
  readonly details: readonly { readonly label: string; readonly text: string }[];
}

export interface CatalogueControl {
  readonly id: string;
  readonly title: string;
  readonly theme: string;
  readonly status: string;
  readonly implementation: string;
  readonly evidence: readonly string[];
}

export interface CatalogueEvidence {
  readonly id: string;
  readonly phase: number;
  readonly title: string;
  readonly how: string;
  readonly status: string;
  readonly captured: string | null;
  readonly files: readonly string[];
}

export { ISMS_CATALOGUE };

// --------------------------------------------------------------------------------- risk method

export const ISMS_LEVELS = ['Low', 'Medium', 'High'] as const;
export type IsmsLevel = (typeof ISMS_LEVELS)[number];
export const ISMS_RATINGS = ['Low', 'Medium', 'High', 'Critical'] as const;
export type IsmsRating = (typeof ISMS_RATINGS)[number];

/** The 3x3 matrix of the threat model, section 1 (likelihood, then impact). */
const MATRIX: Readonly<Record<IsmsLevel, Readonly<Record<IsmsLevel, IsmsRating>>>> = {
  High: { Low: 'Medium', Medium: 'High', High: 'Critical' },
  Medium: { Low: 'Low', Medium: 'Medium', High: 'High' },
  Low: { Low: 'Low', Medium: 'Low', High: 'Medium' },
};

export function riskRating(likelihood: IsmsLevel, impact: IsmsLevel): IsmsRating {
  return MATRIX[likelihood][impact];
}

export function ratingRank(rating: IsmsRating): number {
  return ISMS_RATINGS.indexOf(rating);
}

/** "L", "M", "H" (the register's notation) or a word. */
export function levelOf(text: string): IsmsLevel | undefined {
  const value = text.trim();
  if (value === 'L' || value.startsWith('Low')) return 'Low';
  if (value === 'M' || value.startsWith('Medium')) return 'Medium';
  if (value === 'H' || value.startsWith('High')) return 'High';
  return undefined;
}

/** The first rating word of a register cell, for example "Low (for an attacker ...)". */
export function ratingOf(text: string): IsmsRating | undefined {
  const word = /^(Low|Medium|High|Critical)\b/.exec(text.trim())?.[1];
  return ISMS_RATINGS.find((rating) => rating === word);
}

// ------------------------------------------------------------------------------------- records

export const ISMS_RECORD_KINDS = [
  'RISK_ASSESSMENT',
  'CONTROL_VERIFICATION',
  'AUDIT',
  'FINDING',
  'MANAGEMENT_REVIEW',
  'SCOPE_REVIEW',
  'POLICY_REVIEW',
  'INCIDENT',
] as const;
export type IsmsRecordKind = (typeof ISMS_RECORD_KINDS)[number];

export const ISMS_CODE_PREFIX: Readonly<Record<IsmsRecordKind, string>> = {
  RISK_ASSESSMENT: 'RA',
  CONTROL_VERIFICATION: 'CV',
  AUDIT: 'AUD',
  FINDING: 'FND',
  MANAGEMENT_REVIEW: 'MR',
  SCOPE_REVIEW: 'SR',
  POLICY_REVIEW: 'PR',
  INCIDENT: 'INC',
};

export const ISMS_STATUSES = {
  RISK_ASSESSMENT: ['ASSESSED', 'TREATMENT_PLANNED', 'TREATMENT_VERIFIED', 'RESIDUAL_ACCEPTED', 'WITHDRAWN'],
  CONTROL_VERIFICATION: ['RECORDED', 'WITHDRAWN'],
  AUDIT: ['PLANNED', 'IN_PROGRESS', 'COMPLETED', 'WITHDRAWN'],
  FINDING: [
    'OPEN',
    'ANALYZED',
    'ACTION_PLANNED',
    'ACTION_IMPLEMENTED',
    'AWAITING_EFFECTIVENESS',
    'CLOSED',
    'WITHDRAWN',
  ],
  MANAGEMENT_REVIEW: ['DRAFT', 'RECORDED', 'WITHDRAWN'],
  SCOPE_REVIEW: ['RECORDED', 'WITHDRAWN'],
  POLICY_REVIEW: ['RECORDED', 'WITHDRAWN'],
  INCIDENT: ['OPEN', 'CONTAINED', 'RESOLVED', 'CLOSED', 'WITHDRAWN'],
} as const satisfies Record<IsmsRecordKind, readonly string[]>;

/** Statuses after which nothing changes (withdrawal included). */
export const ISMS_FINAL_STATUSES: ReadonlySet<string> = new Set([
  'RESIDUAL_ACCEPTED',
  'COMPLETED',
  'CLOSED',
  'WITHDRAWN',
]);

export interface IsmsActor {
  readonly userId: string;
  readonly name: string;
}

export const TREATMENT_OPTIONS = ['MITIGATE', 'AVOID', 'TRANSFER', 'ACCEPT'] as const;
export type TreatmentOption = (typeof TREATMENT_OPTIONS)[number];

export interface RiskAssessmentData {
  readonly assets: readonly string[];
  readonly threat: string;
  readonly vulnerability: string;
  readonly consequences: string;
  readonly owner: string;
  readonly likelihood: IsmsLevel;
  readonly impact: IsmsLevel;
  readonly inherent: IsmsRating;
  readonly rationale: string;
  readonly treatment?: {
    readonly option: TreatmentOption;
    readonly responsible: string;
    readonly controls: readonly string[];
    readonly activity: string;
    readonly targetDate: string | null;
    readonly requiredEvidence: readonly string[];
    readonly plannedAt: string;
  };
  readonly residual?: {
    readonly likelihood: IsmsLevel;
    readonly impact: IsmsLevel;
    readonly rating: IsmsRating;
    readonly rationale: string;
    /** The verification records that showed each linked control verified (codes). */
    readonly verifications: readonly string[];
    readonly verifiedAt: string;
    readonly verifiedBy: IsmsActor;
  };
  readonly acceptance?: {
    readonly decision: 'ACCEPTED' | 'NOT_ACCEPTED';
    readonly note: string;
    readonly by: IsmsActor;
    readonly at: string;
  };
}

export const VERIFICATION_METHODS = [
  'AUTOMATED_TEST',
  'CI_RUN',
  'LOCAL_VERIFICATION',
  'DOCUMENT_REVIEW',
  'MANUAL_INSPECTION',
] as const;
export const VERIFICATION_ENVIRONMENTS = ['LOCAL_DOCKER', 'CI', 'DEVELOPMENT', 'DOCUMENTATION'] as const;
export const VERIFICATION_RESULTS = ['PASS', 'FAIL', 'INCONCLUSIVE'] as const;

export interface ControlVerificationData {
  readonly method: (typeof VERIFICATION_METHODS)[number];
  readonly procedure: string;
  readonly environment: (typeof VERIFICATION_ENVIRONMENTS)[number];
  readonly result: (typeof VERIFICATION_RESULTS)[number];
  readonly limitations: string;
  readonly relatedRisks: readonly string[];
  readonly evidence: readonly string[];
  readonly ciRun: string | null;
  /** Attached output: the text is returned only by the record detail, never by lists. */
  readonly attachment: {
    readonly label: string;
    readonly bytes: number;
    readonly sha256: string;
    readonly text?: string;
  } | null;
  readonly freshnessClass: string;
  readonly verifiedAt: string;
  readonly validUntil: string;
}

export const AUDIT_INDEPENDENCE = ['SELF_ASSESSMENT', 'SIMULATED_INTERNAL_AUDIT', 'INTERNAL_AUDIT'] as const;
export const AUDIT_CHECK_RESULTS = [
  'CONFORMITY',
  'MAJOR_NONCONFORMITY',
  'MINOR_NONCONFORMITY',
  'OBSERVATION',
  'IMPROVEMENT',
  'INSUFFICIENT_EVIDENCE',
] as const;
export type AuditCheckResult = (typeof AUDIT_CHECK_RESULTS)[number];

export interface AuditData {
  readonly title: string;
  readonly scope: string;
  readonly objective: string;
  readonly criteria: readonly string[];
  readonly scheduledFor: string;
  readonly independence: (typeof AUDIT_INDEPENDENCE)[number];
  readonly plannedBy: IsmsActor;
  readonly auditor: IsmsActor;
  readonly startedAt?: string;
  readonly checks: readonly {
    readonly criterion: string;
    readonly result: AuditCheckResult;
    readonly note: string;
    readonly evidence: readonly string[];
    readonly finding: string | null;
    readonly by: IsmsActor;
    readonly at: string;
  }[];
  readonly conclusion?: string;
  readonly completedAt?: string;
}

export const FINDING_CLASSIFICATIONS = [
  'MAJOR_NONCONFORMITY',
  'MINOR_NONCONFORMITY',
  'OBSERVATION',
  'IMPROVEMENT',
  'INSUFFICIENT_EVIDENCE',
] as const;
export type FindingClassification = (typeof FINDING_CLASSIFICATIONS)[number];
export const FINDING_SOURCES = [
  'AUDIT',
  'SELF_ASSESSMENT',
  'EVIDENCE_FRESHNESS',
  'INCIDENT',
  'MANAGEMENT_REVIEW',
  'OTHER',
] as const;

export interface FindingData {
  readonly source: { readonly type: (typeof FINDING_SOURCES)[number]; readonly ref: string | null };
  readonly classification: FindingClassification;
  readonly criterion: string;
  readonly observation: string;
  readonly evidence: readonly string[];
  readonly responsible: string;
  readonly relatedRisks: readonly string[];
  readonly relatedControls: readonly string[];
  readonly analysis?: {
    readonly rootCause: string;
    readonly correction: string;
    readonly at: string;
    readonly by: IsmsActor;
  };
  readonly action?: {
    readonly description: string;
    readonly owner: string;
    readonly dueDate: string;
    readonly plannedAt: string;
    readonly by: IsmsActor;
  };
  readonly implementation?: { readonly note: string; readonly at: string; readonly by: IsmsActor };
  readonly closureEvidence?: {
    readonly verifications: readonly string[];
    readonly evidence: readonly string[];
    readonly at: string;
    readonly by: IsmsActor;
  };
  readonly effectivenessChecks: readonly {
    readonly result: 'EFFECTIVE' | 'NOT_EFFECTIVE';
    readonly note: string;
    readonly by: IsmsActor;
    readonly at: string;
    /** False when the checker is the person who recorded the implementation (self-verification). */
    readonly independentOfImplementer: boolean;
  }[];
}

export const REVIEW_FORMATS = ['ONE_PERSON_PROJECT_REVIEW', 'PROJECT_TEAM_REVIEW'] as const;

export interface ManagementReviewData {
  readonly title: string;
  readonly reviewDate: string;
  readonly format: (typeof REVIEW_FORMATS)[number];
  readonly participants: readonly string[];
  readonly inputs: ReviewInputs;
  readonly inputNotes: string;
  readonly decisions: readonly string[];
  readonly actions: readonly {
    readonly description: string;
    readonly owner: string;
    readonly dueDate: string;
    readonly finding: string | null;
  }[];
  readonly recorded?: { readonly by: IsmsActor; readonly at: string };
}

export interface ScopeReviewData {
  readonly scopeRevision: number;
  readonly scopeFingerprint: string;
  readonly decision: 'CONFIRMED' | 'CHANGES_REQUIRED';
  readonly reason: string;
  readonly nextReviewDate: string;
}

export const POLICY_DECISIONS = ['ADOPTED', 'REVIEWED_NO_CHANGE', 'CHANGES_REQUIRED', 'RETIRED'] as const;

export interface PolicyReviewData {
  readonly documentFingerprint: string;
  readonly decision: (typeof POLICY_DECISIONS)[number];
  readonly effectiveFrom: string;
  readonly nextReviewDate: string;
  readonly note: string;
}

export interface IncidentData {
  readonly title: string;
  readonly detection: string;
  readonly classification: 'SECURITY_EVENT' | 'SECURITY_INCIDENT';
  readonly impact: string;
  readonly owner: string;
  readonly relatedRisks: readonly string[];
  readonly relatedControls: readonly string[];
  readonly containment?: string;
  readonly recovery?: string;
  readonly lessons?: string;
}

export interface IsmsDataByKind {
  readonly RISK_ASSESSMENT: RiskAssessmentData;
  readonly CONTROL_VERIFICATION: ControlVerificationData;
  readonly AUDIT: AuditData;
  readonly FINDING: FindingData;
  readonly MANAGEMENT_REVIEW: ManagementReviewData;
  readonly SCOPE_REVIEW: ScopeReviewData;
  readonly POLICY_REVIEW: PolicyReviewData;
  readonly INCIDENT: IncidentData;
}

export interface IsmsRecordOf<K extends IsmsRecordKind> {
  readonly id: string;
  readonly kind: K;
  readonly code: string;
  readonly ref: string;
  readonly status: string;
  readonly data: IsmsDataByKind[K];
  readonly version: number;
  readonly exercise: boolean;
  readonly createdAt: string;
  readonly createdBy: IsmsActor;
  readonly updatedAt: string;
  readonly updatedBy: IsmsActor;
}

export type IsmsRecord = { [K in IsmsRecordKind]: IsmsRecordOf<K> }[IsmsRecordKind];

/** Records of one kind that count (not withdrawn), newest first. */
export function recordsOf<K extends IsmsRecordKind>(
  records: readonly IsmsRecord[],
  kind: K,
  options: { readonly includeWithdrawn?: boolean } = {},
): IsmsRecordOf<K>[] {
  // The kind check establishes the element type; TypeScript cannot narrow a generic union by it.
  const matching = records.filter(
    (r) => r.kind === kind && (options.includeWithdrawn === true || r.status !== 'WITHDRAWN'),
  ) as unknown as IsmsRecordOf<K>[];
  return matching.sort((a, b) =>
    a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : b.code.localeCompare(a.code),
  );
}

// --------------------------------------------------------------------------------------- dates

const DAY_MS = 24 * 60 * 60 * 1000;

/** The UTC calendar day of a time, as YYYY-MM-DD. */
export function dayOf(time: Date | string): string {
  return new Date(time).toISOString().slice(0, 10);
}

/** End of a UTC calendar day plus whole days: the instant a validity window closes. */
export function endOfDayPlus(day: string, days: number): Date {
  return new Date(Date.parse(`${day}T00:00:00.000Z`) + (days + 1) * DAY_MS - 1);
}

export function addDays(time: Date | string, days: number): Date {
  return new Date(new Date(time).getTime() + days * DAY_MS);
}

// ------------------------------------------------------------------------------- freshness

export type EvidenceFreshnessState = 'CURRENT' | 'STALE' | 'UNDATED' | 'NOT_CAPTURED' | 'UNKNOWN';

export interface EvidenceFreshness {
  readonly id: string;
  readonly state: EvidenceFreshnessState;
  readonly captured: string | null;
  readonly expires: string | null;
  readonly freshnessClass: string;
  readonly validityDays: number;
}

export function freshnessClassOf(evidenceId: string, catalogue: IsmsCatalogue = ISMS_CATALOGUE) {
  const id = catalogue.freshness.evidence[evidenceId] ?? catalogue.freshness.defaultClass;
  const cls = catalogue.freshness.classes.find((c) => c.id === id);
  if (cls === undefined) throw new Error(`Unknown freshness class ${id}`);
  return cls;
}

/** The freshness rule of section 7: current for the validity of its class from its capture date. */
export function evidenceFreshness(
  evidenceId: string,
  now: Date,
  catalogue: IsmsCatalogue = ISMS_CATALOGUE,
): EvidenceFreshness {
  const item = catalogue.evidence.find((e) => e.id === evidenceId);
  const cls = freshnessClassOf(evidenceId, catalogue);
  const base = { id: evidenceId, freshnessClass: cls.id, validityDays: cls.validityDays };
  if (item === undefined) return { ...base, state: 'UNKNOWN', captured: null, expires: null };
  if (item.status !== 'captured' && item.status !== 'partial') {
    return { ...base, state: 'NOT_CAPTURED', captured: null, expires: null };
  }
  if (item.captured === null) return { ...base, state: 'UNDATED', captured: null, expires: null };
  const expires = endOfDayPlus(item.captured, cls.validityDays);
  return {
    ...base,
    state: now.getTime() <= expires.getTime() ? 'CURRENT' : 'STALE',
    captured: item.captured,
    expires: expires.toISOString(),
  };
}

// ------------------------------------------------------------------- Statement of Applicability

export type Applicability = 'APPLICABLE' | 'NOT_APPLICABLE' | 'PROVIDER';

export function applicabilityOf(control: CatalogueControl): Applicability {
  if (control.status === 'Not applicable') return 'NOT_APPLICABLE';
  if (control.status === 'Provider') return 'PROVIDER';
  return 'APPLICABLE';
}

/** Annex A control numbers (5.1 to 5.37, 6.1 to 6.8, 7.1 to 7.14, 8.1 to 8.34): numbers only. */
export const ANNEX_A_NUMBERS: readonly string[] = Object.freeze(
  (
    [
      [5, 37],
      [6, 8],
      [7, 14],
      [8, 34],
    ] as const
  ).flatMap(([theme, count]) => Array.from({ length: count }, (_, i) => `${String(theme)}.${String(i + 1)}`)),
);

/** The Annex A numbers one Statement of Applicability row covers ("8.5" or "5.19 to 5.22"). */
export function annexNumbersOf(rowId: string): string[] {
  const range = /^(\d+)\.(\d+) to (\d+)\.(\d+)$/.exec(rowId);
  if (range === null) return [rowId];
  const [, theme, from, , to] = range;
  return Array.from({ length: Number(to) - Number(from) + 1 }, (_, i) => `${theme ?? ''}.${String(Number(from) + i)}`);
}

/** Annex A numbers that no row covers: not assessed, never applicable by default. */
export function notAssessedAnnexNumbers(catalogue: IsmsCatalogue = ISMS_CATALOGUE): string[] {
  const covered = new Set(catalogue.controls.flatMap((c) => annexNumbersOf(c.id)));
  return ANNEX_A_NUMBERS.filter((n) => !covered.has(n));
}

export type ControlAssuranceState =
  | 'VERIFIED'
  | 'VERIFICATION_DUE'
  | 'FAILED'
  | 'EVIDENCE_CURRENT'
  | 'EVIDENCE_STALE'
  | 'NO_EVIDENCE'
  | 'NOT_APPLICABLE'
  | 'PROVIDER';

export interface ControlAssurance {
  readonly control: CatalogueControl;
  readonly applicability: Applicability;
  readonly state: ControlAssuranceState;
  readonly latest: IsmsRecordOf<'CONTROL_VERIFICATION'> | undefined;
  readonly validUntil: string | null;
  readonly evidence: readonly EvidenceFreshness[];
  readonly risks: readonly string[];
}

export function controlById(id: string, catalogue: IsmsCatalogue = ISMS_CATALOGUE): CatalogueControl | undefined {
  return catalogue.controls.find((c) => c.id === id);
}

/** Risks linked to a row: the baseline mapping plus treatment records that link it. */
export function risksOfControl(
  controlId: string,
  records: readonly IsmsRecord[],
  catalogue: IsmsCatalogue = ISMS_CATALOGUE,
): string[] {
  const linked = new Set(catalogue.risks.filter((r) => r.controls.includes(controlId)).map((r) => r.id));
  for (const record of recordsOf(records, 'RISK_ASSESSMENT')) {
    if (record.data.treatment?.controls.includes(controlId) === true) linked.add(record.ref);
  }
  return [...linked].sort();
}

/** Section 7: the assurance of one Statement of Applicability row, computed, never stored. */
export function controlAssurance(
  control: CatalogueControl,
  records: readonly IsmsRecord[],
  now: Date,
  catalogue: IsmsCatalogue = ISMS_CATALOGUE,
): ControlAssurance {
  const applicability = applicabilityOf(control);
  const evidence = control.evidence.map((id) => evidenceFreshness(id, now, catalogue));
  const latest = recordsOf(records, 'CONTROL_VERIFICATION').find((r) => r.ref === control.id);
  const risks = risksOfControl(control.id, records, catalogue);
  const base = { control, applicability, latest, evidence, risks, validUntil: latest?.data.validUntil ?? null };
  if (applicability === 'NOT_APPLICABLE') return { ...base, state: 'NOT_APPLICABLE' };
  if (latest !== undefined) {
    if (latest.data.result !== 'PASS') return { ...base, state: 'FAILED' };
    return { ...base, state: now.getTime() <= Date.parse(latest.data.validUntil) ? 'VERIFIED' : 'VERIFICATION_DUE' };
  }
  if (applicability === 'PROVIDER') return { ...base, state: 'PROVIDER' };
  if (evidence.some((e) => e.state === 'CURRENT')) return { ...base, state: 'EVIDENCE_CURRENT' };
  if (evidence.some((e) => e.state === 'STALE' || e.state === 'UNDATED')) return { ...base, state: 'EVIDENCE_STALE' };
  return { ...base, state: 'NO_EVIDENCE' };
}

export function allControlAssurance(
  records: readonly IsmsRecord[],
  now: Date,
  catalogue: IsmsCatalogue = ISMS_CATALOGUE,
): ControlAssurance[] {
  return catalogue.controls.map((control) => controlAssurance(control, records, now, catalogue));
}

// ------------------------------------------------------------------------------------- risks

export interface RiskView {
  readonly risk: CatalogueRisk;
  /** REGISTER: the documented baseline; RECORD: a dated re-assessment in the Control Center. */
  readonly source: 'REGISTER' | 'RECORD';
  readonly likelihood: IsmsLevel;
  readonly impact: IsmsLevel;
  readonly inherent: IsmsRating;
  readonly residual: IsmsRating | null;
  readonly residualSource: 'REGISTER' | 'RECORD' | null;
  readonly status: string;
  readonly assessment: IsmsRecordOf<'RISK_ASSESSMENT'> | undefined;
  readonly controls: readonly string[];
}

export function riskById(id: string, catalogue: IsmsCatalogue = ISMS_CATALOGUE): CatalogueRisk | undefined {
  return catalogue.risks.find((r) => r.id === id);
}

export function riskView(risk: CatalogueRisk, records: readonly IsmsRecord[]): RiskView {
  const assessment = recordsOf(records, 'RISK_ASSESSMENT').find((r) => r.ref === risk.id);
  const controls = [...new Set([...risk.controls, ...(assessment?.data.treatment?.controls ?? [])])];
  if (assessment !== undefined) {
    const residual = assessment.data.residual?.rating ?? ratingOf(risk.residual) ?? null;
    return {
      risk,
      source: 'RECORD',
      likelihood: assessment.data.likelihood,
      impact: assessment.data.impact,
      inherent: assessment.data.inherent,
      residual,
      residualSource: assessment.data.residual === undefined ? (residual === null ? null : 'REGISTER') : 'RECORD',
      status: assessment.status,
      assessment,
      controls,
    };
  }
  const likelihood = levelOf(risk.likelihood) ?? 'High';
  const impact = levelOf(risk.impact) ?? 'High';
  const residual = ratingOf(risk.residual) ?? null;
  return {
    risk,
    source: 'REGISTER',
    likelihood,
    impact,
    inherent: ratingOf(risk.inherent) ?? riskRating(likelihood, impact),
    residual,
    residualSource: residual === null ? null : 'REGISTER',
    status: 'DOCUMENTED',
    assessment: undefined,
    controls,
  };
}

/** Counts per likelihood and impact cell, from the current views (the heat map). */
export function riskMatrix(views: readonly RiskView[]): Record<IsmsLevel, Record<IsmsLevel, number>> {
  const zero = (): Record<IsmsLevel, number> => ({ Low: 0, Medium: 0, High: 0 });
  const matrix = { Low: zero(), Medium: zero(), High: zero() };
  for (const view of views) matrix[view.likelihood][view.impact] += 1;
  return matrix;
}

// ------------------------------------------------------------------------- policies and scope

export type PolicyState =
  'DOCUMENTED' | 'EFFECTIVE' | 'REVIEW_DUE' | 'CHANGED_SINCE_APPROVAL' | 'UNDER_REVISION' | 'RETIRED';

export function policyState(
  policy: CataloguePolicy,
  records: readonly IsmsRecord[],
  now: Date,
): { readonly state: PolicyState; readonly latest: IsmsRecordOf<'POLICY_REVIEW'> | undefined } {
  const latest = recordsOf(records, 'POLICY_REVIEW').find((r) => r.ref === policy.id);
  if (latest === undefined) return { state: 'DOCUMENTED', latest };
  const { decision, documentFingerprint, nextReviewDate } = latest.data;
  if (decision === 'RETIRED') return { state: 'RETIRED', latest };
  if (decision === 'CHANGES_REQUIRED') return { state: 'UNDER_REVISION', latest };
  if (documentFingerprint !== policy.fingerprint) return { state: 'CHANGED_SINCE_APPROVAL', latest };
  if (now.getTime() > endOfDayPlus(nextReviewDate, 0).getTime()) return { state: 'REVIEW_DUE', latest };
  return { state: 'EFFECTIVE', latest };
}

export function scopeState(
  records: readonly IsmsRecord[],
  now: Date,
  catalogue: IsmsCatalogue = ISMS_CATALOGUE,
): {
  readonly state: 'NOT_REVIEWED' | 'CONFIRMED' | 'CHANGES_REQUIRED' | 'REVIEW_DUE' | 'CHANGED_SINCE_REVIEW';
  readonly latest: IsmsRecordOf<'SCOPE_REVIEW'> | undefined;
} {
  const latest = recordsOf(records, 'SCOPE_REVIEW')[0];
  if (latest === undefined) return { state: 'NOT_REVIEWED', latest };
  if (latest.data.scopeFingerprint !== catalogue.scope.fingerprint) return { state: 'CHANGED_SINCE_REVIEW', latest };
  if (latest.data.decision === 'CHANGES_REQUIRED') return { state: 'CHANGES_REQUIRED', latest };
  if (now.getTime() > endOfDayPlus(latest.data.nextReviewDate, 0).getTime()) return { state: 'REVIEW_DUE', latest };
  return { state: 'CONFIRMED', latest };
}

// ----------------------------------------------------------------------------------- findings

const FINDING_OPEN: ReadonlySet<string> = new Set(['OPEN', 'ANALYZED', 'ACTION_PLANNED', 'ACTION_IMPLEMENTED']);

/** Section 10: past its action due date and not yet awaiting effectiveness or closed. */
export function isOverdue(finding: IsmsRecordOf<'FINDING'>, now: Date): boolean {
  const due = finding.data.action?.dueDate;
  return due !== undefined && FINDING_OPEN.has(finding.status) && now.getTime() > endOfDayPlus(due, 0).getTime();
}

// ------------------------------------------------------------------------------------ metrics

export interface MetricValue {
  readonly id: string;
  readonly value: number | null;
  readonly numerator?: number;
  readonly denominator?: number;
  readonly breakdown?: Readonly<Record<string, number>>;
  readonly display: string;
}

/** Section 12: every metric from the records, the catalogue and the time; nothing typed in. */
export function computeMetrics(
  records: readonly IsmsRecord[],
  now: Date,
  catalogue: IsmsCatalogue = ISMS_CATALOGUE,
): MetricValue[] {
  const counted = records.filter((r) => r.status !== 'WITHDRAWN');
  const assurance = allControlAssurance(counted, now, catalogue);
  const applicable = assurance.filter((a) => a.applicability === 'APPLICABLE');
  const verified = applicable.filter((a) => a.state === 'VERIFIED').length;
  const views = catalogue.risks.map((risk) => riskView(risk, counted));
  const treated = views.filter((v) => v.status === 'TREATMENT_VERIFIED' || v.status === 'RESIDUAL_ACCEPTED').length;
  const findings = recordsOf(counted, 'FINDING');
  const overdue = findings.filter((f) => isOverdue(f, now)).length;
  const open = findings.filter((f) => f.status !== 'CLOSED');
  const byClass: Record<string, number> = {};
  for (const finding of open) byClass[finding.data.classification] = (byClass[finding.data.classification] ?? 0) + 1;
  const captured = catalogue.evidence.filter((e) => e.status === 'captured' || e.status === 'partial');
  const stale = captured.filter((e) => evidenceFreshness(e.id, now, catalogue).state !== 'CURRENT').length;
  const effective = catalogue.policies.filter((p) => policyState(p, counted, now).state === 'EFFECTIVE').length;
  const lastReview = recordsOf(counted, 'MANAGEMENT_REVIEW').find((r) => r.status === 'RECORDED');
  const sinceReview =
    lastReview?.data.recorded === undefined
      ? null
      : Math.floor((now.getTime() - Date.parse(lastReview.data.recorded.at)) / DAY_MS);
  const ratio = (id: string, numerator: number, denominator: number): MetricValue => ({
    id,
    value: denominator === 0 ? null : numerator / denominator,
    numerator,
    denominator,
    display: `${String(numerator)} of ${String(denominator)}`,
  });
  return [
    ratio('M-01', verified, applicable.length),
    ratio('M-02', treated, views.length),
    { id: 'M-03', value: overdue, display: String(overdue) },
    { id: 'M-04', value: open.length, breakdown: byClass, display: String(open.length) },
    { ...ratio('M-05', stale, captured.length), display: `${String(stale)} stale of ${String(captured.length)}` },
    ratio('M-06', effective, catalogue.policies.length),
    sinceReview === null
      ? { id: 'M-07', value: null, display: 'No management review recorded' }
      : { id: 'M-07', value: sinceReview, display: `${String(sinceReview)} days` },
  ];
}

export interface ReviewInputs {
  readonly computedAt: string;
  readonly metrics: readonly MetricValue[];
  readonly assurance: Readonly<Record<string, number>>;
  readonly risksAwaitingTreatment: readonly string[];
  readonly risksAwaitingAcceptance: readonly string[];
  readonly openFindings: readonly { readonly code: string; readonly classification: string; readonly status: string }[];
  readonly overdueFindings: readonly string[];
  readonly previousActions: readonly {
    readonly review: string;
    readonly description: string;
    readonly finding: string | null;
    readonly status: string;
  }[];
  readonly staleEvidence: readonly string[];
}

/** The inputs of a management review (clause 9.3), computed when the draft is created. */
export function reviewInputs(
  records: readonly IsmsRecord[],
  now: Date,
  catalogue: IsmsCatalogue = ISMS_CATALOGUE,
): ReviewInputs {
  const counted = records.filter((r) => r.status !== 'WITHDRAWN');
  const assurance: Record<string, number> = {};
  for (const a of allControlAssurance(counted, now, catalogue)) assurance[a.state] = (assurance[a.state] ?? 0) + 1;
  const views = catalogue.risks.map((risk) => riskView(risk, counted));
  const findings = recordsOf(counted, 'FINDING');
  const byCode = new Map(findings.map((f) => [f.code, f]));
  return {
    computedAt: now.toISOString(),
    metrics: computeMetrics(counted, now, catalogue),
    assurance,
    risksAwaitingTreatment: views
      .filter((v) => v.status === 'ASSESSED' || v.status === 'TREATMENT_PLANNED')
      .map((v) => v.risk.id),
    risksAwaitingAcceptance: views.filter((v) => v.status === 'TREATMENT_VERIFIED').map((v) => v.risk.id),
    openFindings: findings
      .filter((f) => f.status !== 'CLOSED')
      .map((f) => ({ code: f.code, classification: f.data.classification, status: f.status })),
    overdueFindings: findings.filter((f) => isOverdue(f, now)).map((f) => f.code),
    previousActions: recordsOf(counted, 'MANAGEMENT_REVIEW')
      .filter((r) => r.status === 'RECORDED')
      .flatMap((r) =>
        r.data.actions.map((action) => ({
          review: r.code,
          description: action.description,
          finding: action.finding,
          status: action.finding === null ? 'NO_FINDING' : (byCode.get(action.finding)?.status ?? 'UNKNOWN'),
        })),
      ),
    staleEvidence: catalogue.evidence
      .filter((e) => e.status === 'captured' || e.status === 'partial')
      .filter((e) => evidenceFreshness(e.id, now, catalogue).state !== 'CURRENT')
      .map((e) => e.id),
  };
}
