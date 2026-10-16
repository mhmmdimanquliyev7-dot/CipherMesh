import {
  AUDIT_CHECK_RESULTS,
  AUDIT_INDEPENDENCE,
  FINDING_CLASSIFICATIONS,
  FINDING_SOURCES,
  ISMS_LEVELS,
  ISMS_RECORD_KINDS,
  POLICY_DECISIONS,
  REVIEW_FORMATS,
  TREATMENT_OPTIONS,
  VERIFICATION_ENVIRONMENTS,
  VERIFICATION_METHODS,
  VERIFICATION_RESULTS,
} from '@ciphermesh/shared';
import { isoTimestampSchema, uuidV4Schema } from './schemas';
import { z } from './zod';

/**
 * Operational ISMS (ADR-016, docs/security/isms-operations.md): the request and response schemas of
 * the /isms routes. Every object is strict (unknown fields refused), every identifier has the shape
 * of its catalogue (the API then checks that it exists), every text and list is bounded. Statuses
 * are never part of a request: a change is a named transition with its own input.
 */

const text = (max: number) => z.string().trim().min(1).max(max);
const shortText = text(200);
const longText = text(4000);
/** May be empty (an optional correction, a note on inputs). */
const optionalText = z.string().trim().max(4000);

const isRealDay = (value: string): boolean => {
  const time = Date.parse(`${value}T00:00:00.000Z`);
  return !Number.isNaN(time) && new Date(time).toISOString().slice(0, 10) === value;
};
export const isoDaySchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine(isRealDay, { message: 'Expected a date' });

export const riskIdSchema = z.string().regex(/^T-\d{2}$/);
export const controlIdSchema = z.string().regex(/^\d\.\d{1,2}( to \d\.\d{1,2})?$/);
export const evidenceIdSchema = z.string().regex(/^EV-\d{2}-\d{2}$/);
export const assetIdSchema = z.string().regex(/^A-\d{2}$/);
export const policyIdSchema = z.string().regex(/^POL-\d{2}$/);
/** A clause reference (for example 6.1.2 or 9.2) or a Statement of Applicability row. */
export const criterionSchema = z.string().regex(/^\d{1,2}(\.\d{1,2}){0,2}( to \d\.\d{1,2})?$/);
export const recordCodeSchema = z.string().regex(/^(RA|CV|AUD|FND|MR|SR|PR|INC)-\d{3,6}$/);

const list = <T extends z.ZodType>(item: T, max: number) => z.array(item).max(max);

const levelSchema = z.enum(ISMS_LEVELS);

// --------------------------------------------------------------------------- creation inputs

const riskAssessmentInput = z.strictObject({
  assets: list(assetIdSchema, 20).min(1),
  threat: longText,
  vulnerability: longText,
  consequences: longText,
  owner: shortText,
  likelihood: levelSchema,
  impact: levelSchema,
  rationale: longText,
});

const verificationInput = z.strictObject({
  method: z.enum(VERIFICATION_METHODS),
  procedure: longText,
  environment: z.enum(VERIFICATION_ENVIRONMENTS),
  result: z.enum(VERIFICATION_RESULTS),
  limitations: longText,
  relatedRisks: list(riskIdSchema, 50),
  evidence: list(evidenceIdSchema, 30),
  ciRun: z.string().max(200).nullable(),
  // The byte limit and the secret check are applied by the API (attachmentProblem).
  attachment: z.strictObject({ label: shortText, text: z.string().min(1).max(32_768) }).nullable(),
  freshnessClass: z.string().regex(/^[A-Z]{3,20}$/),
});

const auditInput = z.strictObject({
  title: shortText,
  scope: longText,
  objective: longText,
  criteria: list(criterionSchema, 40).min(1),
  scheduledFor: isoDaySchema,
  independence: z.enum(AUDIT_INDEPENDENCE),
  auditorUserId: uuidV4Schema,
});

const findingInput = z.strictObject({
  source: z.strictObject({ type: z.enum(FINDING_SOURCES), ref: z.string().max(100).nullable() }),
  classification: z.enum(FINDING_CLASSIFICATIONS),
  criterion: criterionSchema,
  observation: longText,
  evidence: list(evidenceIdSchema, 30),
  responsible: shortText,
  relatedRisks: list(riskIdSchema, 50),
  relatedControls: list(controlIdSchema, 30),
});

const reviewActionSchema = z.strictObject({ description: longText, owner: shortText, dueDate: isoDaySchema });

const reviewInput = z.strictObject({
  title: shortText,
  reviewDate: isoDaySchema,
  format: z.enum(REVIEW_FORMATS),
  participants: list(shortText, 20),
  inputNotes: optionalText,
  decisions: list(longText, 20),
  actions: list(reviewActionSchema, 20),
});

const incidentInput = z.strictObject({
  title: shortText,
  detection: longText,
  classification: z.enum(['SECURITY_EVENT', 'SECURITY_INCIDENT']),
  impact: longText,
  owner: shortText,
  relatedRisks: list(riskIdSchema, 50),
  relatedControls: list(controlIdSchema, 30),
});

/** POST /isms/records (PA-07): records. `exercise` labels a demonstration record (section 13). */
export const ismsCreateRequestSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('RISK_ASSESSMENT'),
    ref: riskIdSchema,
    exercise: z.boolean(),
    input: riskAssessmentInput,
  }),
  z.strictObject({
    kind: z.literal('CONTROL_VERIFICATION'),
    ref: controlIdSchema,
    exercise: z.boolean(),
    input: verificationInput,
  }),
  z.strictObject({ kind: z.literal('AUDIT'), exercise: z.boolean(), input: auditInput }),
  z.strictObject({ kind: z.literal('FINDING'), exercise: z.boolean(), input: findingInput }),
  z.strictObject({ kind: z.literal('MANAGEMENT_REVIEW'), exercise: z.boolean(), input: reviewInput }),
  z.strictObject({ kind: z.literal('INCIDENT'), exercise: z.boolean(), input: incidentInput }),
]);
export type IsmsCreateRequest = z.infer<typeof ismsCreateRequestSchema>;

/** POST /isms/decisions (PA-08, step-up): scope and policy decisions. */
export const ismsDecisionCreateRequestSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('SCOPE_REVIEW'),
    exercise: z.boolean(),
    input: z.strictObject({
      decision: z.enum(['CONFIRMED', 'CHANGES_REQUIRED']),
      reason: longText,
      nextReviewDate: isoDaySchema,
    }),
  }),
  z.strictObject({
    kind: z.literal('POLICY_REVIEW'),
    ref: policyIdSchema,
    exercise: z.boolean(),
    input: z.strictObject({
      decision: z.enum(POLICY_DECISIONS),
      effectiveFrom: isoDaySchema,
      nextReviewDate: isoDaySchema,
      note: longText,
    }),
  }),
]);
export type IsmsDecisionCreateRequest = z.infer<typeof ismsDecisionCreateRequestSchema>;

// ------------------------------------------------------------------------- transition inputs

const version = z.number().int().min(1).max(1_000_000);
const step = <N extends string, T extends z.ZodType>(name: N, input: T) =>
  z.strictObject({ transition: z.literal(name), expectedVersion: version, input });
const empty = z.strictObject({});
const noteInput = z.strictObject({ note: longText });

/** POST /isms/records/:recordId/transitions (PA-07): every non-decision transition. */
export const ismsRecordTransitionSchema = z.discriminatedUnion('transition', [
  step(
    'plan_treatment',
    z.strictObject({
      option: z.enum(TREATMENT_OPTIONS),
      responsible: shortText,
      controls: list(controlIdSchema, 30),
      activity: longText,
      targetDate: isoDaySchema.nullable(),
      requiredEvidence: list(evidenceIdSchema, 30),
    }),
  ),
  step('verify_treatment', z.strictObject({ likelihood: levelSchema, impact: levelSchema, rationale: longText })),
  step('start', empty),
  step(
    'record_check',
    z.strictObject({
      criterion: criterionSchema,
      result: z.enum(AUDIT_CHECK_RESULTS),
      note: longText,
      evidence: list(evidenceIdSchema, 30),
    }),
  ),
  step('complete', z.strictObject({ conclusion: longText })),
  step('analyze', z.strictObject({ rootCause: longText, correction: optionalText })),
  step('plan_action', reviewActionSchema),
  step('implement_action', noteInput),
  step(
    'submit_closure_evidence',
    z.strictObject({ verifications: list(recordCodeSchema, 20), evidence: list(evidenceIdSchema, 30) }),
  ),
  step(
    'update_draft',
    z.strictObject({
      participants: list(shortText, 20),
      inputNotes: optionalText,
      decisions: list(longText, 20),
      actions: list(reviewActionSchema, 20),
    }),
  ),
  step('contain', z.strictObject({ containment: longText })),
  step('resolve', z.strictObject({ recovery: longText })),
  step('withdraw', z.strictObject({ reason: longText })),
]);
export type IsmsRecordTransition = z.infer<typeof ismsRecordTransitionSchema>;

/** POST /isms/records/:recordId/decisions (PA-08, step-up): every decision transition. */
export const ismsDecisionTransitionSchema = z.discriminatedUnion('transition', [
  step('accept_residual', noteInput),
  step('reject_residual', noteInput),
  step('effectiveness_check', z.strictObject({ result: z.enum(['EFFECTIVE', 'NOT_EFFECTIVE']), note: longText })),
  step('record_review', empty),
  step('close_incident', z.strictObject({ lessons: longText })),
]);
export type IsmsDecisionTransition = z.infer<typeof ismsDecisionTransitionSchema>;

export const ismsRecordParamsSchema = z.strictObject({ recordId: uuidV4Schema });

// ---------------------------------------------------------------------------------- responses

const actorSchema = z.strictObject({ userId: uuidV4Schema, name: z.string().max(200) });

/**
 * One record, projected field by field from its row. `data` is the record's content as validated
 * when it was written (per kind, above); in lists an attached output carries its label, size and
 * digest only, never its text.
 */
export const ismsRecordSchema = z.strictObject({
  id: uuidV4Schema,
  kind: z.enum(ISMS_RECORD_KINDS),
  code: recordCodeSchema,
  ref: z.string().max(400),
  status: z.string().regex(/^[A-Z_]{3,40}$/),
  data: z.record(z.string(), z.unknown()),
  version: version,
  exercise: z.boolean(),
  createdAt: isoTimestampSchema,
  createdBy: actorSchema,
  updatedAt: isoTimestampSchema,
  updatedBy: actorSchema,
});
export type IsmsRecordResponse = z.infer<typeof ismsRecordSchema>;

export const ismsActivitySchema = z.strictObject({
  id: z.string().regex(/^\d{1,19}$/),
  recordId: uuidV4Schema,
  code: recordCodeSchema,
  kind: z.enum(ISMS_RECORD_KINDS),
  action: z.string().regex(/^[a-z_]{3,40}$/),
  fromStatus: z.string().max(40).nullable(),
  toStatus: z.string().max(40),
  rationale: z.string().max(4000).nullable(),
  actor: actorSchema,
  at: isoTimestampSchema,
  exercise: z.boolean(),
});
export type IsmsActivityResponse = z.infer<typeof ismsActivitySchema>;

/** GET /isms/state (PA-06): every record (lists projection), recent activity and the auditors. */
export const ismsStateResponseSchema = z.strictObject({
  computedAt: isoTimestampSchema,
  records: z.array(ismsRecordSchema).max(5000),
  activity: z.array(ismsActivitySchema).max(500),
  people: z.array(actorSchema).max(200),
});
export type IsmsStateResponse = z.infer<typeof ismsStateResponseSchema>;

/** GET /isms/records/:recordId (PA-06): the record with any attached output, and its full history. */
export const ismsRecordDetailResponseSchema = z.strictObject({
  record: ismsRecordSchema,
  history: z.array(ismsActivitySchema.extend({ snapshot: z.record(z.string(), z.unknown()) })).max(1000),
});
export type IsmsRecordDetailResponse = z.infer<typeof ismsRecordDetailResponseSchema>;

/** The answer to a creation or transition: the record and any findings created with it. */
export const ismsWriteResponseSchema = z.strictObject({
  record: ismsRecordSchema,
  created: z.array(recordCodeSchema).max(40),
});
export type IsmsWriteResponse = z.infer<typeof ismsWriteResponseSchema>;
