import { createHash } from 'node:crypto';
import {
  applyTransition,
  attachmentProblem,
  createRecord,
  creationAuthority,
  ErrorCode,
  ISMS_CATALOGUE,
  transitionSpec,
  type IsmsActor,
  type IsmsAuthority,
  type IsmsCreateInputs,
  type IsmsRecord,
  type IsmsRecordKind,
  type WorkflowFailure,
  type WorkflowResult,
} from '@ciphermesh/shared';
import type {
  IsmsCreateRequest,
  IsmsDecisionCreateRequest,
  IsmsDecisionTransition,
  IsmsRecordTransition,
} from '@ciphermesh/validation';
import type { Actor } from '../auth/sessions';
import type { IsmsActivityRow, IsmsActivityWithSnapshot, IsmsStore, IsmsWriter } from '../db/isms-store';
import { HttpError } from '../http/errors';

/**
 * The operational ISMS service (ADR-016). Handler order of CLAUDE.md section 9: the registry has
 * authenticated the caller, applied the platform administrator gate (PA-06 to PA-08) and, for
 * decisions, the step-up; the body is schema-validated. Here: the authority of the route must match
 * the transition's, the shared workflow decides inside a locked transaction, the record and its
 * activity row are written together. Nothing is back-dated: every time is the server's clock.
 */

export interface IsmsService {
  state(): Promise<{ records: IsmsRecord[]; activity: IsmsActivityRow[]; people: IsmsActor[] }>;
  detail(recordId: string): Promise<{ record: IsmsRecord; history: IsmsActivityWithSnapshot[] }>;
  create(
    actor: Actor,
    request: IsmsCreateRequest | IsmsDecisionCreateRequest,
    authority: IsmsAuthority,
  ): Promise<WriteResult>;
  transition(
    actor: Actor,
    recordId: string,
    request: IsmsRecordTransition | IsmsDecisionTransition,
    authority: IsmsAuthority,
  ): Promise<WriteResult>;
}

export interface WriteResult {
  readonly record: IsmsRecord;
  readonly created: readonly string[];
}

const RECENT_ACTIVITY = 200;

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');

function failure(result: WorkflowFailure): HttpError {
  const issues = result.conditions.map((code) => ({ path: 'condition', code }));
  switch (result.error) {
    case 'ISMS_REFERENCE_UNKNOWN':
      return new HttpError(400, ErrorCode.ISMS_REFERENCE_UNKNOWN, 'A referenced item does not exist', issues);
    case 'ISMS_TRANSITION_NOT_ALLOWED':
      return new HttpError(
        409,
        ErrorCode.ISMS_TRANSITION_NOT_ALLOWED,
        'This change is not possible from the current status',
        issues,
      );
    case 'ISMS_CONDITION_NOT_MET':
      return new HttpError(
        409,
        ErrorCode.ISMS_CONDITION_NOT_MET,
        'A documented condition of this change is not met',
        issues,
      );
  }
}

const actorOf = (actor: Actor): IsmsActor => ({ userId: actor.userId, name: actor.user.displayName });

/** The note that explains a change in the activity history, from the transition's own input. */
function rationaleOf(input: unknown): string | null {
  if (typeof input !== 'object' || input === null) return null;
  const record = input as Record<string, unknown>;
  for (const key of ['note', 'reason', 'rationale', 'conclusion', 'rootCause', 'containment', 'recovery', 'lessons']) {
    const value = record[key];
    if (typeof value === 'string' && value !== '') return value.slice(0, 4000);
  }
  return null;
}

async function persist<K extends IsmsRecordKind>(
  writer: IsmsWriter,
  result: WorkflowResult<K>,
  write: (status: string, data: unknown) => Promise<IsmsRecord | undefined>,
  context: {
    readonly actor: IsmsActor;
    readonly now: Date;
    readonly exercise: boolean;
    readonly parentCode: string | null;
  },
): Promise<WriteResult> {
  if (!result.ok) throw failure(result);
  // Findings created as a consequence (an audit check, a review action) are written first, so
  // their codes can be linked into the parent in the same transaction.
  let data = result.data;
  const created: string[] = [];
  for (const spawn of result.spawn) {
    const finding = await writer.insert({
      kind: 'FINDING',
      ref: spawn.ref,
      status: 'OPEN',
      data: spawn.data,
      exercise: context.exercise,
      actor: context.actor,
      now: context.now,
      rationale: context.parentCode === null ? null : `Raised by ${context.parentCode}`,
    });
    created.push(finding.code);
    data = spawn.link(data, finding.code);
  }
  const record = await write(result.status, data);
  if (record === undefined) throw new HttpError(409, ErrorCode.ISMS_VERSION_CONFLICT, 'The record changed; reload it');
  return { record, created };
}

export function createIsmsService(store: IsmsStore, clock: () => Date): IsmsService {
  const people = async (): Promise<ReadonlyMap<string, string>> =>
    new Map((await store.auditors()).map((p) => [p.userId, p.name]));

  return {
    async state() {
      const [records, activity, auditors] = await Promise.all([
        store.listRecords(),
        store.recentActivity(RECENT_ACTIVITY),
        store.auditors(),
      ]);
      return { records, activity, people: auditors };
    },

    async detail(recordId) {
      const found = await store.findRecord(recordId);
      if (found === undefined) throw notFound();
      return found;
    },

    async create(actor, request, authority) {
      if (creationAuthority(request.kind) !== authority) throw notFound();
      const who = actorOf(actor);
      let sha256: string | undefined;
      if (request.kind === 'CONTROL_VERIFICATION' && request.input.attachment !== null) {
        const problem = attachmentProblem(request.input.attachment.text);
        if (problem !== undefined) {
          // The value is never echoed (INV-10); only which rule refused it.
          throw new HttpError(400, ErrorCode.ISMS_ATTACHMENT_REJECTED, 'The attached output was refused', [
            { path: 'input.attachment.text', code: problem },
          ]);
        }
        sha256 = createHash('sha256').update(request.input.attachment.text, 'utf8').digest('hex');
      }
      const auditors = await people();
      return store.write(async (writer) => {
        const now = clock();
        const ref = 'ref' in request ? request.ref : '';
        const result = createRecord(
          request.kind,
          ref,
          request.input as IsmsCreateInputs[typeof request.kind],
          { now, actor: who, records: writer.records, catalogue: ISMS_CATALOGUE, people: auditors },
          sha256 === undefined ? {} : { attachmentSha256: sha256 },
        );
        return persist(
          writer,
          result,
          (status, data) =>
            writer.insert({
              kind: request.kind,
              ref: result.ok ? result.ref : ref,
              status,
              data,
              exercise: request.exercise,
              actor: who,
              now,
              rationale: rationaleOf(request.input),
            }),
          { actor: who, now, exercise: request.exercise, parentCode: null },
        );
      });
    },

    async transition(actor, recordId, request, authority) {
      const who = actorOf(actor);
      const auditors = await people();
      return store.write(async (writer) => {
        const record = writer.records.find((r) => r.id === recordId);
        if (record === undefined) throw notFound();
        const spec = transitionSpec(record.kind, request.transition);
        if (spec === undefined) {
          throw failure({ ok: false, error: 'ISMS_TRANSITION_NOT_ALLOWED', conditions: ['TRANSITION_UNKNOWN'] });
        }
        // A decision cannot arrive through the record route, nor a record through the decision route.
        if (spec.authority !== authority) {
          throw failure({ ok: false, error: 'ISMS_TRANSITION_NOT_ALLOWED', conditions: ['AUTHORITY'] });
        }
        if (record.version !== request.expectedVersion) {
          throw new HttpError(409, ErrorCode.ISMS_VERSION_CONFLICT, 'The record changed; reload it');
        }
        const now = clock();
        const result = applyTransition(record, request.transition, request.input, {
          now,
          actor: who,
          records: writer.records,
          catalogue: ISMS_CATALOGUE,
          people: auditors,
        });
        return persist(
          writer,
          result,
          (status, data) =>
            writer.update({
              record,
              expectedVersion: request.expectedVersion,
              status,
              data,
              action: request.transition,
              actor: who,
              now,
              rationale: rationaleOf(request.input),
            }),
          { actor: who, now, exercise: record.exercise, parentCode: record.code },
        );
      });
    },
  };
}
