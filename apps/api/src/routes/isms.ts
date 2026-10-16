import type { IsmsRecord } from '@ciphermesh/shared';
import {
  emptyQuerySchema,
  ismsCreateRequestSchema,
  ismsDecisionCreateRequestSchema,
  ismsDecisionTransitionSchema,
  ismsRecordDetailResponseSchema,
  ismsRecordParamsSchema,
  ismsRecordTransitionSchema,
  ismsStateResponseSchema,
  ismsWriteResponseSchema,
  type IsmsRecordResponse,
} from '@ciphermesh/validation';
import { withoutAttachmentText } from '../db/isms-store';
import type { IsmsService, WriteResult } from '../isms/service';
import { actorOf, defineRoute, type AnyRoute } from './registry';

/**
 * Operational ISMS routes (ADR-016, docs/security/isms-operations.md section 15). Every route needs
 * PLATFORM_ADMIN with an MFA-verified session (the registry's administrator gate); everyone else
 * gets the generic 404. PA-06 views, PA-07 records, PA-08 decides and needs a step-up every time.
 * No GET changes anything; every change is a named transition or a creation (never a status).
 */

/** Explicit projection of a record. Lists never carry the text of an attached output. */
function recordView(record: IsmsRecord, withAttachmentText: boolean): IsmsRecordResponse {
  return {
    id: record.id,
    kind: record.kind,
    code: record.code,
    ref: record.ref,
    status: record.status,
    data: withAttachmentText ? (record.data as unknown as Record<string, unknown>) : withoutAttachmentText(record),
    version: record.version,
    exercise: record.exercise,
    createdAt: record.createdAt,
    createdBy: record.createdBy,
    updatedAt: record.updatedAt,
    updatedBy: record.updatedBy,
  };
}

const written = (result: WriteResult) => ({ record: recordView(result.record, false), created: [...result.created] });

export function ismsRoutes(isms: IsmsService, clock: () => Date): readonly AnyRoute[] {
  return [
    defineRoute({
      method: 'GET',
      path: '/isms/state',
      action: 'PA-06-ISMS-VIEW',
      access: { kind: 'authenticated', requires: { platformAdmin: true } },
      query: emptyQuerySchema,
      body: undefined,
      response: ismsStateResponseSchema,
      handler: async () => {
        const state = await isms.state();
        return {
          status: 200,
          body: {
            computedAt: clock().toISOString(),
            records: state.records.map((r) => recordView(r, false)),
            activity: state.activity.map((a) => ({ ...a })),
            people: state.people.map((p) => ({ ...p })),
          },
        };
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/isms/records/:recordId',
      action: 'PA-06-ISMS-VIEW',
      access: { kind: 'authenticated', requires: { platformAdmin: true } },
      params: ismsRecordParamsSchema,
      query: emptyQuerySchema,
      body: undefined,
      response: ismsRecordDetailResponseSchema,
      handler: async (ctx) => {
        const found = await isms.detail(ctx.params.recordId);
        return {
          status: 200,
          body: {
            record: recordView(found.record, true),
            history: found.history.map((h) => ({ ...h })),
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/isms/records',
      action: 'PA-07-ISMS-RECORD',
      access: { kind: 'authenticated', requires: { platformAdmin: true } },
      query: emptyQuerySchema,
      body: ismsCreateRequestSchema,
      response: ismsWriteResponseSchema,
      handler: async (ctx) => ({ status: 201, body: written(await isms.create(actorOf(ctx), ctx.body, 'record')) }),
    }),
    defineRoute({
      method: 'POST',
      path: '/isms/records/:recordId/transitions',
      action: 'PA-07-ISMS-RECORD',
      access: { kind: 'authenticated', requires: { platformAdmin: true } },
      params: ismsRecordParamsSchema,
      query: emptyQuerySchema,
      body: ismsRecordTransitionSchema,
      response: ismsWriteResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: written(await isms.transition(actorOf(ctx), ctx.params.recordId, ctx.body, 'record')),
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/isms/decisions',
      action: 'PA-08-ISMS-DECIDE',
      access: { kind: 'authenticated', requires: { platformAdmin: true, stepUp: 'standard' } },
      query: emptyQuerySchema,
      body: ismsDecisionCreateRequestSchema,
      response: ismsWriteResponseSchema,
      handler: async (ctx) => ({ status: 201, body: written(await isms.create(actorOf(ctx), ctx.body, 'decide')) }),
    }),
    defineRoute({
      method: 'POST',
      path: '/isms/records/:recordId/decisions',
      action: 'PA-08-ISMS-DECIDE',
      access: { kind: 'authenticated', requires: { platformAdmin: true, stepUp: 'standard' } },
      params: ismsRecordParamsSchema,
      query: emptyQuerySchema,
      body: ismsDecisionTransitionSchema,
      response: ismsWriteResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: written(await isms.transition(actorOf(ctx), ctx.params.recordId, ctx.body, 'decide')),
      }),
    }),
  ];
}
