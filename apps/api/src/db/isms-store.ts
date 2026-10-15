import { ISMS_CODE_PREFIX, type IsmsActor, type IsmsRecord, type IsmsRecordKind } from '@ciphermesh/shared';
import type { Prisma, PrismaClient } from '../generated/prisma/client';

/**
 * Persistence of the operational ISMS (ADR-016): `isms_records` and the append-only
 * `isms_activity`. Every write runs in one transaction that first takes a transaction-scoped
 * advisory lock, so ISMS writes are serialized: conditions that read other records (a control
 * verified, a later verification) and the per-kind code numbers are consistent. The volume is a
 * few records a day; the lock never touches room traffic. The version check is conditional
 * (`WHERE version = expected`), so a stale writer gets a conflict, never a silent overwrite.
 */

type Db = PrismaClient | Prisma.TransactionClient;

/** Arbitrary but fixed: the advisory lock that serializes ISMS writes. */
const ISMS_WRITE_LOCK = 270_160_15;

export interface IsmsActivityRow {
  readonly id: string;
  readonly recordId: string;
  readonly code: string;
  readonly kind: IsmsRecordKind;
  readonly action: string;
  readonly fromStatus: string | null;
  readonly toStatus: string;
  readonly rationale: string | null;
  readonly actor: IsmsActor;
  readonly at: string;
  readonly exercise: boolean;
}

export interface IsmsActivityWithSnapshot extends IsmsActivityRow {
  readonly snapshot: Record<string, unknown>;
}

const recordSelect = {
  id: true,
  kind: true,
  seq: true,
  ref: true,
  status: true,
  data: true,
  version: true,
  exercise: true,
  createdAt: true,
  updatedAt: true,
  createdBy: { select: { id: true, displayName: true } },
  updatedBy: { select: { id: true, displayName: true } },
} as const satisfies Prisma.IsmsRecordSelect;

type RecordRow = Prisma.IsmsRecordGetPayload<{ select: typeof recordSelect }>;

export function codeOf(kind: IsmsRecordKind, seq: number): string {
  return `${ISMS_CODE_PREFIX[kind]}-${String(seq).padStart(3, '0')}`;
}

function toRecord(row: RecordRow): IsmsRecord {
  return {
    id: row.id,
    kind: row.kind,
    code: codeOf(row.kind, row.seq),
    ref: row.ref,
    status: row.status,
    // The content was validated per kind when it was written (apps/api/src/isms/service.ts).
    data: row.data as never,
    version: row.version,
    exercise: row.exercise,
    createdAt: row.createdAt.toISOString(),
    createdBy: { userId: row.createdBy.id, name: row.createdBy.displayName },
    updatedAt: row.updatedAt.toISOString(),
    updatedBy: { userId: row.updatedBy.id, name: row.updatedBy.displayName },
  };
}

const activitySelect = {
  id: true,
  recordId: true,
  action: true,
  fromStatus: true,
  toStatus: true,
  rationale: true,
  at: true,
  actor: { select: { id: true, displayName: true } },
  record: { select: { kind: true, seq: true, exercise: true } },
} as const satisfies Prisma.IsmsActivitySelect;

type ActivityRow = Prisma.IsmsActivityGetPayload<{ select: typeof activitySelect }>;

function toActivity(row: ActivityRow): IsmsActivityRow {
  return {
    id: row.id.toString(),
    recordId: row.recordId,
    code: codeOf(row.record.kind, row.record.seq),
    kind: row.record.kind,
    action: row.action,
    fromStatus: row.fromStatus,
    toStatus: row.toStatus,
    rationale: row.rationale,
    actor: { userId: row.actor.id, name: row.actor.displayName },
    at: row.at.toISOString(),
    exercise: row.record.exercise,
  };
}

/** The data as kept in the history: an attached output keeps its label, size and digest only. */
export function withoutAttachmentText(record: Pick<IsmsRecord, 'kind' | 'data'>): Record<string, unknown> {
  const data = record.data as unknown as Record<string, unknown>;
  if (record.kind !== 'CONTROL_VERIFICATION') return data;
  const attachment = data['attachment'] as Record<string, unknown> | null | undefined;
  if (attachment === null || attachment === undefined) return data;
  const { text: _text, ...rest } = attachment;
  return { ...data, attachment: rest };
}

export interface IsmsWriter {
  /** Every record, newest first, read inside the locked transaction. */
  readonly records: readonly IsmsRecord[];
  insert(input: {
    readonly kind: IsmsRecordKind;
    readonly ref: string;
    readonly status: string;
    readonly data: unknown;
    readonly exercise: boolean;
    readonly actor: IsmsActor;
    readonly now: Date;
    readonly rationale: string | null;
  }): Promise<IsmsRecord>;
  /** Writes a transition; false when the stored version is no longer `expectedVersion`. */
  update(input: {
    readonly record: IsmsRecord;
    readonly expectedVersion: number;
    readonly status: string;
    readonly data: unknown;
    readonly action: string;
    readonly actor: IsmsActor;
    readonly now: Date;
    readonly rationale: string | null;
  }): Promise<IsmsRecord | undefined>;
}

export interface IsmsStore {
  listRecords(): Promise<IsmsRecord[]>;
  recentActivity(limit: number): Promise<IsmsActivityRow[]>;
  /** Platform administrators with MFA: the accounts that may be named as auditors. */
  auditors(): Promise<IsmsActor[]>;
  findRecord(id: string): Promise<{ record: IsmsRecord; history: IsmsActivityWithSnapshot[] } | undefined>;
  write<T>(fn: (writer: IsmsWriter) => Promise<T>): Promise<T>;
}

async function listRecords(db: Db): Promise<IsmsRecord[]> {
  const rows = await db.ismsRecord.findMany({
    select: recordSelect,
    orderBy: [{ createdAt: 'desc' }, { seq: 'desc' }],
  });
  return rows.map(toRecord);
}

export function createIsmsStore(prisma: PrismaClient): IsmsStore {
  return {
    listRecords: () => listRecords(prisma),

    async recentActivity(limit) {
      const rows = await prisma.ismsActivity.findMany({ select: activitySelect, orderBy: { id: 'desc' }, take: limit });
      return rows.map(toActivity);
    },

    async auditors() {
      const users = await prisma.user.findMany({
        where: { platformRole: 'PLATFORM_ADMIN', status: 'ACTIVE', mfaEnabled: true, deletedAt: null },
        select: { id: true, displayName: true },
        orderBy: { displayName: 'asc' },
      });
      return users.map((u) => ({ userId: u.id, name: u.displayName }));
    },

    async findRecord(id) {
      const row = await prisma.ismsRecord.findUnique({ where: { id }, select: recordSelect });
      if (row === null) return undefined;
      const history = await prisma.ismsActivity.findMany({
        where: { recordId: id },
        select: { ...activitySelect, snapshot: true },
        orderBy: { id: 'asc' },
      });
      return {
        record: toRecord(row),
        history: history.map((h) => ({ ...toActivity(h), snapshot: h.snapshot as Record<string, unknown> })),
      };
    },

    write(fn) {
      return prisma.$transaction(
        async (tx) => {
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(${ISMS_WRITE_LOCK})`;
          const records = await listRecords(tx);
          const activity = async (
            recordId: string,
            action: string,
            fromStatus: string | null,
            record: IsmsRecord,
            actor: IsmsActor,
            now: Date,
            rationale: string | null,
          ) => {
            await tx.ismsActivity.create({
              data: {
                recordId,
                action,
                fromStatus,
                toStatus: record.status,
                rationale,
                snapshot: withoutAttachmentText(record) as Prisma.InputJsonValue,
                actorId: actor.userId,
                at: now,
              },
            });
          };
          return fn({
            records,
            async insert(input) {
              const last = await tx.ismsRecord.aggregate({ where: { kind: input.kind }, _max: { seq: true } });
              const row = await tx.ismsRecord.create({
                data: {
                  kind: input.kind,
                  seq: (last._max.seq ?? 0) + 1,
                  ref: input.ref,
                  status: input.status,
                  data: input.data as Prisma.InputJsonValue,
                  exercise: input.exercise,
                  createdAt: input.now,
                  createdById: input.actor.userId,
                  updatedAt: input.now,
                  updatedById: input.actor.userId,
                },
                select: recordSelect,
              });
              const record = toRecord(row);
              await activity(record.id, 'create', null, record, input.actor, input.now, input.rationale);
              return record;
            },
            async update(input) {
              const changed = await tx.ismsRecord.updateMany({
                where: { id: input.record.id, version: input.expectedVersion },
                data: {
                  status: input.status,
                  data: input.data as Prisma.InputJsonValue,
                  version: { increment: 1 },
                  updatedAt: input.now,
                  updatedById: input.actor.userId,
                },
              });
              if (changed.count !== 1) return undefined;
              const row = await tx.ismsRecord.findUniqueOrThrow({
                where: { id: input.record.id },
                select: recordSelect,
              });
              const record = toRecord(row);
              await activity(
                record.id,
                input.action,
                input.record.status,
                record,
                input.actor,
                input.now,
                input.rationale,
              );
              return record;
            },
          });
        },
        { isolationLevel: 'ReadCommitted' },
      );
    },
  };
}
