import { canonicalBytes } from '@ciphermesh/crypto/identity';
import { isUuidV4 } from '@ciphermesh/shared';
import { createHash } from 'node:crypto';
import { Prisma, type PrismaClient } from '../generated/prisma/client';
import type {
  KeyVersionReason,
  RekeyMode,
  RekeyReason,
  RekeyStatus,
  RoomKeyState,
  RoomRole,
} from '../generated/prisma/enums';
import type { GrantRecord, IdentityRecord } from './room-key-store';

/**
 * Data access for the rekey state machine (Phase 11, CM-T050 to CM-T053, ADR-013, data-model
 * 4.9.1). Part of the room store, so one transaction locks the room, the memberships, the
 * operation and writes the new key version with its envelopes.
 *
 * - The recipient snapshot is computed here from the database alone (OL-13): the ACTIVE identity
 *   of every ACTIVE member with an ACTIVE account, and the invitee key of every open invitation
 *   whose invitee is still an ACTIVE account with that ACTIVE identity. Nothing a client sends
 *   selects or filters it. Its digest is SHA-256 over the RFC 8785 serialization.
 * - Operations are loaded by operation ID AND room ID (OL-13). Writes are conditional on the
 *   checked status and report whether they applied.
 * - No row here holds key material: commitments and signatures are public, envelopes are
 *   RSA-OAEP ciphertext for one recipient (INV-01, INV-04).
 * - Database triggers back the rules (20261011000000_key_rotation): closed operations are final,
 *   versions chain to their predecessor, a room unlocks only with the next ACTIVE version, an epoch
 *   change makes a PENDING operation STALE, and REKEYING exists exactly with a PENDING MANDATORY
 *   operation at commit.
 */
type Db = PrismaClient | Prisma.TransactionClient;

export interface RekeyOperationRecord {
  readonly id: string;
  readonly roomId: string;
  readonly startedById: string;
  readonly mode: RekeyMode;
  readonly status: RekeyStatus;
  readonly baseVersion: number;
  readonly targetVersion: number;
  readonly membershipEpoch: bigint;
  readonly recipientSetDigest: Uint8Array;
  readonly leaseExpiresAt: Date;
  readonly payloadDigest: Uint8Array | null;
  readonly createdAt: Date;
  readonly completedAt: Date | null;
}

export type RecipientKind = 'MEMBER' | 'INVITEE';

/** One entry of the server's recipient snapshot. */
export interface SnapshotRecipient {
  readonly userId: string;
  readonly keyId: string;
  readonly kind: RecipientKind;
  /** The open invitation of an INVITEE; its envelope is stored PENDING with this ID. */
  readonly invitationId: string | null;
  readonly displayName: string;
  readonly identity: IdentityRecord;
}

/** Thrown when the database state cannot form a snapshot (a user twice, too many recipients). */
export class SnapshotInvalidError extends Error {
  constructor() {
    super('Recipient snapshot invalid');
    this.name = 'SnapshotInvalidError';
  }
}

export interface NewKeyVersion {
  readonly roomId: string;
  readonly operation: RekeyOperationRecord;
  readonly commitment: Uint8Array;
  readonly previousCommitment: Uint8Array;
  readonly reasons: readonly KeyVersionReason[];
  readonly creatorUserId: string;
  readonly creatorKeyId: string;
  readonly recipients: readonly SnapshotRecipient[];
  readonly statementSignature: Uint8Array;
  readonly envelopes: ReadonlyMap<string, Uint8Array>;
  readonly payloadDigest: Uint8Array;
  readonly now: Date;
}

export const recipientKey = (userId: string, keyId: string): string => `${userId}/${keyId}`;

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** SHA-256 over the canonical, sorted recipient list with kinds (data-model 4.9.1). */
export function recipientSetDigest(recipients: readonly SnapshotRecipient[]): Uint8Array {
  const list = [...recipients]
    .sort((a, b) => compare(a.userId, b.userId) || compare(a.keyId, b.keyId))
    .map((r) => ({ userId: r.userId, keyId: r.keyId, kind: r.kind, invitationId: r.invitationId }));
  return new Uint8Array(
    createHash('sha256')
      .update(canonicalBytes({ v: 1, recipients: list }))
      .digest(),
  );
}

const OPERATION_COLUMNS = {
  id: true,
  roomId: true,
  startedById: true,
  mode: true,
  status: true,
  baseVersion: true,
  targetVersion: true,
  membershipEpoch: true,
  recipientSetDigest: true,
  leaseExpiresAt: true,
  payloadDigest: true,
  createdAt: true,
  completedAt: true,
} as const;

interface OperationRow {
  id: string;
  room_id: string;
  started_by_id: string;
  mode: RekeyMode;
  status: RekeyStatus;
  base_version: number;
  target_version: number;
  membership_epoch: bigint;
  recipient_set_digest: Uint8Array;
  lease_expires_at: Date;
  payload_digest: Uint8Array | null;
  created_at: Date;
  completed_at: Date | null;
}

const operationOf = (row: OperationRow): RekeyOperationRecord => ({
  id: row.id,
  roomId: row.room_id,
  startedById: row.started_by_id,
  mode: row.mode,
  status: row.status,
  baseVersion: row.base_version,
  targetVersion: row.target_version,
  membershipEpoch: row.membership_epoch,
  recipientSetDigest: new Uint8Array(row.recipient_set_digest),
  leaseExpiresAt: row.lease_expires_at,
  payloadDigest: row.payload_digest === null ? null : new Uint8Array(row.payload_digest),
  createdAt: row.created_at,
  completedAt: row.completed_at,
});

const IDENTITY_SELECT = {
  id: true,
  userId: true,
  status: true,
  algorithmSuite: true,
  publicKeySpki: true,
  signingPublicKeySpki: true,
  identitySignature: true,
  publicKeyFingerprint: true,
  createdAt: true,
} as const;

export function rekeyStoreFunctions(db: Db) {
  async function lockOperationBy(where: Prisma.Sql): Promise<RekeyOperationRecord | null> {
    const rows = await db.$queryRaw<OperationRow[]>`
      SELECT id::text AS id, room_id::text AS room_id, started_by_id::text AS started_by_id,
             mode::text AS mode, status::text AS status, base_version, target_version, membership_epoch,
             recipient_set_digest, lease_expires_at, payload_digest, created_at, completed_at
        FROM rekey_operations WHERE ${where} FOR UPDATE`;
    const row = rows[0];
    return row === undefined ? null : operationOf(row);
  }

  return {
    // ---------------------------------------------------------------------------------- reads

    /** The snapshot of ADR-013 step 1, from the database only (OL-13). Sorted by user and key. */
    async recipientSnapshot(roomId: string): Promise<SnapshotRecipient[]> {
      const members = await db.roomMember.findMany({
        where: { roomId, status: 'ACTIVE', user: { status: 'ACTIVE' } },
        select: {
          userId: true,
          user: { select: { displayName: true, keyPairs: { where: { status: 'ACTIVE' }, select: IDENTITY_SELECT } } },
        },
      });
      const invitees = await db.invitation.findMany({
        where: {
          roomId,
          status: { in: ['PENDING_APPROVAL', 'PENDING'] },
          invitee: { status: 'ACTIVE' },
          inviteeKey: { status: 'ACTIVE' },
        },
        select: {
          id: true,
          inviteeUserId: true,
          invitee: { select: { displayName: true } },
          inviteeKey: { select: IDENTITY_SELECT },
        },
      });
      const snapshot: SnapshotRecipient[] = [];
      for (const m of members) {
        const key = m.user.keyPairs[0];
        // An ACTIVE member of an ACTIVE account always has one ACTIVE identity (Phase 4 index);
        // without one there is nothing to wrap to, so the member is not a recipient.
        if (key === undefined) continue;
        snapshot.push({
          userId: m.userId,
          keyId: key.id,
          kind: 'MEMBER',
          invitationId: null,
          displayName: m.user.displayName,
          identity: identityRecord(key),
        });
      }
      for (const i of invitees) {
        snapshot.push({
          userId: i.inviteeUserId,
          keyId: i.inviteeKey.id,
          kind: 'INVITEE',
          invitationId: i.id,
          displayName: i.invitee.displayName,
          identity: identityRecord(i.inviteeKey),
        });
      }
      snapshot.sort((a, b) => compare(a.userId, b.userId) || compare(a.keyId, b.keyId));
      if (new Set(snapshot.map((r) => r.userId)).size !== snapshot.length) throw new SnapshotInvalidError();
      return snapshot;
    },

    /** The PENDING operation of the room, unlocked (AZ-15 view), or null. */
    async findPendingOperation(roomId: string): Promise<RekeyOperationRecord | null> {
      if (!isUuidV4(roomId)) return null;
      const row = await db.rekeyOperation.findFirst({
        where: { roomId, status: 'PENDING' },
        select: OPERATION_COLUMNS,
      });
      return row === null
        ? null
        : {
            ...row,
            recipientSetDigest: new Uint8Array(row.recipientSetDigest),
            payloadDigest: row.payloadDigest === null ? null : new Uint8Array(row.payloadDigest),
          };
    },

    /** Operations started in the room since `since` (CP-25: at most 10 per hour). */
    countOperationStarts(roomId: string, since: Date): Promise<number> {
      return db.rekeyOperation.count({ where: { roomId, createdAt: { gt: since } } });
    },

    /** The commitment and creation time of a key version of the room. */
    async keyVersionFacts(
      roomId: string,
      version: number,
    ): Promise<{ commitment: Uint8Array; createdAt: Date } | null> {
      const row = await db.roomKeyVersion.findUnique({
        where: { roomId_version: { roomId, version } },
        select: { commitment: true, createdAt: true },
      });
      return row === null ? null : { commitment: new Uint8Array(row.commitment), createdAt: row.createdAt };
    },

    /** Whether the commitment equals one the room already used (a replayed or reused version). */
    async commitmentUsed(roomId: string, commitment: Uint8Array): Promise<boolean> {
      const count = await db.roomKeyVersion.count({ where: { roomId, commitment: new Uint8Array(commitment) } });
      return count > 0;
    },

    /**
     * Members without an envelope of the current version for their current identity (AZ-14): an
     * identity replaced by a vault reset, or a SUSPENDED membership of a re-enabled account.
     */
    async membersNeedingKeys(
      roomId: string,
      currentKeyVersion: number,
    ): Promise<{ userId: string; reason: 'IDENTITY_CHANGED' | 'SUSPENDED' }[]> {
      const rows = await db.$queryRaw<{ user_id: string; status: string }[]>`
        SELECT m.user_id::text AS user_id, m.status::text AS status
          FROM room_members m
          JOIN users u ON u.id = m.user_id AND u.status = 'ACTIVE'
          JOIN user_key_pairs k ON k.user_id = m.user_id AND k.status = 'ACTIVE'
         WHERE m.room_id = ${roomId}::uuid
           AND m.status IN ('ACTIVE', 'SUSPENDED')
           AND NOT EXISTS (SELECT 1 FROM key_envelopes e
                            WHERE e.room_id = m.room_id AND e.recipient_user_id = m.user_id
                              AND e.recipient_key_id = k.id AND e.key_version = ${currentKeyVersion}
                              AND e.status = 'ACTIVE')
         ORDER BY m.user_id
         LIMIT 100`;
      return rows.map((r) => ({
        userId: r.user_id,
        reason: r.status === 'SUSPENDED' ? 'SUSPENDED' : 'IDENTITY_CHANGED',
      }));
    },

    /**
     * The signed grants that name the snapshot's recipients: each member's stored grant when it names
     * the member's current key, and each invitee's invitation grant (ADR-015 section 4). The browser
     * uses them only to flag keys the room has not signed before; it verifies every one itself.
     */
    async recipientGrants(roomId: string, recipients: readonly SnapshotRecipient[]): Promise<GrantRecord[]> {
      const members = recipients.filter((r) => r.kind === 'MEMBER');
      const invitations = recipients.flatMap((r) => (r.invitationId === null ? [] : [r.invitationId]));
      const memberRows =
        members.length === 0
          ? []
          : await db.roomMember.findMany({
              where: {
                roomId,
                status: 'ACTIVE',
                OR: members.map((m) => ({ userId: m.userId, subjectKeyId: m.keyId })),
                grantSignature: { not: null },
              },
              select: {
                userId: true,
                subjectKeyId: true,
                grantRole: true,
                grantorUserId: true,
                grantorKeyId: true,
                grantSignature: true,
              },
            });
      const invitationRows =
        invitations.length === 0
          ? []
          : await db.invitation.findMany({
              where: { roomId, id: { in: invitations } },
              select: {
                inviteeUserId: true,
                inviteeKeyId: true,
                role: true,
                invitedById: true,
                grantorKeyId: true,
                grantSignature: true,
              },
            });
      const grants: GrantRecord[] = [];
      for (const row of memberRows) {
        if (
          row.subjectKeyId === null ||
          row.grantRole === null ||
          row.grantorUserId === null ||
          row.grantorKeyId === null ||
          row.grantSignature === null
        ) {
          continue;
        }
        grants.push({
          subjectUserId: row.userId,
          subjectKeyId: row.subjectKeyId,
          role: row.grantRole,
          grantorUserId: row.grantorUserId,
          grantorKeyId: row.grantorKeyId,
          signature: new Uint8Array(row.grantSignature),
        });
      }
      for (const row of invitationRows) {
        grants.push({
          subjectUserId: row.inviteeUserId,
          subjectKeyId: row.inviteeKeyId,
          role: row.role,
          grantorUserId: row.invitedById,
          grantorKeyId: row.grantorKeyId,
          signature: new Uint8Array(row.grantSignature),
        });
      }
      return grants;
    },

    /** The room's key state for AZ-15, for an ACTIVE member of the ACTIVE room. */
    async roomRekeyView(roomId: string, viewerId: string) {
      if (!isUuidV4(roomId) || !isUuidV4(viewerId)) return null;
      return db.room.findFirst({
        where: { id: roomId, status: 'ACTIVE', members: { some: { userId: viewerId, status: 'ACTIVE' } } },
        select: { keyState: true, rekeyReasons: true, rekeyRequiredSince: true, currentKeyVersion: true },
      });
    },

    // -------------------------------------------------------------------- locks (transaction)

    /** Locks the room's PENDING operation, if any. Taken after the room lock. */
    lockPendingOperation(roomId: string): Promise<RekeyOperationRecord | null> {
      return lockOperationBy(Prisma.sql`room_id = ${roomId}::uuid AND status = 'PENDING'`);
    },

    /** Locks an operation by its ID AND its room (OL-13): another room's operation is not found. */
    lockOperation(roomId: string, operationId: string): Promise<RekeyOperationRecord | null> {
      if (!isUuidV4(roomId) || !isUuidV4(operationId)) return Promise.resolve(null);
      return lockOperationBy(Prisma.sql`id = ${operationId}::uuid AND room_id = ${roomId}::uuid`);
    },

    // ------------------------------------------------------------------- writes (conditional)

    /** Closes a PENDING operation (ABANDONED, SUPERSEDED, CANCELLED or STALE). */
    async closeOperation(
      operation: RekeyOperationRecord,
      status: 'ABANDONED' | 'SUPERSEDED' | 'CANCELLED' | 'STALE',
      reason: string,
      now: Date,
    ): Promise<boolean> {
      const result = await db.rekeyOperation.updateMany({
        where: { id: operation.id, roomId: operation.roomId, status: 'PENDING' },
        data: { status, closedReason: reason, closedAt: now },
      });
      return result.count === 1;
    },

    /** Moves the room's key state between REKEY_REQUIRED and REKEYING, only from the checked state. */
    async setKeyState(
      roomId: string,
      from: RoomKeyState,
      to: 'REKEY_REQUIRED' | 'REKEYING',
      now: Date,
    ): Promise<boolean> {
      const result = await db.room.updateMany({
        where: { id: roomId, keyState: from, status: 'ACTIVE' },
        data: { keyState: to, updatedAt: now },
      });
      return result.count === 1;
    },

    async insertOperation(input: {
      readonly roomId: string;
      readonly startedById: string;
      readonly mode: RekeyMode;
      readonly baseVersion: number;
      readonly membershipEpoch: bigint;
      readonly recipientSetDigest: Uint8Array;
      readonly leaseExpiresAt: Date;
      readonly now: Date;
    }): Promise<RekeyOperationRecord> {
      const row = await db.rekeyOperation.create({
        data: {
          roomId: input.roomId,
          startedById: input.startedById,
          mode: input.mode,
          status: 'PENDING',
          baseVersion: input.baseVersion,
          targetVersion: input.baseVersion + 1,
          membershipEpoch: input.membershipEpoch,
          recipientSetDigest: new Uint8Array(input.recipientSetDigest),
          leaseExpiresAt: input.leaseExpiresAt,
          createdAt: input.now,
        },
        select: OPERATION_COLUMNS,
      });
      return {
        ...row,
        recipientSetDigest: new Uint8Array(row.recipientSetDigest),
        payloadDigest: row.payloadDigest === null ? null : new Uint8Array(row.payloadDigest),
      };
    },

    /**
     * ADR-013 step 3, the activating writes. The caller holds the room and operation locks and has
     * checked everything. In order: version v RETIRED, version v+1 ACTIVE with its signed statement,
     * one envelope per snapshot recipient (PENDING for invitees, bound to the invitation), the room
     * on v+1 and ACTIVE with no reasons, the operation COMPLETED with the payload digest. Any failed
     * statement rolls the whole transaction back: nothing partial is ever stored.
     */
    async activateKeyVersion(input: NewKeyVersion): Promise<void> {
      const { roomId, operation, now } = input;
      const retired = await db.roomKeyVersion.updateMany({
        where: { roomId, version: operation.baseVersion, status: 'ACTIVE' },
        data: { status: 'RETIRED', retiredAt: now },
      });
      if (retired.count !== 1) throw new Error('base key version is not ACTIVE');
      const sorted = [...input.recipients];
      await db.roomKeyVersion.create({
        data: {
          roomId,
          version: operation.targetVersion,
          status: 'ACTIVE',
          commitment: new Uint8Array(input.commitment),
          algorithmSuite: 'CM1',
          reasons: [...input.reasons],
          createdByOperationId: operation.id,
          createdById: input.creatorUserId,
          createdByKeyId: input.creatorKeyId,
          previousCommitment: new Uint8Array(input.previousCommitment),
          recipientUserIds: sorted.map((r) => r.userId),
          recipientKeyIds: sorted.map((r) => r.keyId),
          statementSignature: new Uint8Array(input.statementSignature),
          createdAt: now,
        },
        select: { id: true },
      });
      await db.keyEnvelope.createMany({
        data: sorted.map((r) => {
          const wrapped = input.envelopes.get(recipientKey(r.userId, r.keyId));
          if (wrapped === undefined) throw new Error('envelope missing for a snapshot recipient');
          return {
            roomId,
            keyVersion: operation.targetVersion,
            recipientUserId: r.userId,
            recipientKeyId: r.keyId,
            invitationId: r.invitationId,
            status: r.kind === 'INVITEE' ? ('PENDING' as const) : ('ACTIVE' as const),
            wrappedKey: new Uint8Array(wrapped),
            algorithm: 'RSA-OAEP-3072-SHA256',
            createdById: input.creatorUserId,
            createdAt: now,
          };
        }),
      });
      const room = await db.room.updateMany({
        where: { id: roomId, currentKeyVersion: operation.baseVersion, membershipEpoch: operation.membershipEpoch },
        data: {
          currentKeyVersion: operation.targetVersion,
          keyState: 'ACTIVE',
          rekeyReasons: [],
          rekeyRequiredSince: null,
          updatedAt: now,
        },
      });
      if (room.count !== 1) throw new Error('room changed during finalize');
      const completed = await db.rekeyOperation.updateMany({
        where: { id: operation.id, roomId, status: 'PENDING' },
        data: {
          status: 'COMPLETED',
          payloadDigest: new Uint8Array(input.payloadDigest),
          completedAt: now,
          closedAt: now,
          closedReason: 'COMPLETED',
        },
      });
      if (completed.count !== 1) throw new Error('operation changed during finalize');
    },

    /**
     * AZ-14 (CM-T053): the member's current identity receives the envelopes the caller made, the
     * membership records the caller's signed grant for that key (the history trigger keeps the
     * earlier grant for statements the old key signed), and a SUSPENDED membership of a
     * re-enabled account becomes ACTIVE again. Envelopes for any other key of the member in the
     * room are deleted first: an identity holds the room's keys only through its own envelopes.
     */
    async reshareKeys(input: {
      readonly membershipId: string;
      readonly roomId: string;
      readonly userId: string;
      readonly role: RoomRole;
      readonly reinstate: boolean;
      readonly grant: {
        readonly subjectKeyId: string;
        readonly grantorUserId: string;
        readonly grantorKeyId: string;
        readonly signature: Uint8Array;
      };
      readonly envelopes: readonly { readonly keyVersion: number; readonly wrappedKey: Uint8Array }[];
      readonly now: Date;
    }): Promise<boolean> {
      const { roomId, userId, grant, now } = input;
      const updated = await db.roomMember.updateMany({
        where: {
          id: input.membershipId,
          roomId,
          userId,
          role: input.role,
          status: input.reinstate ? 'SUSPENDED' : 'ACTIVE',
        },
        data: {
          status: 'ACTIVE',
          ...(input.reinstate ? { removedAt: null, removedById: null, removalReason: null } : {}),
          subjectKeyId: grant.subjectKeyId,
          grantRole: input.role,
          grantorUserId: grant.grantorUserId,
          grantorKeyId: grant.grantorKeyId,
          grantSignature: new Uint8Array(grant.signature),
        },
      });
      if (updated.count !== 1) return false;
      await db.keyEnvelope.deleteMany({ where: { roomId, recipientUserId: userId } });
      await db.keyEnvelope.createMany({
        data: input.envelopes.map((e) => ({
          roomId,
          keyVersion: e.keyVersion,
          recipientUserId: userId,
          recipientKeyId: grant.subjectKeyId,
          status: 'ACTIVE' as const,
          wrappedKey: new Uint8Array(e.wrappedKey),
          algorithm: 'RSA-OAEP-3072-SHA256',
          createdById: grant.grantorUserId,
          createdAt: now,
        })),
      });
      return true;
    },

    /** Whether the member's identity holds an ACTIVE envelope of the version in the room. */
    async holdsEnvelope(roomId: string, userId: string, keyId: string, keyVersion: number): Promise<boolean> {
      const count = await db.keyEnvelope.count({
        where: { roomId, recipientUserId: userId, recipientKeyId: keyId, keyVersion, status: 'ACTIVE' },
      });
      return count > 0;
    },

    /**
     * The member-loss transaction of AZ-11 (key-lifecycle R2): status LEFT, the member's envelopes
     * deleted, the epoch incremented and REKEY_REQUIRED with MEMBER_LEFT (by the caller, through
     * requireRekey). Conditional on the locked ACTIVE membership.
     */
    async markMemberLeft(membershipId: string, roomId: string, userId: string, now: Date): Promise<boolean> {
      const result = await db.roomMember.updateMany({
        where: { id: membershipId, roomId, userId, status: 'ACTIVE' },
        data: { status: 'LEFT', removedAt: now, removedById: userId, removalReason: 'LEFT_ROOM' },
      });
      if (result.count !== 1) return false;
      await db.keyEnvelope.deleteMany({ where: { roomId, recipientUserId: userId } });
      return true;
    },
  };
}

function identityRecord(row: {
  id: string;
  userId: string;
  status: IdentityRecord['status'];
  algorithmSuite: string;
  publicKeySpki: Uint8Array;
  signingPublicKeySpki: Uint8Array;
  identitySignature: Uint8Array;
  publicKeyFingerprint: string;
  createdAt: Date;
}): IdentityRecord {
  return {
    userId: row.userId,
    keyId: row.id,
    status: row.status,
    algorithmSuite: row.algorithmSuite,
    publicKeySpki: new Uint8Array(row.publicKeySpki),
    signingPublicKeySpki: new Uint8Array(row.signingPublicKeySpki),
    identitySignature: new Uint8Array(row.identitySignature),
    publicKeyFingerprint: row.publicKeyFingerprint,
    createdAt: row.createdAt,
  };
}

export type RekeyStoreFunctions = ReturnType<typeof rekeyStoreFunctions>;
export type { RekeyReason };
