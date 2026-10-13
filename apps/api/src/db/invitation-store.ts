import { isUuidV4 } from '@ciphermesh/shared';
import { Prisma, type PrismaClient } from '../generated/prisma/client';
import type { InvitationRole, InvitationStatus, SecurityProfile } from '../generated/prisma/enums';
import type { ListPosition } from './room-store';

/**
 * Data access for invitations (Phase 6, CM-T034, CM-T035, DF-06). Invitations are in-app only:
 * there is no bearer token or link (data-model section 6). An invitation carries the inviter's
 * signed membership grant and PENDING envelopes for the invitee's identity key; PENDING envelopes
 * are never served (CM-T035) and become ACTIVE only in the acceptance transaction.
 *
 * Locks, in the order every room transaction uses (authorization-model 9.6): the user row, then
 * the identity key row, then the room row, then the invitation and membership rows. Room
 * administration takes the room row first; account suspension takes the user row first; a vault
 * reset takes the identity key row first. None of them locks in the opposite order, so they
 * cannot deadlock with an acceptance.
 */
type Db = PrismaClient | Prisma.TransactionClient;

const OPEN: InvitationStatus[] = ['PENDING_APPROVAL', 'PENDING'];

export interface InvitationRecord {
  readonly id: string;
  readonly roomId: string;
  readonly inviteeUserId: string;
  readonly inviteeKeyId: string;
  readonly invitedById: string;
  readonly grantorKeyId: string;
  readonly grantSignature: Uint8Array;
  readonly role: InvitationRole;
  readonly status: InvitationStatus;
  readonly approvedById: string | null;
  readonly expiresAt: Date;
}

export interface RoomInvitationRecord {
  readonly id: string;
  readonly invitee: { readonly userId: string; readonly displayName: string; readonly keyId: string };
  readonly invitedBy: { readonly userId: string; readonly displayName: string };
  readonly role: InvitationRole;
  readonly status: InvitationStatus;
  readonly fingerprintConfirmed: boolean;
  readonly approvedByUserId: string | null;
  readonly expiresAt: Date;
  readonly createdAt: Date;
}

export interface OwnInvitationRecord {
  readonly id: string;
  readonly room: { readonly id: string; readonly name: string; readonly securityProfile: SecurityProfile };
  readonly invitedBy: { readonly userId: string; readonly displayName: string };
  readonly role: InvitationRole;
  readonly status: 'PENDING_APPROVAL' | 'PENDING';
  readonly inviteeKeyId: string;
  readonly expiresAt: Date;
  readonly createdAt: Date;
}

export interface NewInvitation {
  readonly roomId: string;
  readonly inviteeUserId: string;
  readonly inviteeKeyId: string;
  readonly invitedById: string;
  readonly grantorKeyId: string;
  readonly grantSignature: Uint8Array;
  readonly role: InvitationRole;
  readonly status: 'PENDING_APPROVAL' | 'PENDING';
  readonly confirmedFingerprint: string | null;
  readonly expiresAt: Date;
  readonly envelopes: readonly { readonly keyVersion: number; readonly wrappedKey: Uint8Array }[];
  readonly now: Date;
}

/** The invitee already has an open invitation to this room (partial unique index). */
export class InvitationPendingError extends Error {
  constructor() {
    super('Invitation pending');
    this.name = 'InvitationPendingError';
  }
}

const INVITATION_SELECT = {
  id: true,
  roomId: true,
  inviteeUserId: true,
  inviteeKeyId: true,
  invitedById: true,
  grantorKeyId: true,
  grantSignature: true,
  role: true,
  status: true,
  approvedById: true,
  expiresAt: true,
} as const;

const recordOf = (row: {
  id: string;
  roomId: string;
  inviteeUserId: string;
  inviteeKeyId: string;
  invitedById: string;
  grantorKeyId: string;
  grantSignature: Uint8Array;
  role: InvitationRole;
  status: InvitationStatus;
  approvedById: string | null;
  expiresAt: Date;
}): InvitationRecord => ({ ...row, grantSignature: new Uint8Array(row.grantSignature) });

const bytes = (value: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(value);

const ROOM_INVITATION_SELECT = {
  id: true,
  inviteeUserId: true,
  inviteeKeyId: true,
  role: true,
  status: true,
  confirmedFingerprint: true,
  approvedById: true,
  expiresAt: true,
  createdAt: true,
  invitee: { select: { displayName: true } },
  invitedBy: { select: { id: true, displayName: true } },
} as const;

const roomInvitationOf = (row: {
  id: string;
  inviteeUserId: string;
  inviteeKeyId: string;
  role: InvitationRole;
  status: InvitationStatus;
  confirmedFingerprint: string | null;
  approvedById: string | null;
  expiresAt: Date;
  createdAt: Date;
  invitee: { displayName: string };
  invitedBy: { id: string; displayName: string };
}): RoomInvitationRecord => ({
  id: row.id,
  invitee: { userId: row.inviteeUserId, displayName: row.invitee.displayName, keyId: row.inviteeKeyId },
  invitedBy: { userId: row.invitedBy.id, displayName: row.invitedBy.displayName },
  role: row.role,
  status: row.status,
  // Only whether a fingerprint was confirmed; the value itself is not sent back.
  fingerprintConfirmed: row.confirmedFingerprint !== null,
  approvedByUserId: row.approvedById,
  expiresAt: row.expiresAt,
  createdAt: row.createdAt,
});

/**
 * `advanceEpoch` (Phase 11) is the room store's single epoch writer, which also closes a PENDING
 * rekey operation as STALE; stores built without the room store (the vault's) never accept.
 */
export function invitationStoreFunctions(db: Db, advanceEpoch?: (roomId: string, now: Date) => Promise<void>) {
  /** Deletes the PENDING envelopes of the given invitations (decline, revoke, expiry, invalidation). */
  async function deletePendingEnvelopes(invitationIds: readonly string[]): Promise<number> {
    if (invitationIds.length === 0) return 0;
    const result = await db.keyEnvelope.deleteMany({
      where: { invitationId: { in: [...invitationIds] }, status: 'PENDING' },
    });
    return result.count;
  }

  return {
    /** Inserts the invitation and its PENDING envelopes. */
    async insertInvitation(invitation: NewInvitation): Promise<InvitationRecord> {
      let created;
      try {
        created = await db.invitation.create({
          data: {
            roomId: invitation.roomId,
            inviteeUserId: invitation.inviteeUserId,
            inviteeKeyId: invitation.inviteeKeyId,
            invitedById: invitation.invitedById,
            grantorKeyId: invitation.grantorKeyId,
            grantSignature: bytes(invitation.grantSignature),
            role: invitation.role,
            status: invitation.status,
            confirmedFingerprint: invitation.confirmedFingerprint,
            expiresAt: invitation.expiresAt,
            createdAt: invitation.now,
          },
          select: INVITATION_SELECT,
        });
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          throw new InvitationPendingError();
        }
        throw error;
      }
      await db.keyEnvelope.createMany({
        data: invitation.envelopes.map((envelope) => ({
          roomId: invitation.roomId,
          keyVersion: envelope.keyVersion,
          recipientUserId: invitation.inviteeUserId,
          recipientKeyId: invitation.inviteeKeyId,
          invitationId: created.id,
          status: 'PENDING' as const,
          wrappedKey: bytes(envelope.wrappedKey),
          algorithm: 'RSA-OAEP-3072-SHA256',
          createdById: invitation.invitedById,
          createdAt: invitation.now,
        })),
      });
      return recordOf(created);
    },

    /** Key versions of the room that can still be shared (not DESTROYED), for PC-07. */
    async shareableKeyVersions(roomId: string): Promise<number[]> {
      const rows = await db.roomKeyVersion.findMany({
        where: { roomId, status: { in: ['ACTIVE', 'RETIRED'] } },
        select: { version: true },
        orderBy: { version: 'asc' },
      });
      return rows.map((row) => row.version);
    },

    /** The invitation of the room, unlocked, for the resource loader of AZ-08 (OL-02). */
    async findRoomInvitation(roomId: string, invitationId: string): Promise<InvitationRecord | null> {
      if (!isUuidV4(roomId) || !isUuidV4(invitationId)) return null;
      const row = await db.invitation.findFirst({ where: { id: invitationId, roomId }, select: INVITATION_SELECT });
      return row === null ? null : recordOf(row);
    },

    /** The caller's own invitation, unlocked (SS-03, OL-11); another user's invitation is null. */
    async findOwnInvitation(invitationId: string, inviteeUserId: string): Promise<InvitationRecord | null> {
      if (!isUuidV4(invitationId) || !isUuidV4(inviteeUserId)) return null;
      const row = await db.invitation.findFirst({
        where: { id: invitationId, inviteeUserId },
        select: INVITATION_SELECT,
      });
      return row === null ? null : recordOf(row);
    },

    /** Locks the invitation row of the room (after the room row) and returns it, or null. */
    async lockInvitation(roomId: string, invitationId: string): Promise<InvitationRecord | null> {
      const rows = await db.$queryRaw<{ id: string }[]>`
        SELECT id::text AS id FROM invitations WHERE id = ${invitationId}::uuid AND room_id = ${roomId}::uuid FOR UPDATE`;
      if (rows.length !== 1) return null;
      const row = await db.invitation.findFirst({ where: { id: invitationId, roomId }, select: INVITATION_SELECT });
      return row === null ? null : recordOf(row);
    },

    /** The key versions of the PENDING envelopes the invitation carries for its invitee. */
    async pendingEnvelopeVersions(invitation: InvitationRecord): Promise<number[]> {
      const rows = await db.keyEnvelope.findMany({
        where: {
          invitationId: invitation.id,
          roomId: invitation.roomId,
          recipientUserId: invitation.inviteeUserId,
          recipientKeyId: invitation.inviteeKeyId,
          status: 'PENDING',
        },
        select: { keyVersion: true },
        orderBy: { keyVersion: 'asc' },
      });
      return rows.map((row) => row.keyVersion);
    },

    /** PENDING_APPROVAL to PENDING by the OWNER (AZ-07); the database refuses approver = inviter. */
    async approveInvitation(invitation: InvitationRecord, approvedById: string, now: Date): Promise<boolean> {
      const result = await db.invitation.updateMany({
        where: { id: invitation.id, roomId: invitation.roomId, status: 'PENDING_APPROVAL' },
        data: { status: 'PENDING', approvedById, approvedAt: now },
      });
      return result.count === 1;
    },

    /** Closes an open invitation (revoke, decline) and deletes its PENDING envelopes. */
    async closeInvitation(invitation: InvitationRecord, status: 'REVOKED' | 'DECLINED', now: Date): Promise<boolean> {
      const result = await db.invitation.updateMany({
        where: { id: invitation.id, roomId: invitation.roomId, status: { in: OPEN } },
        data: { status, ...(status === 'DECLINED' ? { respondedAt: now } : {}) },
      });
      if (result.count !== 1) return false;
      await deletePendingEnvelopes([invitation.id]);
      return true;
    },

    /**
     * Acceptance (CM-T035): the membership with the invitation's signed grant, the envelopes made
     * ACTIVE, the invitation ACCEPTED and the epoch incremented, all conditional on the checked state.
     */
    async acceptInvitation(invitation: InvitationRecord, firstKeyVersion: number, now: Date): Promise<boolean> {
      const updated = await db.invitation.updateMany({
        where: { id: invitation.id, roomId: invitation.roomId, status: 'PENDING' },
        data: { status: 'ACCEPTED', respondedAt: now },
      });
      if (updated.count !== 1) return false;
      await db.roomMember.create({
        data: {
          roomId: invitation.roomId,
          userId: invitation.inviteeUserId,
          role: invitation.role,
          firstKeyVersion,
          addedById: invitation.invitedById,
          invitationId: invitation.id,
          joinedAt: now,
          subjectKeyId: invitation.inviteeKeyId,
          grantRole: invitation.role,
          grantorUserId: invitation.invitedById,
          grantorKeyId: invitation.grantorKeyId,
          grantSignature: bytes(invitation.grantSignature),
        },
        select: { id: true },
      });
      await db.keyEnvelope.updateMany({
        where: {
          invitationId: invitation.id,
          roomId: invitation.roomId,
          recipientUserId: invitation.inviteeUserId,
          recipientKeyId: invitation.inviteeKeyId,
          status: 'PENDING',
        },
        data: { status: 'ACTIVE', invitationId: null },
      });
      // A new member changes the recipient set (ADR-013 step 5).
      if (advanceEpoch === undefined) throw new Error('acceptance needs the room store');
      await advanceEpoch(invitation.roomId, now);
      return true;
    },

    /** One invitation of the room in the projection of the room's list (after it was created). */
    async findRoomInvitationView(roomId: string, invitationId: string): Promise<RoomInvitationRecord | null> {
      const row = await db.invitation.findFirst({
        where: { id: invitationId, roomId },
        select: ROOM_INVITATION_SELECT,
      });
      return row === null ? null : roomInvitationOf(row);
    },

    /** The room's open, unexpired invitations, newest first (AZ-31, OL-11). */
    async listRoomInvitations(
      roomId: string,
      viewerId: string,
      now: Date,
      after: ListPosition | undefined,
      take: number,
    ): Promise<RoomInvitationRecord[]> {
      const rows = await db.invitation.findMany({
        where: {
          roomId,
          status: { in: OPEN },
          expiresAt: { gt: now },
          room: { status: 'ACTIVE', members: { some: { userId: viewerId, status: 'ACTIVE' } } },
          ...(after === undefined
            ? {}
            : { OR: [{ createdAt: { lt: after.at } }, { createdAt: after.at, id: { lt: after.id } }] }),
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take,
        select: ROOM_INVITATION_SELECT,
      });
      return rows.map(roomInvitationOf);
    },

    /** The caller's open, unexpired invitations to ACTIVE rooms, newest first (SS-03, OL-11). */
    async listOwnInvitations(
      userId: string,
      now: Date,
      after: ListPosition | undefined,
      take: number,
    ): Promise<OwnInvitationRecord[]> {
      const rows = await db.invitation.findMany({
        where: {
          inviteeUserId: userId,
          status: { in: OPEN },
          expiresAt: { gt: now },
          room: { status: 'ACTIVE' },
          ...(after === undefined
            ? {}
            : { OR: [{ createdAt: { lt: after.at } }, { createdAt: after.at, id: { lt: after.id } }] }),
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take,
        select: {
          id: true,
          role: true,
          status: true,
          inviteeKeyId: true,
          expiresAt: true,
          createdAt: true,
          room: { select: { id: true, name: true, securityProfile: true } },
          invitedBy: { select: { id: true, displayName: true } },
        },
      });
      return rows.map((row) => ({
        id: row.id,
        room: row.room,
        invitedBy: { userId: row.invitedBy.id, displayName: row.invitedBy.displayName },
        role: row.role,
        status: row.status === 'PENDING_APPROVAL' ? 'PENDING_APPROVAL' : 'PENDING',
        inviteeKeyId: row.inviteeKeyId,
        expiresAt: row.expiresAt,
        createdAt: row.createdAt,
      }));
    },

    /**
     * A vault reset retires the invitee's identity: its open invitations can no longer be accepted,
     * because their envelopes and grants name the old key (CM-T034, DF-06). They are revoked and
     * their PENDING envelopes deleted in the reset transaction. Returns the invitations closed.
     */
    async invalidateInvitationsForKey(userId: string, keyId: string): Promise<{ id: string; roomId: string }[]> {
      const rows = await db.invitation.findMany({
        where: { inviteeUserId: userId, inviteeKeyId: keyId, status: { in: OPEN } },
        select: { id: true, roomId: true },
      });
      if (rows.length === 0) return [];
      await db.invitation.updateMany({
        where: { id: { in: rows.map((r) => r.id) }, status: { in: OPEN } },
        data: { status: 'REVOKED' },
      });
      await deletePendingEnvelopes(rows.map((r) => r.id));
      return rows;
    },
  };
}

export type InvitationStoreFunctions = ReturnType<typeof invitationStoreFunctions>;

/**
 * Worker step (cm_worker): open invitations past their expiry become EXPIRED and lose their
 * PENDING envelopes. Expiry is enforced at read time anyway (INV-14); this reclaims the rows.
 */
export async function expireInvitations(prisma: PrismaClient, now: Date): Promise<{ invitationsExpired: number }> {
  return prisma.$transaction(
    async (tx) => {
      const expired = await tx.$queryRaw<{ id: string }[]>`
        UPDATE invitations SET status = 'EXPIRED'
         WHERE status IN ('PENDING_APPROVAL', 'PENDING') AND expires_at <= ${now}
        RETURNING id::text AS id`;
      if (expired.length > 0) {
        await tx.keyEnvelope.deleteMany({
          where: { invitationId: { in: expired.map((row) => row.id) }, status: 'PENDING' },
        });
      }
      return { invitationsExpired: expired.length };
    },
    { isolationLevel: 'ReadCommitted' },
  );
}
