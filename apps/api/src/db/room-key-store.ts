import { isUuidV4 } from '@ciphermesh/shared';
import type { Prisma, PrismaClient } from '../generated/prisma/client';
import type { KeyPairStatus, KeyVersionStatus, RoomKeyState, RoomRole } from '../generated/prisma/enums';

/**
 * Data access for room key material and signed room statements (Phase 6, CM-T033 to CM-T036).
 *
 * What is stored here is public or ciphertext only: commitments, ECDSA signatures, identifiers and
 * RSA-OAEP envelopes that only their recipient can open. The server never holds room key material
 * (INV-04) and creates no envelope or statement itself; it stores what member browsers produced
 * after checking shapes and signatures, and serves it back for the browsers to verify (ADR-015).
 *
 * Every read is constrained in the query by the room ID AND the caller's ACTIVE membership in an
 * ACTIVE room (INV-06, OL-01), and envelopes additionally by recipient = caller (OL-05): no
 * endpoint can fetch an envelope by its own ID.
 */
type Db = PrismaClient | Prisma.TransactionClient;

/** A public identity row (any status: retired identities stay verifiable, ADR-015). */
export interface IdentityRecord {
  readonly userId: string;
  readonly keyId: string;
  readonly status: KeyPairStatus;
  readonly algorithmSuite: string;
  readonly publicKeySpki: Uint8Array;
  readonly signingPublicKeySpki: Uint8Array;
  readonly identitySignature: Uint8Array;
  readonly publicKeyFingerprint: string;
  readonly createdAt: Date;
}

export interface IdentityRef {
  readonly userId: string;
  readonly keyId: string;
}

export interface GrantRecord {
  readonly subjectUserId: string;
  readonly subjectKeyId: string;
  readonly role: RoomRole;
  readonly grantorUserId: string;
  readonly grantorKeyId: string;
  readonly signature: Uint8Array;
}

export interface KeyVersionRecord {
  readonly keyVersion: number;
  readonly status: KeyVersionStatus;
  readonly algorithmSuite: string;
  readonly commitment: Uint8Array;
  readonly previousCommitment: Uint8Array | null;
  readonly creatorUserId: string;
  readonly creatorKeyId: string;
  readonly recipients: readonly IdentityRef[];
  readonly signature: Uint8Array;
  readonly createdAt: Date;
}

export interface RoomKeyStateRecord {
  readonly currentKeyVersion: number;
  readonly keyState: RoomKeyState;
  /** Null for rooms created before Phase 6 (L-43). */
  readonly genesis: {
    readonly creatorUserId: string;
    readonly creatorKeyId: string;
    readonly signature: Uint8Array;
  } | null;
}

export interface EnvelopeRecord {
  readonly keyVersion: number;
  readonly recipientKeyId: string;
  readonly wrappedKey: Uint8Array;
}

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

const identityOf = (row: {
  id: string;
  userId: string;
  status: KeyPairStatus;
  algorithmSuite: string;
  publicKeySpki: Uint8Array;
  signingPublicKeySpki: Uint8Array;
  identitySignature: Uint8Array;
  publicKeyFingerprint: string;
  createdAt: Date;
}): IdentityRecord => ({
  userId: row.userId,
  keyId: row.id,
  status: row.status,
  algorithmSuite: row.algorithmSuite,
  publicKeySpki: new Uint8Array(row.publicKeySpki),
  signingPublicKeySpki: new Uint8Array(row.signingPublicKeySpki),
  identitySignature: new Uint8Array(row.identitySignature),
  publicKeyFingerprint: row.publicKeyFingerprint,
  createdAt: row.createdAt,
});

const refKey = (r: IdentityRef): string => `${r.userId}/${r.keyId}`;

function uniqueRefs(refs: readonly IdentityRef[]): IdentityRef[] {
  const seen = new Map<string, IdentityRef>();
  for (const r of refs) if (isUuidV4(r.userId) && isUuidV4(r.keyId)) seen.set(refKey(r), r);
  return [...seen.values()];
}

/** Bounds on the authority chain served for one room (the client bounds its work as well). */
const MAX_CHAIN_ROUNDS = 16;
const MAX_GRANTS = 1_000;

/** A membership filter: the caller is an ACTIVE member of the ACTIVE room. */
const callerIsMember = (roomId: string, userId: string) => ({
  id: roomId,
  status: 'ACTIVE' as const,
  members: { some: { userId, status: 'ACTIVE' as const } },
});

export function roomKeyStoreFunctions(db: Db) {
  async function identities(refs: readonly IdentityRef[]): Promise<IdentityRecord[]> {
    const unique = uniqueRefs(refs);
    if (unique.length === 0) return [];
    const rows = await db.userKeyPair.findMany({
      where: { OR: unique.map((r) => ({ id: r.keyId, userId: r.userId })) },
      select: IDENTITY_SELECT,
    });
    return rows.map(identityOf);
  }

  return {
    // ------------------------------------------------------------------------------ identities

    /** The ACTIVE identity (public part only) of an ACTIVE account, or null. */
    async findActiveIdentity(userId: string): Promise<IdentityRecord | null> {
      if (!isUuidV4(userId)) return null;
      const row = await db.userKeyPair.findFirst({
        where: { userId, status: 'ACTIVE', user: { status: 'ACTIVE' } },
        select: IDENTITY_SELECT,
      });
      return row === null ? null : identityOf(row);
    },

    /**
     * Locks the named identity of the user against a concurrent vault reset and reports whether it
     * is still the ACTIVE one. A reset that supersedes it waits for this transaction, and a reset
     * that came first makes this return false (key-lifecycle section 3).
     */
    async lockActiveIdentity(userId: string, keyId: string): Promise<boolean> {
      if (!isUuidV4(userId) || !isUuidV4(keyId)) return false;
      const rows = await db.$queryRaw<{ id: string }[]>`
        SELECT id::text AS id FROM user_key_pairs
         WHERE id = ${keyId}::uuid AND user_id = ${userId}::uuid AND status = 'ACTIVE'
           FOR SHARE`;
      return rows.length === 1;
    },

    /** The current public identity of an ACTIVE member of the room, as seen by an ACTIVE member. */
    async findMemberIdentity(roomId: string, viewerId: string, memberId: string): Promise<IdentityRecord | null> {
      if (!isUuidV4(roomId) || !isUuidV4(viewerId) || !isUuidV4(memberId)) return null;
      const member = await db.roomMember.findFirst({
        where: { roomId, userId: memberId, status: 'ACTIVE', room: callerIsMember(roomId, viewerId) },
        select: { userId: true },
      });
      if (member === null) return null;
      const row = await db.userKeyPair.findFirst({
        where: { userId: memberId, status: 'ACTIVE', user: { status: 'ACTIVE' } },
        select: IDENTITY_SELECT,
      });
      return row === null ? null : identityOf(row);
    },

    // ---------------------------------------------------------------------------- key material

    /** The room's genesis and key state, for an ACTIVE member (AZ-15). */
    async findRoomKeyState(roomId: string, viewerId: string): Promise<RoomKeyStateRecord | null> {
      if (!isUuidV4(roomId) || !isUuidV4(viewerId)) return null;
      const room = await db.room.findFirst({
        where: callerIsMember(roomId, viewerId),
        select: {
          currentKeyVersion: true,
          keyState: true,
          createdById: true,
          creatorKeyId: true,
          genesisSignature: true,
        },
      });
      if (room === null) return null;
      return {
        currentKeyVersion: room.currentKeyVersion,
        keyState: room.keyState,
        genesis:
          room.creatorKeyId === null || room.genesisSignature === null
            ? null
            : {
                creatorUserId: room.createdById,
                creatorKeyId: room.creatorKeyId,
                signature: new Uint8Array(room.genesisSignature),
              },
      };
    },

    /** Every key version of the room with its signed statement, oldest first (AZ-15). */
    async listKeyVersions(roomId: string, viewerId: string): Promise<KeyVersionRecord[]> {
      if (!isUuidV4(roomId) || !isUuidV4(viewerId)) return [];
      const rows = await db.roomKeyVersion.findMany({
        where: { roomId, room: callerIsMember(roomId, viewerId) },
        orderBy: { version: 'asc' },
        select: {
          version: true,
          status: true,
          algorithmSuite: true,
          commitment: true,
          previousCommitment: true,
          createdById: true,
          createdByKeyId: true,
          recipientUserIds: true,
          recipientKeyIds: true,
          statementSignature: true,
          createdAt: true,
        },
      });
      return rows.map((row) => ({
        keyVersion: row.version,
        status: row.status,
        algorithmSuite: row.algorithmSuite,
        commitment: new Uint8Array(row.commitment),
        previousCommitment: row.previousCommitment === null ? null : new Uint8Array(row.previousCommitment),
        creatorUserId: row.createdById,
        creatorKeyId: row.createdByKeyId,
        recipients: row.recipientUserIds.map((userId, i) => ({ userId, keyId: row.recipientKeyIds[i] ?? '' })),
        signature: new Uint8Array(row.statementSignature),
        createdAt: row.createdAt,
      }));
    },

    /** The caller's own ACTIVE envelopes in the room (AZ-12, OL-05). PENDING envelopes are never served. */
    async listOwnEnvelopes(roomId: string, userId: string): Promise<EnvelopeRecord[]> {
      if (!isUuidV4(roomId) || !isUuidV4(userId)) return [];
      const rows = await db.keyEnvelope.findMany({
        where: { roomId, recipientUserId: userId, status: 'ACTIVE', room: callerIsMember(roomId, userId) },
        orderBy: [{ keyVersion: 'asc' }, { recipientKeyId: 'asc' }],
        select: { keyVersion: true, recipientKeyId: true, wrappedKey: true },
      });
      return rows.map((row) => ({
        keyVersion: row.keyVersion,
        recipientKeyId: row.recipientKeyId,
        wrappedKey: new Uint8Array(row.wrappedKey),
      }));
    },

    /**
     * The signed grants a member needs to verify the room's statements (ADR-015 section 4): the
     * caller's own current grant, and the OWNER and ADMIN grants of every identity in the authority
     * chain of the key-version creators and of the caller's grantor, back to the genesis creator.
     * Grants of former members, and grants a later one replaced, are included when the chain runs
     * through them.
     */
    async grantChain(roomId: string, viewerId: string, start: readonly IdentityRef[]): Promise<GrantRecord[]> {
      if (!isUuidV4(roomId) || !isUuidV4(viewerId)) return [];
      const visible = await db.room.count({ where: callerIsMember(roomId, viewerId) });
      if (visible !== 1) return [];
      const select = {
        id: true,
        userId: true,
        subjectKeyId: true,
        grantRole: true,
        grantorUserId: true,
        grantorKeyId: true,
        grantSignature: true,
      } as const;
      const found = new Map<string, GrantRecord>();
      const add = (row: {
        id: string;
        userId: string;
        subjectKeyId: string | null;
        grantRole: RoomRole | null;
        grantorUserId: string | null;
        grantorKeyId: string | null;
        grantSignature: Uint8Array | null;
      }): IdentityRef | undefined => {
        if (
          row.subjectKeyId === null ||
          row.grantRole === null ||
          row.grantorUserId === null ||
          row.grantorKeyId === null ||
          row.grantSignature === null ||
          found.has(row.id)
        ) {
          return undefined;
        }
        found.set(row.id, {
          subjectUserId: row.userId,
          subjectKeyId: row.subjectKeyId,
          role: row.grantRole,
          grantorUserId: row.grantorUserId,
          grantorKeyId: row.grantorKeyId,
          signature: new Uint8Array(row.grantSignature),
        });
        return { userId: row.grantorUserId, keyId: row.grantorKeyId };
      };
      const own = await db.roomMember.findFirst({
        where: { roomId, userId: viewerId, status: 'ACTIVE' },
        select,
      });
      const seen = new Set<string>();
      let frontier = uniqueRefs([...start, ...(own === null ? [] : [add(own)].filter((r) => r !== undefined))]);
      for (const r of frontier) seen.add(refKey(r));
      // Phase 11: the chain reads every grant ever stored (room_member_grants), not only each
      // membership's latest one, so statements an earlier identity signed keep their authority
      // after a re-share replaced that membership's grant (AZ-14, CM-T053).
      for (let round = 0; round < MAX_CHAIN_ROUNDS && frontier.length > 0 && found.size < MAX_GRANTS; round++) {
        const rows = await db.roomMemberGrant.findMany({
          where: {
            roomId,
            role: { in: ['OWNER', 'ADMIN'] },
            OR: frontier.map((r) => ({ subjectUserId: r.userId, subjectKeyId: r.keyId })),
          },
          select: {
            id: true,
            subjectUserId: true,
            subjectKeyId: true,
            role: true,
            grantorUserId: true,
            grantorKeyId: true,
            grantSignature: true,
          },
          orderBy: { createdAt: 'asc' },
          take: MAX_GRANTS,
        });
        const next: IdentityRef[] = [];
        for (const history of rows) {
          const grantor = add({
            id: history.id,
            userId: history.subjectUserId,
            subjectKeyId: history.subjectKeyId,
            grantRole: history.role,
            grantorUserId: history.grantorUserId,
            grantorKeyId: history.grantorKeyId,
            grantSignature: history.grantSignature,
          });
          if (grantor !== undefined && !seen.has(refKey(grantor))) {
            seen.add(refKey(grantor));
            next.push(grantor);
          }
        }
        frontier = next;
      }
      return [...found.values()];
    },

    /** Public identities for (user, key) pairs, any status (ADR-015: retired keys stay verifiable). */
    identities,
  };
}

export type RoomKeyStoreFunctions = ReturnType<typeof roomKeyStoreFunctions>;
