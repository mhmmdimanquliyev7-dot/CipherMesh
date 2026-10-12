import { isUuidV4, type SecretStatus } from '@ciphermesh/shared';
import { Prisma, type PrismaClient } from '../generated/prisma/client';

/**
 * Data access for recipient-bound secrets (Phase 9, CM-T043, CM-T044; data-model 4.13 and 5,
 * DF-09). Part of the room store, so one transaction can lock the user, the room, the memberships
 * and the secret row in the established order (user, room, membership, object).
 *
 * - Lists are metadata only and are constrained inside the query by room ID, the caller's ACTIVE
 *   membership in an ACTIVE room and, for MEMBER and VIEWER, by sender or recipient = caller
 *   (INV-06, OL-08, OL-14). No list or lookup returns the payload or the wrapped SEK.
 * - The only function that returns ciphertext is `releaseSecret`, called inside the reveal
 *   transaction after `lockSecretForRecipient` locked the row by secret ID, room ID and
 *   recipient = caller (OL-06). For a burn-after-reading secret the same statement that returns
 *   the ciphertext sets it, the IV and the wrapped SEK to NULL (INV-13): the values exist after
 *   the commit only in the response.
 * - Every destruction (burn, expiry, revocation) is conditional on status ACTIVE and removes the
 *   material together; the guard trigger of migration 20261009000000_burn_secrets makes every
 *   final state final. Rows are never deleted; the metadata row stays as a tombstone.
 */
type Db = PrismaClient | Prisma.TransactionClient;

/** The metadata of a secret: what lists and the sender see. Never ciphertext or a wrapped SEK. */
export interface SecretMetadata {
  readonly id: string;
  readonly roomId: string;
  readonly senderId: string;
  readonly recipientUserId: string;
  readonly recipientKeyId: string;
  /** As stored; the service reports an ACTIVE secret past its expiry as EXPIRED (INV-14). */
  readonly status: SecretStatus;
  readonly burnAfterReading: boolean;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  readonly revealedAt: Date | null;
  readonly destroyedAt: Date | null;
}

/** A secret row locked for its recipient, with what the reveal decision needs. */
export interface LockedSecret extends SecretMetadata {
  /** Whether the recipient key the SEK was wrapped to is still the recipient's ACTIVE identity. */
  readonly recipientKeyActive: boolean;
}

/** The ciphertext released to the recipient (once, for a burn-after-reading secret). */
export interface ReleasedSecret {
  readonly metadata: SecretMetadata;
  readonly wrappedSek: Uint8Array;
  readonly payloadIv: Uint8Array;
  readonly payloadCiphertext: Uint8Array;
}

export interface NewSecret {
  readonly id: string;
  readonly roomId: string;
  readonly senderId: string;
  readonly recipientUserId: string;
  readonly recipientKeyId: string;
  readonly burnAfterReading: boolean;
  readonly wrappedSek: Uint8Array;
  readonly payloadIv: Uint8Array;
  readonly payloadCiphertext: Uint8Array;
  readonly expiresAt: Date;
  readonly now: Date;
}

/** The client-chosen secret ID was used before (in any room). Raised inside the creating transaction. */
export class SecretIdUnavailableError extends Error {
  constructor() {
    super('Secret ID unavailable');
    this.name = 'SecretIdUnavailableError';
  }
}

const metadataSelect = {
  id: true,
  roomId: true,
  senderId: true,
  recipientUserId: true,
  recipientKeyId: true,
  status: true,
  burnAfterReading: true,
  expiresAt: true,
  createdAt: true,
  revealedAt: true,
  destroyedAt: true,
} as const;

interface SecretRow {
  id: string;
  room_id: string;
  sender_id: string;
  recipient_user_id: string;
  recipient_key_id: string;
  status: SecretStatus;
  burn_after_reading: boolean;
  expires_at: Date;
  created_at: Date;
  revealed_at: Date | null;
  destroyed_at: Date | null;
}

const fromRow = (row: SecretRow): SecretMetadata => ({
  id: row.id,
  roomId: row.room_id,
  senderId: row.sender_id,
  recipientUserId: row.recipient_user_id,
  recipientKeyId: row.recipient_key_id,
  status: row.status,
  burnAfterReading: row.burn_after_reading,
  expiresAt: row.expires_at,
  createdAt: row.created_at,
  revealedAt: row.revealed_at,
  destroyedAt: row.destroyed_at,
});

/**
 * The destruction write: material removed (crypto-shredding of the live copy), destroyed_at set.
 * Conditional on ACTIVE wherever it is used.
 */
const destroyed = (status: 'EXPIRED' | 'REVOKED', now: Date) => ({
  status,
  wrappedSek: null,
  payloadCiphertext: null,
  payloadIv: null,
  destroyedAt: now,
});

export function secretStoreFunctions(db: Db) {
  return {
    /** A secret of the room by (secret ID, room ID) (OL-02), any status, for authorization facts. */
    async findRoomSecret(roomId: string, secretId: string): Promise<SecretMetadata | null> {
      if (!isUuidV4(roomId) || !isUuidV4(secretId)) return null;
      return db.secret.findFirst({ where: { id: secretId, roomId }, select: metadataSelect });
    },

    /**
     * The room's secrets visible to the caller (OL-14), newest first, one keyset page: every secret
     * for `allOfRoom` (OWNER, ADMIN), otherwise those the caller sent or received. The membership
     * filter is in the query (OL-08).
     */
    async listRoomSecrets(
      roomId: string,
      userId: string,
      allOfRoom: boolean,
      after: { readonly at: Date; readonly id: string } | undefined,
      take: number,
    ): Promise<SecretMetadata[]> {
      return db.secret.findMany({
        where: {
          AND: [
            {
              roomId,
              room: { status: 'ACTIVE', members: { some: { userId, status: 'ACTIVE' } } },
            },
            allOfRoom ? {} : { OR: [{ senderId: userId }, { recipientUserId: userId }] },
            after === undefined
              ? {}
              : { OR: [{ createdAt: { lt: after.at } }, { createdAt: after.at, id: { lt: after.id } }] },
          ],
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take,
        select: metadataSelect,
      });
    },

    /**
     * Locks the secret row for its recipient (after the user, the room and the membership), or
     * returns null: selected by secret ID AND room ID AND recipient = caller inside the locking
     * statement (OL-06). Concurrent reveals of one secret, from any API process, queue here; the
     * second sees the state the first committed. The recipient key's status is read, not locked:
     * a vault reset locks the identity row before the secrets it revokes, and the reveal must not
     * wait on that row while it holds the secret (no lock cycle). A reveal racing a reset can at
     * most release ciphertext for the retired key, which only the retired private key opens.
     */
    async lockSecretForRecipient(roomId: string, secretId: string, userId: string): Promise<LockedSecret | null> {
      if (!isUuidV4(roomId) || !isUuidV4(secretId)) return null;
      const rows = await db.$queryRaw<(SecretRow & { key_active: boolean })[]>`
        SELECT s.id::text AS id, s.room_id::text AS room_id, s.sender_id::text AS sender_id,
               s.recipient_user_id::text AS recipient_user_id, s.recipient_key_id::text AS recipient_key_id,
               s.status::text AS status, s.burn_after_reading, s.expires_at, s.created_at, s.revealed_at,
               s.destroyed_at, (k.status = 'ACTIVE') AS key_active
          FROM secrets s
          JOIN user_key_pairs k ON k.id = s.recipient_key_id AND k.user_id = s.recipient_user_id
         WHERE s.id = ${secretId}::uuid AND s.room_id = ${roomId}::uuid AND s.recipient_user_id = ${userId}::uuid
           FOR UPDATE OF s`;
      const row = rows[0];
      return row === undefined ? null : { ...fromRow(row), recipientKeyActive: row.key_active };
    },

    /** Locks any secret row of the room (after the room and the membership), for revocation. */
    async lockRoomSecret(roomId: string, secretId: string): Promise<SecretMetadata | null> {
      if (!isUuidV4(roomId) || !isUuidV4(secretId)) return null;
      const rows = await db.$queryRaw<SecretRow[]>`
        SELECT id::text AS id, room_id::text AS room_id, sender_id::text AS sender_id,
               recipient_user_id::text AS recipient_user_id, recipient_key_id::text AS recipient_key_id,
               status::text AS status, burn_after_reading, expires_at, created_at, revealed_at, destroyed_at
          FROM secrets
         WHERE id = ${secretId}::uuid AND room_id = ${roomId}::uuid
           FOR UPDATE`;
      const row = rows[0];
      return row === undefined ? null : fromRow(row);
    },

    /**
     * Releases the ciphertext of a locked ACTIVE, unexpired secret to its recipient (DF-09). For a
     * burn-after-reading secret one statement returns the stored values and destroys them: status
     * REVEALED, payload, IV and wrapped SEK NULL (INV-13). Otherwise the values stay and the first
     * reveal is recorded (D-09-02). Returns null when the row is no longer redeemable at `now`,
     * so a caller that skipped its own checks still cannot release twice. The CTE reads the values
     * as they were before the statement; RETURNING hands back those, not the NULLs written.
     */
    async releaseSecret(roomId: string, secretId: string, recipientUserId: string, now: Date) {
      const rows = await db.$queryRaw<
        (SecretRow & { wrapped_sek: Uint8Array; payload_iv: Uint8Array; payload_ciphertext: Uint8Array })[]
      >`
        WITH released AS (
          SELECT id, wrapped_sek, payload_iv, payload_ciphertext
            FROM secrets
           WHERE id = ${secretId}::uuid AND room_id = ${roomId}::uuid
             AND recipient_user_id = ${recipientUserId}::uuid
             AND status = 'ACTIVE' AND expires_at > ${now}
        )
        UPDATE secrets s SET
          status = CASE WHEN s.burn_after_reading THEN 'REVEALED'::"SecretStatus" ELSE s.status END,
          revealed_at = COALESCE(s.revealed_at, ${now}),
          destroyed_at = CASE WHEN s.burn_after_reading THEN ${now} ELSE s.destroyed_at END,
          wrapped_sek = CASE WHEN s.burn_after_reading THEN NULL ELSE s.wrapped_sek END,
          payload_iv = CASE WHEN s.burn_after_reading THEN NULL ELSE s.payload_iv END,
          payload_ciphertext = CASE WHEN s.burn_after_reading THEN NULL ELSE s.payload_ciphertext END
          FROM released r
         -- Repeated on the UPDATE itself: under READ COMMITTED PostgreSQL re-evaluates these
         -- conditions on the newest row version if another transaction changed it meanwhile, so
         -- even without the row lock a second release would update nothing.
         WHERE s.id = r.id AND s.status = 'ACTIVE' AND s.expires_at > ${now}
        RETURNING s.id::text AS id, s.room_id::text AS room_id, s.sender_id::text AS sender_id,
                  s.recipient_user_id::text AS recipient_user_id, s.recipient_key_id::text AS recipient_key_id,
                  s.status::text AS status, s.burn_after_reading, s.expires_at, s.created_at, s.revealed_at,
                  s.destroyed_at, r.wrapped_sek, r.payload_iv, r.payload_ciphertext`;
      const row = rows[0];
      if (row === undefined) return null;
      return {
        metadata: fromRow(row),
        wrappedSek: new Uint8Array(row.wrapped_sek),
        payloadIv: new Uint8Array(row.payload_iv),
        payloadCiphertext: new Uint8Array(row.payload_ciphertext),
      } satisfies ReleasedSecret;
    },

    /** Whether a secret ID was ever used, in any room (IDs are never reused, CD-08). */
    async secretIdUsed(secretId: string): Promise<boolean> {
      return (await db.secret.count({ where: { id: secretId } })) > 0;
    },

    /** ACTIVE, unexpired secrets the user sent, in any room (D-09-04). Call with the user row locked. */
    async activeSentSecretCount(senderId: string, now: Date): Promise<number> {
      return db.secret.count({ where: { senderId, status: 'ACTIVE', expiresAt: { gt: now } } });
    },

    /**
     * Locks the recipient's ACTIVE identity row and reports whether `keyId` is it. The sender's
     * browser wrapped the SEK to that key; any other key (an old one, another user's) is refused.
     */
    async lockActiveIdentity(userId: string, keyId: string): Promise<boolean> {
      if (!isUuidV4(userId) || !isUuidV4(keyId)) return false;
      const rows = await db.$queryRaw<{ id: string }[]>`
        SELECT k.id::text AS id
          FROM user_key_pairs k JOIN users u ON u.id = k.user_id
         WHERE k.id = ${keyId}::uuid AND k.user_id = ${userId}::uuid AND k.status = 'ACTIVE' AND u.status = 'ACTIVE'
           FOR SHARE OF k`;
      return rows.length === 1;
    },

    /** Inserts an ACTIVE secret (DF-09). The service has checked everything on locked state. */
    async insertSecret(secret: NewSecret): Promise<SecretMetadata> {
      try {
        return await db.secret.create({
          data: {
            id: secret.id,
            roomId: secret.roomId,
            senderId: secret.senderId,
            recipientUserId: secret.recipientUserId,
            recipientKeyId: secret.recipientKeyId,
            status: 'ACTIVE',
            burnAfterReading: secret.burnAfterReading,
            algorithmSuite: 'CM1',
            wrapAlgorithm: 'RSA-OAEP-3072-SHA256',
            wrappedSek: new Uint8Array(secret.wrappedSek),
            payloadIv: new Uint8Array(secret.payloadIv),
            payloadCiphertext: new Uint8Array(secret.payloadCiphertext),
            expiresAt: secret.expiresAt,
            createdAt: secret.now,
          },
          select: metadataSelect,
        });
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          throw new SecretIdUnavailableError();
        }
        throw error;
      }
    },

    /** AZ-25: revokes an ACTIVE secret of the room (material removed); false when it was not ACTIVE. */
    async revokeSecret(roomId: string, secretId: string, now: Date): Promise<boolean> {
      const updated = await db.secret.updateMany({
        where: { id: secretId, roomId, status: 'ACTIVE' },
        data: destroyed('REVOKED', now),
      });
      return updated.count === 1;
    },

    /**
     * The member left the room (removal, suspension): their ACTIVE secrets in these rooms are
     * revoked in the same transaction, so no later reinstatement makes them redeemable (D-09-06).
     */
    async revokeSecretsToMember(roomIds: readonly string[], userId: string, now: Date): Promise<number> {
      if (roomIds.length === 0) return 0;
      const updated = await db.secret.updateMany({
        where: { roomId: { in: [...roomIds] }, recipientUserId: userId, status: 'ACTIVE' },
        data: destroyed('REVOKED', now),
      });
      return updated.count;
    },

    /**
     * The recipient's identity was replaced (vault reset): ACTIVE secrets wrapped to the retired key
     * can never be opened, so they are revoked in the reset transaction (D-09-06).
     */
    async revokeSecretsToKey(userId: string, keyId: string, now: Date): Promise<{ id: string; roomId: string }[]> {
      const rows = await db.secret.findMany({
        where: { recipientUserId: userId, recipientKeyId: keyId, status: 'ACTIVE' },
        select: { id: true, roomId: true },
      });
      if (rows.length === 0) return [];
      await db.secret.updateMany({
        where: { id: { in: rows.map((r) => r.id) }, status: 'ACTIVE' },
        data: destroyed('REVOKED', now),
      });
      return rows;
    },
  };
}

export type SecretStoreFunctions = ReturnType<typeof secretStoreFunctions>;

/**
 * Secret cleanup, run by the worker as cm_worker (data-model 5, DF-09). Expiry is enforced at
 * reveal time by the API (INV-14); this step finishes what reveals already refuse: ACTIVE secrets
 * past their expiry become EXPIRED, and the ACTIVE secrets of rooms being deleted become REVOKED,
 * both with the payload, its IV and the wrapped SEK set to NULL. Without the wrapped SEK the secret
 * cannot be decrypted from the live system (crypto-shredding); backups keep their copies until
 * their retention ends (L-12). Rows are never deleted (cm_worker has no DELETE on secrets).
 */
export async function runSecretCleanup(
  prisma: PrismaClient,
  now: Date,
): Promise<{ readonly expired: number; readonly roomDeleted: number }> {
  const expired = await prisma.secret.updateMany({
    where: { status: 'ACTIVE', expiresAt: { lte: now } },
    data: destroyed('EXPIRED', now),
  });
  const roomDeleted = await prisma.secret.updateMany({
    where: { status: 'ACTIVE', room: { status: 'DELETING' } },
    data: destroyed('REVOKED', now),
  });
  return { expired: expired.count, roomDeleted: roomDeleted.count };
}
