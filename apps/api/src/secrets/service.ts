import { fromBase64Url } from '@ciphermesh/crypto/identity';
import {
  ErrorCode,
  SECRET_LIMITS,
  type RoomActionId,
  type RoomResourceFacts,
  type SecretStatus,
} from '@ciphermesh/shared';
import type { SecurityEventSink } from '../auth/security-events';
import type { Actor, RequestMeta } from '../auth/sessions';
import { policyOf, reapplyRoomPolicy } from '../authorization/policy';
import { reauthorizeRoomAction, roomDenial, type RoomAccess } from '../authorization/rooms';
import type { ListPosition, LockedRoom, RoomStore } from '../db/room-store';
import {
  SecretIdUnavailableError,
  type LockedSecret,
  type ReleasedSecret,
  type SecretMetadata,
} from '../db/secret-store';
import { HttpError } from '../http/errors';
import { factsOf } from '../rooms/service';

/**
 * Recipient-bound secrets with burn-after-reading (Phase 9, CM-T043, CM-T044; DF-09, data-model
 * 4.13 and 5, INV-13, INV-14, INV-17).
 *
 * The API never sees a secret's text or its SEK: the sender's browser encrypts the secret under a
 * fresh SEK and wraps only the 32-byte SEK to the recipient's identity key, which it authenticated
 * against the room's signed statements (INV-01, INV-17). The API decides who may store, see and
 * release which ciphertext, and makes the release of a burn-after-reading secret happen once.
 *
 * Create (AZ-23). One transaction locks the sender's user row, the room, the sender's membership
 * and the recipient's membership, in the established order, re-checks the matrix on that state,
 * then requires: the room's key state ACTIVE (PC-16, REKEY_REQUIRED), a recipient who is an ACTIVE
 * member other than the sender with exactly that ACTIVE identity key (OL-03), a lifetime within
 * the profile (PC-09) and above the minimum (D-09-03), burn-after-reading where the profile makes
 * it mandatory (PC-10), an unused secret ID and the sender's ACTIVE-secret limit (D-09-04).
 *
 * Reveal (AZ-24, the recipient only; DF-09, INV-13). A POST with an empty body, never a GET. One
 * transaction locks the recipient's user row, the room, the membership and the secret row,
 * selected by secret ID AND room ID AND recipient = caller (OL-06), re-checks AZ-24 on that state,
 * and requires the secret ACTIVE, unexpired at the moment of the reveal (INV-14) and still wrapped
 * to the recipient's ACTIVE identity key. One conditional statement then returns the ciphertext
 * and, for a burn-after-reading secret, destroys it (REVEALED; payload, IV and wrapped SEK NULL).
 * The response is built only after the commit, so a failed transaction releases nothing and a
 * committed burn is final. Concurrent reveals (tabs, browsers, API processes) queue on the row
 * lock; the first commits, every later one sees REVEALED and is refused. Delivery is therefore at
 * most once: a response lost after the commit cannot be repeated, by design (DF-09, L-03).
 * Refusals change nothing: a caller who is not the recipient gets 404 before any row is touched,
 * so nobody can burn another person's secret by guessing its ID (OL-06, OL-09).
 *
 * Revoke (AZ-25, own for MEMBER): an ACTIVE secret becomes REVOKED with its material removed.
 * Allowed while the room is REKEY_REQUIRED: only content writes are locked (PC-16).
 *
 * What the server can and cannot know: it knows that it released the ciphertext once. It cannot
 * know whether the browser decrypted it, whether a person read it, or whether they kept a copy.
 */

export interface SecretServiceDependencies {
  readonly store: RoomStore;
  readonly transaction: <T>(fn: (store: RoomStore) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

export interface SecretCreateInput {
  readonly secretId: string;
  readonly recipientUserId: string;
  readonly recipientKeyId: string;
  readonly suite: 'CM1';
  readonly wrappedSek: string;
  readonly payloadIv: string;
  readonly ciphertext: string;
  readonly expiresAt: string;
  readonly burnAfterReading: boolean;
}

/** Metadata as reported: an ACTIVE secret past its expiry is EXPIRED before the worker runs (INV-14). */
export interface SecretView extends SecretMetadata {
  readonly status: SecretStatus;
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
const rekeyRequired = (): HttpError =>
  new HttpError(409, ErrorCode.REKEY_REQUIRED, 'The room key must be rotated before new content can be added');
const unavailable = (): HttpError =>
  new HttpError(409, ErrorCode.SECRET_UNAVAILABLE, 'This secret can no longer be revealed');
const recipientInvalid = (): HttpError =>
  new HttpError(
    422,
    ErrorCode.SECRET_RECIPIENT_INVALID,
    'The recipient is not an active member of this room with that identity key',
  );

type SecretEvent = 'SECRET_CREATED' | 'SECRET_REVEALED' | 'SECRET_REVEAL_REFUSED' | 'SECRET_REVOKED';

/** The status a caller sees at `now`. */
export function viewOf(secret: SecretMetadata, now: Date): SecretView {
  const expired = secret.status === 'ACTIVE' && secret.expiresAt.getTime() <= now.getTime();
  return { ...secret, status: expired ? 'EXPIRED' : secret.status };
}

export function createSecretService(deps: SecretServiceDependencies) {
  const { store, transaction, events, clock } = deps;

  /**
   * Locks the room and the actor's membership (in that order) and decides again on that state:
   * the matrix, then the room's policy gates on the locked profile (PC-01, PC-02, and PC-03 for a
   * reveal; CM-T047). A refusal throws before the reveal's destroying UPDATE, so it burns nothing.
   */
  async function lockAndReauthorize(
    tx: RoomStore,
    actor: Actor,
    roomId: string,
    meta: RequestMeta,
    action: RoomActionId,
    resource?: () => Promise<RoomResourceFacts | null>,
  ): Promise<LockedRoom> {
    const request = { actorUserId: actor.userId, requestId: meta.requestId };
    const room = await tx.lockRoom(roomId);
    const member = room === null ? null : await tx.lockMembership(roomId, actor.userId);
    let facts: RoomResourceFacts | undefined;
    if (room !== null && member !== null && resource !== undefined) {
      const loaded = await resource();
      if (loaded === null) throw roomDenial(events, { ...request, action }, 'RESOURCE_NOT_FOUND');
      facts = loaded;
    }
    reauthorizeRoomAction(events, request, {
      actorUserId: actor.userId,
      roomId,
      membership: factsOf(room, member),
      action,
      ...(facts === undefined ? {} : { resource: facts }),
    });
    if (room === null || member === null) throw notFound();
    reapplyRoomPolicy(events, { ...request, action }, actor, room, clock(), action === 'AZ-24');
    return room;
  }

  /** PC-09 and D-09-03: a required expiry, at least the minimum and at most the profile's maximum. */
  function checkExpiry(room: LockedRoom, expiresAt: Date, now: Date): void {
    const { maxLifetimeMs } = policyOf(room).secrets;
    const lifetime = expiresAt.getTime() - now.getTime();
    if (!Number.isFinite(lifetime) || lifetime < SECRET_LIMITS.minLifetimeMs || lifetime > maxLifetimeMs) {
      throw new HttpError(422, ErrorCode.EXPIRY_NOT_ALLOWED, 'The expiry is outside what this room allows');
    }
  }

  /** Decodes the ciphertext; the schema bounded every length already. */
  function decode(input: SecretCreateInput) {
    try {
      const payloadCiphertext = fromBase64Url(input.ciphertext);
      if (
        payloadCiphertext.length < SECRET_LIMITS.minCiphertextBytes ||
        payloadCiphertext.length > SECRET_LIMITS.maxCiphertextBytes
      ) {
        throw new Error('ciphertext size');
      }
      return {
        wrappedSek: fromBase64Url(input.wrappedSek, SECRET_LIMITS.wrappedSekBytes),
        payloadIv: fromBase64Url(input.payloadIv, 12),
        payloadCiphertext,
      };
    } catch {
      throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed');
    }
  }

  function record(
    name: SecretEvent,
    actor: Actor,
    meta: RequestMeta,
    details: Readonly<Record<string, string | number | boolean>>,
    outcome: 'SUCCESS' | 'DENIED' = 'SUCCESS',
  ): void {
    events.record({ name, outcome, actorUserId: actor.userId, requestId: meta.requestId, details });
  }

  /** Why a locked secret cannot be released now, or undefined when it can. */
  function refusal(secret: LockedSecret, now: Date): string | undefined {
    if (secret.status !== 'ACTIVE') return `STATUS_${secret.status}`;
    if (secret.expiresAt.getTime() <= now.getTime()) return 'EXPIRED';
    if (!secret.recipientKeyActive) return 'RECIPIENT_KEY_CHANGED';
    return undefined;
  }

  return {
    /** AZ-32 (OL-14): metadata of the secrets the caller may see, newest first. */
    async listSecrets(
      actor: Actor,
      access: RoomAccess,
      after: ListPosition | undefined,
      take: number,
    ): Promise<SecretView[]> {
      const allOfRoom = access.role === 'OWNER' || access.role === 'ADMIN';
      const now = clock();
      const rows = await store.listRoomSecrets(access.roomId, actor.userId, allOfRoom, after, take);
      return rows.map((row) => viewOf(row, now));
    },

    /** AZ-23 (DF-09): stores one ACTIVE secret for one recipient. */
    async createSecret(
      actor: Actor,
      access: RoomAccess,
      input: SecretCreateInput,
      meta: RequestMeta,
    ): Promise<SecretView> {
      const now = clock();
      const expiresAt = new Date(input.expiresAt);
      const values = decode(input);
      const created = await transaction(async (tx) => {
        if (!(await tx.lockUploader(actor.userId))) throw notFound();
        const room = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-23');
        if (room.keyState !== 'ACTIVE') throw rekeyRequired();
        // OL-03: the recipient is an ACTIVE member (any role) other than the sender, and the SEK
        // is wrapped to exactly their ACTIVE identity key. Locked, so a concurrent removal or
        // vault reset either finished first (and is refused here) or revokes this secret after.
        if (input.recipientUserId === actor.userId) throw recipientInvalid();
        const recipient = await tx.lockMembership(room.id, input.recipientUserId);
        if (recipient === null || recipient.status !== 'ACTIVE') throw recipientInvalid();
        if (!(await tx.lockActiveIdentity(input.recipientUserId, input.recipientKeyId))) throw recipientInvalid();
        checkExpiry(room, expiresAt, now);
        if (policyOf(room).secrets.burnMandatory && !input.burnAfterReading) {
          throw new HttpError(422, ErrorCode.BURN_REQUIRED, 'Burn-after-reading is mandatory in this room');
        }
        if (await tx.secretIdUsed(input.secretId)) throw new SecretIdUnavailableError();
        if ((await tx.activeSentSecretCount(actor.userId, now)) >= SECRET_LIMITS.maxActiveSentPerAccount) {
          throw new HttpError(409, ErrorCode.SECRET_LIMIT_REACHED, 'You have sent the most active secrets allowed');
        }
        return tx.insertSecret({
          id: input.secretId,
          roomId: room.id,
          senderId: actor.userId,
          recipientUserId: input.recipientUserId,
          recipientKeyId: input.recipientKeyId,
          burnAfterReading: input.burnAfterReading,
          ...values,
          expiresAt,
          now,
        });
      }).catch((error: unknown) => {
        if (error instanceof SecretIdUnavailableError) {
          throw new HttpError(409, ErrorCode.SECRET_ID_UNAVAILABLE, 'This secret ID cannot be used');
        }
        throw error;
      });
      record('SECRET_CREATED', actor, meta, {
        roomId: access.roomId,
        secretId: created.id,
        burnAfterReading: created.burnAfterReading,
      });
      return viewOf(created, now);
    },

    /**
     * AZ-24 (DF-09, INV-13): releases the ciphertext to the recipient, once for a
     * burn-after-reading secret. See the module comment for the transaction.
     */
    async revealSecret(
      actor: Actor,
      access: RoomAccess,
      secretId: string,
      meta: RequestMeta,
    ): Promise<{ readonly view: SecretView; readonly released: ReleasedSecret }> {
      const now = clock();
      const outcome = await transaction(async (tx) => {
        if (!(await tx.lockUploader(actor.userId))) throw notFound();
        let target: LockedSecret | null = null;
        await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-24', async () => {
          // OL-06: locked by secret ID AND room ID AND recipient = caller. Anyone else finds nothing.
          target = await tx.lockSecretForRecipient(access.roomId, secretId, actor.userId);
          return target === null ? null : { roomId: target.roomId, recipientUserId: target.recipientUserId };
        });
        const locked = target as LockedSecret | null;
        if (locked === null) throw notFound();
        const reason = refusal(locked, now);
        if (reason !== undefined) return { kind: 'refused' as const, reason };
        const released = await tx.releaseSecret(access.roomId, secretId, actor.userId, now);
        if (released === null) return { kind: 'refused' as const, reason: 'NOT_REDEEMABLE' };
        return { kind: 'released' as const, released };
      });
      if (outcome.kind === 'refused') {
        record(
          'SECRET_REVEAL_REFUSED',
          actor,
          meta,
          { roomId: access.roomId, secretId, reason: outcome.reason },
          'DENIED',
        );
        throw unavailable();
      }
      const { metadata } = outcome.released;
      record('SECRET_REVEALED', actor, meta, {
        roomId: access.roomId,
        secretId,
        burned: metadata.burnAfterReading,
      });
      return { view: viewOf(metadata, now), released: outcome.released };
    },

    /** AZ-25: revokes an ACTIVE secret (material removed); own secrets for MEMBERs. */
    async revokeSecret(actor: Actor, access: RoomAccess, secretId: string, meta: RequestMeta): Promise<void> {
      const now = clock();
      await transaction(async (tx) => {
        let target: SecretMetadata | null = null;
        const room = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-25', async () => {
          target = await tx.lockRoomSecret(access.roomId, secretId);
          return target === null ? null : { roomId: target.roomId, createdById: target.senderId };
        });
        const locked = target as SecretMetadata | null;
        if (locked === null) throw notFound();
        // An ACTIVE secret past its expiry is already gone for its recipient (INV-14).
        if (viewOf(locked, now).status !== 'ACTIVE' || !(await tx.revokeSecret(room.id, secretId, now))) {
          throw unavailable();
        }
      });
      record('SECRET_REVOKED', actor, meta, { roomId: access.roomId, secretId, reason: 'REVOKED_BY_MEMBER' });
    },
  };
}

export type SecretService = ReturnType<typeof createSecretService>;
