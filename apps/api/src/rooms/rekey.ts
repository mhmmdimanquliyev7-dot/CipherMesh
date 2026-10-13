import {
  canonicalBytes,
  keyVersionStatement,
  verifyStatementBy,
  type VerifiedIdentity,
} from '@ciphermesh/crypto/identity';
import { decideRoomAction, ErrorCode, REKEY_RULES, type RoomActionId, type RoomRole } from '@ciphermesh/shared';
import { createHash } from 'node:crypto';
import type { SecurityEventSink } from '../auth/security-events';
import type { Actor, RequestMeta } from '../auth/sessions';
import { policyOf, reapplyRoomPolicy } from '../authorization/policy';
import { reauthorizeRoomAction, roomDenial, type RoomAccess } from '../authorization/rooms';
import {
  recipientKey,
  recipientSetDigest,
  SnapshotInvalidError,
  type RekeyOperationRecord,
  type SnapshotRecipient,
} from '../db/rekey-store';
import type { GrantRecord, IdentityRecord, IdentityRef } from '../db/room-key-store';
import type { LockedMembership, LockedRoom, RoomStore, StaledOperation } from '../db/room-store';
import { HttpError } from '../http/errors';
import { factsOf, identityKeyChanged, statementInvalid, vaultSetupRequired } from './service';
import { decodeExact, toBytes, verifiedIdentity, verifyGrant } from './statements';

/**
 * The rekey state machine and identity re-sharing (Phase 11, CM-T050 to CM-T053; ADR-013,
 * ADR-015 section 4, key-lifecycle sections 1 and 3, DF-10).
 *
 * The browser makes every key: the API records an operation and its recipient snapshot, and later
 * stores the new version, its signed statement and the envelopes the starter's browser made, only
 * after checking in one transaction, on the locked room and operation:
 *   - the caller's current role (AZ-13 on the locked membership) and the room's policy gates
 *     (PC-01, PC-02, and PC-03 for a start in RESTRICTED rooms);
 *   - OL-13: the operation is loaded by its ID and the room's ID; only the starter finalizes; the
 *     starter or the OWNER cancels;
 *   - the operation is PENDING, its lease is valid, and the room's current version and membership
 *     epoch are still the snapshot's, and the room's key state matches the operation's mode;
 *   - the recipient set recomputed from the database still has the snapshot's digest (an invitation
 *     revoked or created meanwhile is caught here, not only a membership change);
 *   - the envelope set equals that set exactly (no missing, extra or duplicate recipient, 422);
 *   - the cm.room.key-version statement verifies under the starter's ACTIVE identity, naming the
 *     snapshot's recipients, the next version and the stored previous commitment, and the new
 *     commitment is not one the room used before.
 * The server never derives, checks or sees room key material (INV-01, INV-04); a compromised
 * server could skip these checks, which is why every member's browser verifies the version itself
 * (ADR-015 section 4, T-36). Events go to the security-event sink after commit (L-33).
 */

export interface RekeyServiceDependencies {
  readonly store: RoomStore;
  readonly transaction: <T>(fn: (store: RoomStore) => Promise<T>) => Promise<T>;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

export interface FinalizeInput {
  readonly targetVersion: number;
  readonly commitment: string;
  readonly statementSignature: string;
  readonly envelopes: readonly {
    readonly recipientUserId: string;
    readonly recipientKeyId: string;
    readonly wrappedKey: string;
  }[];
}

export interface ReshareInput {
  readonly subjectKeyId: string;
  readonly confirmedFingerprint: string | null;
  readonly grantSignature: string;
  readonly envelopes: readonly { readonly keyVersion: number; readonly wrappedKey: string }[];
}

export interface StartedRekey {
  readonly operation: RekeyOperationRecord;
  readonly recipients: readonly SnapshotRecipient[];
  readonly grants: readonly GrantRecord[];
  readonly identities: readonly IdentityRecord[];
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
const rekeyRequired = (): HttpError =>
  new HttpError(409, ErrorCode.REKEY_REQUIRED, 'The room key must be rotated before membership can change this way');
const operationClosed = (): HttpError =>
  new HttpError(409, ErrorCode.REKEY_OPERATION_CLOSED, 'This rekey operation is closed; start a new one');
const recipientsMismatch = (): HttpError =>
  new HttpError(
    422,
    ErrorCode.REKEY_RECIPIENTS_MISMATCH,
    'The envelopes do not match the recipients this rekey operation requires',
  );
const envelopeSetInvalid = (): HttpError =>
  new HttpError(422, ErrorCode.ENVELOPE_SET_INVALID, 'The key envelopes do not match what this room requires');
const notStarter = (message: string): HttpError => new HttpError(403, ErrorCode.REKEY_NOT_STARTER, message);

/** SHA-256 over the RFC 8785 form of a finalize payload, envelopes in recipient order (idempotency). */
export function finalizePayloadDigest(input: FinalizeInput): Uint8Array {
  const envelopes = [...input.envelopes]
    .map((e) => ({ recipientUserId: e.recipientUserId, recipientKeyId: e.recipientKeyId, wrappedKey: e.wrappedKey }))
    .sort((a, b) =>
      a.recipientUserId !== b.recipientUserId
        ? a.recipientUserId < b.recipientUserId
          ? -1
          : 1
        : a.recipientKeyId < b.recipientKeyId
          ? -1
          : a.recipientKeyId > b.recipientKeyId
            ? 1
            : 0,
    );
  const canonical = canonicalBytes({
    v: 1,
    targetVersion: input.targetVersion,
    commitment: input.commitment,
    statementSignature: input.statementSignature,
    envelopes,
  });
  return new Uint8Array(createHash('sha256').update(canonical).digest());
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, i) => value === b[i]);

type Closing = 'ABANDONED' | 'SUPERSEDED' | 'CANCELLED' | 'STALE';
const CLOSING_EVENT = {
  ABANDONED: 'REKEY_ABANDONED',
  SUPERSEDED: 'REKEY_SUPERSEDED',
  CANCELLED: 'REKEY_CANCELLED',
  STALE: 'REKEY_STALE',
} as const;

interface ClosedRecord {
  readonly operation: RekeyOperationRecord;
  readonly status: Closing;
  readonly reason: string;
}

export function createRekeyService(deps: RekeyServiceDependencies) {
  const { store, transaction, events, clock } = deps;

  /** Locks the room and the actor's membership, then decides again on that state (CM-T047). */
  async function lockAndReauthorize(
    tx: RoomStore,
    actor: Actor,
    roomId: string,
    meta: RequestMeta,
    action: RoomActionId,
    now: Date,
    sensitive: boolean,
  ): Promise<{ readonly room: LockedRoom; readonly member: LockedMembership }> {
    const request = { actorUserId: actor.userId, requestId: meta.requestId };
    const room = await tx.lockRoom(roomId);
    const member = room === null ? null : await tx.lockMembership(roomId, actor.userId);
    reauthorizeRoomAction(events, request, {
      actorUserId: actor.userId,
      roomId,
      membership: factsOf(room, member),
      action,
    });
    if (room === null || member === null) throw notFound();
    reapplyRoomPolicy(events, { ...request, action }, actor, room, now, sensitive);
    return { room, member };
  }

  /**
   * Closes a PENDING operation; a MANDATORY one returns the room to REKEY_REQUIRED (ADR-013 steps 4
   * to 6). The room stays write-locked: closing never unlocks a room.
   */
  async function close(
    tx: RoomStore,
    room: LockedRoom,
    operation: RekeyOperationRecord,
    status: Closing,
    reason: string,
    now: Date,
  ): Promise<ClosedRecord> {
    if (!(await tx.closeOperation(operation, status, reason, now))) throw operationClosed();
    if (operation.mode === 'MANDATORY' && room.keyState === 'REKEYING') {
      if (!(await tx.setKeyState(room.id, 'REKEYING', 'REKEY_REQUIRED', now))) throw operationClosed();
    }
    return { operation, status, reason };
  }

  function recordClosed(actor: Actor, meta: RequestMeta, closed: readonly ClosedRecord[]): void {
    for (const c of closed) {
      events.record({
        name: CLOSING_EVENT[c.status],
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId: c.operation.roomId, operationId: c.operation.id, mode: c.operation.mode, reason: c.reason },
      });
    }
  }

  function recordStaled(actor: Actor, meta: RequestMeta, staled: readonly StaledOperation[]): void {
    for (const s of staled) {
      events.record({
        name: 'REKEY_STALE',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId: s.roomId, operationId: s.operationId, mode: s.mode, reason: 'MEMBERSHIP_CHANGED' },
      });
    }
  }

  function recordRejected(actor: Actor, meta: RequestMeta, roomId: string, operationId: string, code: string): void {
    events.record({
      name: 'REKEY_REJECTED',
      outcome: 'DENIED',
      actorUserId: actor.userId,
      requestId: meta.requestId,
      details: { roomId, operationId, reason: code },
    });
  }

  /**
   * The caller's ACTIVE identity, verified as every client verifies it, or VAULT_SETUP_REQUIRED.
   * Looked up only after the target object was found in the room, so the answer for an object of
   * another room never depends on the caller's own vault (OL-02, BOLA class C).
   */
  async function activeSigner(
    db: RoomStore,
    userId: string,
  ): Promise<{ record: IdentityRecord; verified: VerifiedIdentity }> {
    const record = await db.findActiveIdentity(userId);
    const verified = record === null ? undefined : await verifiedIdentity(record);
    if (record === null || verified === undefined) throw vaultSetupRequired();
    return { record, verified };
  }

  return {
    /**
     * AZ-13, ADR-013 step 1 (CM-T050). OWNER or ADMIN; PC-03 in RESTRICTED rooms (route gate and
     * locked row). One live operation per room: an expired one is ABANDONED, the caller's own is
     * SUPERSEDED, anyone else's refuses with 409 REKEY_IN_PROGRESS. From REKEY_REQUIRED the
     * operation is MANDATORY and the room becomes REKEYING; from ACTIVE it is a MANUAL rotation
     * (R8) and the room stays writable until activation.
     */
    async startRekey(actor: Actor, access: RoomAccess, meta: RequestMeta): Promise<StartedRekey> {
      const now = clock();
      const outcome = await transaction(async (tx) => {
        const { room } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-13', now, true);
        const base = await tx.keyVersionFacts(room.id, room.currentKeyVersion);
        if (base === null) {
          throw new HttpError(409, ErrorCode.ROOM_KEY_UNAVAILABLE, 'This room has no key version to rotate');
        }
        const closed: ClosedRecord[] = [];
        let keyState = room.keyState;
        const pending = await tx.lockPendingOperation(room.id);
        if (pending !== null) {
          if (pending.leaseExpiresAt <= now) {
            closed.push(await close(tx, room, pending, 'ABANDONED', 'LEASE_EXPIRED', now));
          } else if (pending.startedById === actor.userId) {
            closed.push(await close(tx, room, pending, 'SUPERSEDED', 'RESTARTED_BY_STARTER', now));
          } else {
            throw new HttpError(
              409,
              ErrorCode.REKEY_IN_PROGRESS,
              `Another rekey of this room is in progress until ${pending.leaseExpiresAt.toISOString()}`,
            );
          }
          if (pending.mode === 'MANDATORY') keyState = 'REKEY_REQUIRED';
        }
        if (keyState === 'REKEYING') throw operationClosed();
        // CP-25: at most 10 starts per room per hour, so a script cannot churn the lock.
        const since = new Date(now.getTime() - 60 * 60_000);
        if ((await tx.countOperationStarts(room.id, since)) >= REKEY_RULES.maxStartsPerHour) {
          throw new HttpError(429, ErrorCode.RATE_LIMITED, 'Too many rekey operations for this room; try again later');
        }
        let recipients: SnapshotRecipient[];
        try {
          recipients = await tx.recipientSnapshot(room.id);
        } catch (error) {
          if (error instanceof SnapshotInvalidError) throw recipientsMismatch();
          throw error;
        }
        if (recipients.length > REKEY_RULES.maxRecipients) throw recipientsMismatch();
        // The starter makes the key: without an ACTIVE identity in the snapshot there is no creator.
        if (!recipients.some((r) => r.userId === actor.userId && r.kind === 'MEMBER')) throw vaultSetupRequired();
        const mode = keyState === 'ACTIVE' ? 'MANUAL' : 'MANDATORY';
        const operation = await tx.insertOperation({
          roomId: room.id,
          startedById: actor.userId,
          mode,
          baseVersion: room.currentKeyVersion,
          membershipEpoch: room.membershipEpoch,
          recipientSetDigest: recipientSetDigest(recipients),
          leaseExpiresAt: new Date(now.getTime() + REKEY_RULES.leaseMs),
          now,
        });
        if (mode === 'MANDATORY' && !(await tx.setKeyState(room.id, 'REKEY_REQUIRED', 'REKEYING', now))) {
          throw operationClosed();
        }
        // For the reviewer's browser: the grants that name the recipients, and their authority chain.
        const grants = await tx.recipientGrants(room.id, recipients);
        const grantors: IdentityRef[] = grants.map((g) => ({ userId: g.grantorUserId, keyId: g.grantorKeyId }));
        const chain = await tx.grantChain(room.id, actor.userId, grantors);
        const signers: IdentityRef[] = [
          ...grantors,
          ...chain.map((g) => ({ userId: g.grantorUserId, keyId: g.grantorKeyId })),
        ];
        return {
          operation,
          recipients,
          grants: [...grants, ...chain],
          identities: await tx.identities(signers),
          closed,
        };
      });
      recordClosed(actor, meta, outcome.closed);
      events.record({
        name: 'REKEY_STARTED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: {
          roomId: access.roomId,
          operationId: outcome.operation.id,
          mode: outcome.operation.mode,
          baseVersion: outcome.operation.baseVersion,
          recipients: outcome.recipients.length,
        },
      });
      return outcome;
    },

    /**
     * AZ-13, ADR-013 steps 3 and 4 (CM-T050). Every check of the module comment runs in one
     * transaction on the locked room and operation, and the new version, the retirement of the old
     * one, the envelopes, the unlock and the operation's completion commit together or not at all.
     * A repeated finalize of a COMPLETED operation with the same payload digest returns the
     * original result; another payload is 409 REKEY_PAYLOAD_MISMATCH.
     */
    async finalizeRekey(
      actor: Actor,
      access: RoomAccess,
      operationId: string,
      input: FinalizeInput,
      meta: RequestMeta,
    ): Promise<{ operationId: string; keyVersion: number; completedAt: Date }> {
      const now = clock();
      const roomId = access.roomId;
      const commitment = decodeExact(input.commitment, 32);
      const signature = decodeExact(input.statementSignature, 64);
      const envelopes = new Map<string, Uint8Array>();
      let malformed: HttpError | undefined =
        commitment === undefined || signature === undefined ? statementInvalid() : undefined;
      for (const e of input.envelopes) {
        const wrapped = decodeExact(e.wrappedKey, 384);
        const key = recipientKey(e.recipientUserId, e.recipientKeyId);
        if (wrapped === undefined) malformed ??= envelopeSetInvalid();
        else if (envelopes.has(key)) malformed ??= recipientsMismatch();
        else envelopes.set(key, wrapped);
      }
      // A malformed payload is refused before any lock, but recorded like every other refusal.
      if (malformed !== undefined || commitment === undefined || signature === undefined) {
        recordRejected(actor, meta, roomId, operationId, malformed?.code ?? ErrorCode.ROOM_STATEMENT_INVALID);
        throw malformed ?? statementInvalid();
      }
      const payloadDigest = finalizePayloadDigest(input);

      type Outcome =
        | {
            readonly kind: 'completed';
            readonly keyVersion: number;
            readonly baseVersion: number;
            readonly mode: string;
            readonly recipients: number;
          }
        | { readonly kind: 'replayed'; readonly keyVersion: number; readonly completedAt: Date }
        | { readonly kind: 'closed'; readonly closed: ClosedRecord };
      let outcome: Outcome;
      try {
        outcome = await transaction(async (tx): Promise<Outcome> => {
          const { room } = await lockAndReauthorize(tx, actor, roomId, meta, 'AZ-13', now, false);
          const operation = await tx.lockOperation(room.id, operationId);
          if (operation === null) {
            throw roomDenial(
              events,
              { actorUserId: actor.userId, requestId: meta.requestId, action: 'AZ-13' },
              'RESOURCE_NOT_FOUND',
            );
          }
          if (operation.startedById !== actor.userId) {
            throw notStarter('Only the member who started this rekey operation can finalize it');
          }
          if (operation.status === 'COMPLETED') {
            if (operation.payloadDigest !== null && sameBytes(operation.payloadDigest, payloadDigest)) {
              return {
                kind: 'replayed',
                keyVersion: operation.targetVersion,
                completedAt: operation.completedAt ?? now,
              };
            }
            throw new HttpError(
              409,
              ErrorCode.REKEY_PAYLOAD_MISMATCH,
              'This rekey operation was completed with a different payload',
            );
          }
          if (operation.status !== 'PENDING') throw operationClosed();
          if (operation.leaseExpiresAt <= now) {
            return { kind: 'closed', closed: await close(tx, room, operation, 'ABANDONED', 'LEASE_EXPIRED', now) };
          }
          const signer = await activeSigner(tx, actor.userId);
          const expectedState = operation.mode === 'MANDATORY' ? 'REKEYING' : 'ACTIVE';
          if (
            room.currentKeyVersion !== operation.baseVersion ||
            room.membershipEpoch !== operation.membershipEpoch ||
            room.keyState !== expectedState
          ) {
            return { kind: 'closed', closed: await close(tx, room, operation, 'STALE', 'ROOM_CHANGED', now) };
          }
          if (input.targetVersion !== operation.targetVersion) {
            throw new HttpError(409, ErrorCode.KEY_VERSION_STALE, 'The new key version must be the next version');
          }
          // The recipient set from the database now must still be the snapshot (OL-13).
          let recipients: SnapshotRecipient[];
          try {
            recipients = await tx.recipientSnapshot(room.id);
          } catch (error) {
            if (!(error instanceof SnapshotInvalidError)) throw error;
            return { kind: 'closed', closed: await close(tx, room, operation, 'STALE', 'RECIPIENTS_CHANGED', now) };
          }
          if (!sameBytes(recipientSetDigest(recipients), operation.recipientSetDigest)) {
            return { kind: 'closed', closed: await close(tx, room, operation, 'STALE', 'RECIPIENTS_CHANGED', now) };
          }
          // Exactly one envelope per snapshot recipient: nobody missing, nobody added (T-21).
          if (
            envelopes.size !== recipients.length ||
            recipients.some((r) => !envelopes.has(recipientKey(r.userId, r.keyId)))
          ) {
            throw recipientsMismatch();
          }
          // The signer is the starter's identity that is ACTIVE now; a reset since start is refused.
          if (!(await tx.lockActiveIdentity(actor.userId, signer.record.keyId))) throw identityKeyChanged();
          const previous = await tx.keyVersionFacts(room.id, operation.baseVersion);
          if (previous === null) throw operationClosed();
          if (await tx.commitmentUsed(room.id, commitment)) throw statementInvalid();
          const statementOk = await (async () => {
            try {
              return await verifyStatementBy(
                signer.verified,
                { userId: signer.verified.userId, keyId: signer.verified.keyId },
                keyVersionStatement({
                  roomId: room.id,
                  keyVersion: operation.targetVersion,
                  commitment: toBytes(commitment),
                  previousCommitment: toBytes(previous.commitment),
                  creatorUserId: signer.verified.userId,
                  creatorKeyId: signer.verified.keyId,
                  recipients: recipients.map((r) => ({ userId: r.userId, keyId: r.keyId })),
                }),
                toBytes(signature),
              );
            } catch {
              return false;
            }
          })();
          if (!statementOk) {
            events.record({
              name: 'ROOM_STATEMENT_REJECTED',
              outcome: 'DENIED',
              actorUserId: actor.userId,
              requestId: meta.requestId,
              details: { roomId: room.id, statement: 'KEY_VERSION' },
            });
            throw statementInvalid();
          }
          const reasons =
            operation.mode === 'MANUAL' || room.rekeyReasons.length === 0 ? (['MANUAL'] as const) : room.rekeyReasons;
          await tx.activateKeyVersion({
            roomId: room.id,
            operation,
            commitment,
            previousCommitment: previous.commitment,
            reasons,
            creatorUserId: actor.userId,
            creatorKeyId: signer.record.keyId,
            recipients,
            statementSignature: signature,
            envelopes,
            payloadDigest,
            now,
          });
          return {
            kind: 'completed',
            keyVersion: operation.targetVersion,
            baseVersion: operation.baseVersion,
            mode: operation.mode,
            recipients: recipients.length,
          };
        });
      } catch (error) {
        if (
          error instanceof HttpError &&
          (error.code === ErrorCode.REKEY_RECIPIENTS_MISMATCH ||
            error.code === ErrorCode.ROOM_STATEMENT_INVALID ||
            error.code === ErrorCode.KEY_VERSION_STALE ||
            error.code === ErrorCode.ENVELOPE_SET_INVALID ||
            error.code === ErrorCode.IDENTITY_KEY_CHANGED)
        ) {
          recordRejected(actor, meta, roomId, operationId, error.code);
        }
        throw error;
      }
      if (outcome.kind === 'closed') {
        recordClosed(actor, meta, [outcome.closed]);
        throw operationClosed();
      }
      if (outcome.kind === 'replayed') {
        return { operationId, keyVersion: outcome.keyVersion, completedAt: outcome.completedAt };
      }
      events.record({
        name: 'REKEY_COMPLETED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: {
          roomId,
          operationId,
          mode: outcome.mode,
          keyVersion: outcome.keyVersion,
          recipients: outcome.recipients,
        },
      });
      events.record({
        name: 'KEY_VERSION_RETIRED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId, keyVersion: outcome.baseVersion },
      });
      return { operationId, keyVersion: outcome.keyVersion, completedAt: now };
    },

    /**
     * AZ-13, OL-13 (CM-T050). The starter or the OWNER cancels a PENDING operation. Cancelling
     * never unlocks a room: a MANDATORY operation returns it to REKEY_REQUIRED, a MANUAL one leaves
     * it ACTIVE on the old version (ADR-013 step 6).
     */
    async cancelRekey(
      actor: Actor,
      access: RoomAccess,
      operationId: string,
      meta: RequestMeta,
    ): Promise<{ keyState: 'ACTIVE' | 'REKEY_REQUIRED' | 'REKEYING' }> {
      const now = clock();
      const outcome = await transaction(async (tx) => {
        const { room, member } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-13', now, false);
        const operation = await tx.lockOperation(room.id, operationId);
        if (operation === null) {
          throw roomDenial(
            events,
            { actorUserId: actor.userId, requestId: meta.requestId, action: 'AZ-13' },
            'RESOURCE_NOT_FOUND',
          );
        }
        if (operation.startedById !== actor.userId && member.role !== 'OWNER') {
          throw notStarter('Only the member who started this rekey operation or the room owner can cancel it');
        }
        if (operation.status !== 'PENDING') throw operationClosed();
        const reason = operation.startedById === actor.userId ? 'CANCELLED_BY_STARTER' : 'CANCELLED_BY_OWNER';
        const closed = await close(tx, room, operation, 'CANCELLED', reason, now);
        const keyState =
          operation.mode === 'MANDATORY' && room.keyState === 'REKEYING' ? ('REKEY_REQUIRED' as const) : room.keyState;
        return { closed, keyState };
      });
      recordClosed(actor, meta, [outcome.closed]);
      return { keyState: outcome.keyState };
    },

    /**
     * AZ-15: the room's key state, its accumulated reasons, the PENDING operation (its lease may
     * have passed; a GET changes nothing, the next start closes it), the PC-14 cryptoperiod and its
     * reminder (R6), and the members whose current identity holds no current envelope (AZ-14).
     */
    async keyState(actor: Actor, access: RoomAccess) {
      const now = clock();
      const view = await store.roomRekeyView(access.roomId, actor.userId);
      if (view === null) throw notFound();
      const current = await store.keyVersionFacts(access.roomId, view.currentKeyVersion);
      const period = access.policy.cryptoperiodMs;
      const endsAt = current === null || period === null ? null : new Date(current.createdAt.getTime() + period);
      return {
        keyState: view.keyState,
        rekeyReasons: view.rekeyReasons,
        rekeyRequiredSince: view.rekeyRequiredSince,
        currentKeyVersion: view.currentKeyVersion,
        cryptoperiodEndsAt: endsAt,
        cryptoperiodReminder: endsAt !== null && endsAt.getTime() - now.getTime() <= REKEY_RULES.cryptoperiodReminderMs,
        operation: await store.findPendingOperation(access.roomId),
        membersNeedingKeys:
          current === null ? [] : await store.membersNeedingKeys(access.roomId, view.currentKeyVersion),
      };
    },

    /**
     * AZ-11 (CM-T051, key-lifecycle R2). An ADMIN, MEMBER or VIEWER leaves; the OWNER transfers
     * ownership first (matrix). The member-loss transaction of INV-07: status LEFT, every envelope of
     * the member deleted, the secrets addressed to them revoked (D-09-06), the epoch advanced (a
     * PENDING operation becomes STALE) and the room REKEY_REQUIRED with MEMBER_LEFT.
     */
    async leaveRoom(actor: Actor, access: RoomAccess, meta: RequestMeta): Promise<void> {
      const now = clock();
      const outcome = await transaction(async (tx) => {
        const { room, member } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-11', now, false);
        if (!(await tx.markMemberLeft(member.membershipId, room.id, actor.userId, now))) throw notFound();
        await tx.revokeSecretsToMember([room.id], actor.userId, now);
        await tx.requireRekey(room.id, 'MEMBER_LEFT', now);
        return { wasActive: room.keyState === 'ACTIVE', staled: tx.takeStaledOperations() };
      });
      events.record({
        name: 'MEMBER_LEFT',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId: access.roomId },
      });
      if (outcome.wasActive) {
        events.record({
          name: 'REKEY_REQUIRED',
          outcome: 'SUCCESS',
          actorUserId: actor.userId,
          requestId: meta.requestId,
          details: { roomId: access.roomId, reason: 'MEMBER_LEFT' },
        });
      }
      recordStaled(actor, meta, outcome.staled);
    },

    /**
     * AZ-14 (CM-T053, key-lifecycle section 3): re-share the room's keys to a member's current
     * identity after a vault reset, or reinstate a SUSPENDED member of a re-enabled account. The
     * same checks as an invitation: the AZ-06 role ceilings for the member's stored role (an ADMIN
     * re-shares to MEMBERs and VIEWERs, the OWNER also to ADMINs; nobody to the OWNER, whose
     * authority is the genesis or an OWNER grant only an OWNER can sign), PC-03 in RESTRICTED
     * rooms, PC-05 fingerprint confirmation, PC-07 history, PC-16 (refused while REKEY_REQUIRED or
     * REKEYING), and a grant signed by the caller's ACTIVE identity for exactly that key and role.
     * The epoch advances: the recipient set changed.
     */
    async reshareKeys(
      actor: Actor,
      access: RoomAccess,
      targetUserId: string,
      input: ReshareInput,
      meta: RequestMeta,
    ): Promise<{ userId: string; keyVersions: number[]; reinstated: boolean }> {
      const now = clock();
      const roomId = access.roomId;
      const signature = decodeExact(input.grantSignature, 64);
      const envelopes = input.envelopes.map((e) => ({
        keyVersion: e.keyVersion,
        wrappedKey: decodeExact(e.wrappedKey, 384),
      }));
      const decoded = envelopes.flatMap((e) =>
        e.wrappedKey === undefined ? [] : [{ ...e, wrappedKey: e.wrappedKey }],
      );
      if (signature === undefined) throw statementInvalid();
      if (decoded.length !== envelopes.length) throw envelopeSetInvalid();
      if (targetUserId === actor.userId) {
        throw roomDenial(
          events,
          { actorUserId: actor.userId, requestId: meta.requestId, action: 'AZ-14' },
          'TARGET_ROLE_NOT_PERMITTED',
        );
      }
      // The member's identity as the directory shows it: an ACTIVE account with an ACTIVE identity.
      const subject = await store.findActiveIdentity(targetUserId);
      const outcome = await transaction(async (tx) => {
        const request = { actorUserId: actor.userId, requestId: meta.requestId, action: 'AZ-14' as const };
        const { room, member } = await lockAndReauthorize(tx, actor, roomId, meta, 'AZ-14', now, true);
        const target = await tx.lockMembership(room.id, targetUserId);
        if (target === null || subject === null) throw roomDenial(events, request, 'RESOURCE_NOT_FOUND');
        // "Same checks as invitations": the caller may grant the member's stored role (AZ-06 cells).
        const ceiling = decideRoomAction({
          actorUserId: actor.userId,
          roomId: room.id,
          membership: factsOf(room, member),
          action: 'AZ-06',
          resource: { roomId: target.roomId, roles: [target.role] },
        });
        if (!ceiling.allowed) throw roomDenial(events, request, ceiling.reason);
        const grantor = await activeSigner(tx, actor.userId);
        if (room.keyState !== 'ACTIVE') throw rekeyRequired();
        if (subject.keyId !== input.subjectKeyId) throw identityKeyChanged();
        if (!(await tx.lockActiveIdentity(targetUserId, subject.keyId))) throw identityKeyChanged();
        if (!(await tx.lockActiveIdentity(actor.userId, grantor.record.keyId))) throw identityKeyChanged();
        const reinstate = target.status === 'SUSPENDED';
        if (!reinstate && (await tx.holdsEnvelope(room.id, targetUserId, subject.keyId, room.currentKeyVersion))) {
          throw new HttpError(
            409,
            ErrorCode.RESHARE_NOT_NEEDED,
            'This member already holds the current room key for their current identity',
          );
        }
        const rules = policyOf(room).invitations;
        if (rules.fingerprintConfirmation === 'required' && input.confirmedFingerprint === null) {
          throw new HttpError(
            422,
            ErrorCode.FINGERPRINT_REQUIRED,
            "This room requires confirming the member's fingerprint",
          );
        }
        if (input.confirmedFingerprint !== null && input.confirmedFingerprint !== subject.publicKeyFingerprint) {
          throw new HttpError(
            409,
            ErrorCode.FINGERPRINT_MISMATCH,
            "The confirmed fingerprint is not the member's current one",
          );
        }
        const role: RoomRole = target.role;
        const grantOk = await verifyGrant(grantor.verified, {
          roomId: room.id,
          subjectUserId: targetUserId,
          subjectKeyId: subject.keyId,
          role,
          signature,
        });
        if (!grantOk) {
          events.record({
            name: 'ROOM_STATEMENT_REJECTED',
            outcome: 'DENIED',
            actorUserId: actor.userId,
            requestId: meta.requestId,
            details: { roomId: room.id, statement: 'MEMBERSHIP_GRANT' },
          });
          throw statementInvalid();
        }
        // PC-07: the current version always; older retained versions only where history is shared.
        const shareable = new Set(await tx.shareableKeyVersions(room.id));
        const requested = decoded.map((e) => e.keyVersion);
        const valid =
          new Set(requested).size === requested.length &&
          requested.includes(room.currentKeyVersion) &&
          requested.every((v) => shareable.has(v) && v <= room.currentKeyVersion) &&
          (rules.keyHistory === 'all-retained' || requested.length === 1);
        if (!valid) throw envelopeSetInvalid();
        const stored = await tx.reshareKeys({
          membershipId: target.membershipId,
          roomId: room.id,
          userId: targetUserId,
          role,
          reinstate,
          grant: {
            subjectKeyId: subject.keyId,
            grantorUserId: actor.userId,
            grantorKeyId: grantor.record.keyId,
            signature,
          },
          envelopes: decoded,
          now,
        });
        if (!stored) throw notFound();
        await tx.incrementMembershipEpoch(room.id, now);
        return { reinstate, keyVersions: requested.sort((a, b) => a - b), staled: tx.takeStaledOperations() };
      });
      events.record({
        name: 'KEYS_RESHARED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        targetUserId,
        requestId: meta.requestId,
        details: { roomId, keyVersions: outcome.keyVersions.length, reinstated: outcome.reinstate },
      });
      if (outcome.reinstate) {
        events.record({
          name: 'MEMBER_REINSTATED',
          outcome: 'SUCCESS',
          actorUserId: actor.userId,
          targetUserId,
          requestId: meta.requestId,
          details: { roomId },
        });
      }
      recordStaled(actor, meta, outcome.staled);
      return { userId: targetUserId, keyVersions: outcome.keyVersions, reinstated: outcome.reinstate };
    },
  };
}

export type RekeyService = ReturnType<typeof createRekeyService>;
