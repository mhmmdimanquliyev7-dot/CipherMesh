import { auditLevelIncludes, ErrorCode } from '@ciphermesh/shared';
import type { SecurityEventSink } from '../auth/security-events';
import type { Actor, RequestMeta } from '../auth/sessions';
import type { RoomAccess } from '../authorization/rooms';
import type {
  EnvelopeRecord,
  GrantRecord,
  IdentityRecord,
  IdentityRef,
  KeyVersionRecord,
  RoomKeyStateRecord,
} from '../db/room-key-store';
import type { RoomStore } from '../db/room-store';
import { HttpError } from '../http/errors';

/**
 * Room key material for members (Phase 6, CM-T036, CM-T085). The API serves what a member's
 * browser needs to verify a room key version itself (ADR-015 section 4): the signed genesis and
 * key-version statements, the grants of the authority chain, the signers' public identities, and
 * the caller's own envelopes. It serves them as stored and claims nothing about them: the browser
 * refuses any key that does not verify (KEY_AUTHENTICATION_FAILED, KEY_COMMITMENT_MISMATCH) and
 * reports it here (AZ-29). Room Safety Codes are computed only in browsers; the API records only
 * that a member compared, or reports a mismatch, with the key version (AZ-30, INV-18).
 */

export interface RoomKeyServiceDependencies {
  readonly store: RoomStore;
  readonly events: SecurityEventSink;
}

export interface RoomKeyMaterial {
  readonly state: RoomKeyStateRecord;
  readonly keyVersions: readonly KeyVersionRecord[];
  readonly grants: readonly GrantRecord[];
  readonly identities: readonly IdentityRecord[];
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');

export function createRoomKeyService(deps: RoomKeyServiceDependencies) {
  const { store, events } = deps;

  return {
    /** AZ-15: statements, grants and signer identities of every key version of the room. */
    async keyMaterial(actor: Actor, access: RoomAccess): Promise<RoomKeyMaterial> {
      const state = await store.findRoomKeyState(access.roomId, actor.userId);
      if (state === null) throw notFound();
      const keyVersions = await store.listKeyVersions(access.roomId, actor.userId);
      const creators: IdentityRef[] = keyVersions.map((v) => ({ userId: v.creatorUserId, keyId: v.creatorKeyId }));
      const grants = await store.grantChain(access.roomId, actor.userId, creators);
      const signers: IdentityRef[] = [
        ...(state.genesis === null ? [] : [{ userId: state.genesis.creatorUserId, keyId: state.genesis.creatorKeyId }]),
        ...creators,
        ...grants.map((g) => ({ userId: g.grantorUserId, keyId: g.grantorKeyId })),
      ];
      return { state, keyVersions, grants, identities: await store.identities(signers) };
    },

    /** AZ-12, OL-05: the caller's own ACTIVE envelopes; PENDING envelopes are never served. */
    async ownEnvelopes(actor: Actor, access: RoomAccess, meta: RequestMeta): Promise<EnvelopeRecord[]> {
      const envelopes = await store.listOwnEnvelopes(access.roomId, actor.userId);
      // PC-13: envelope fetches are recorded at the FULL audit level (versions and count only).
      if (auditLevelIncludes(access.policy.auditLevel, 'FULL')) {
        events.record({
          name: 'ENVELOPES_FETCHED',
          outcome: 'SUCCESS',
          actorUserId: actor.userId,
          requestId: meta.requestId,
          details: { roomId: access.roomId, count: envelopes.length },
        });
      }
      return envelopes;
    },

    /**
     * AZ-01: the current public identity of an ACTIVE member (for grants, fingerprint checks and,
     * since Phase 9, secret recipients), with the member's own grant, its authority chain and the
     * signers' identities. The chain starts from the member's stored grant, exactly as the member's
     * own key material does; the browser verifies all of it (CM-T043).
     */
    async memberIdentity(
      actor: Actor,
      access: RoomAccess,
      memberId: string,
    ): Promise<{ identity: IdentityRecord; grants: GrantRecord[]; identities: IdentityRecord[] }> {
      const identity = await store.findMemberIdentity(access.roomId, actor.userId, memberId);
      if (identity === null) throw notFound();
      // The caller is an ACTIVE member (the route's authorization) and so is the member (above).
      const grants = await store.grantChain(access.roomId, memberId, []);
      const signers: IdentityRef[] = grants.map((g) => ({ userId: g.grantorUserId, keyId: g.grantorKeyId }));
      return { identity, grants, identities: await store.identities(signers) };
    },

    /** AZ-29: a member's browser refused a key version; recorded with the version and reason only. */
    reportRejectedKey(
      actor: Actor,
      access: RoomAccess,
      input: { readonly keyVersion: number; readonly problem: 'AUTHENTICATION_FAILED' | 'COMMITMENT_MISMATCH' },
      meta: RequestMeta,
    ): void {
      events.record({
        name: 'ROOM_KEY_REJECTED',
        outcome: 'FAILURE',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId: access.roomId, keyVersion: input.keyVersion, problem: input.problem },
      });
    },

    /**
     * AZ-30: a member's statement that they compared the Room Safety Code of a key version, or a
     * mismatch report. The key version only; the code never reaches the server (INV-18). A
     * recorded comparison is the member's statement, not a verification by the system (ADR-012).
     */
    recordSafetyCode(
      actor: Actor,
      access: RoomAccess,
      input: { readonly keyVersion: number; readonly result: 'MATCH' | 'MISMATCH' },
      meta: RequestMeta,
    ): void {
      events.record({
        name: input.result === 'MATCH' ? 'SAFETY_CODE_CONFIRMED' : 'SAFETY_CODE_MISMATCH_REPORTED',
        outcome: 'SUCCESS',
        actorUserId: actor.userId,
        requestId: meta.requestId,
        details: { roomId: access.roomId, keyVersion: input.keyVersion },
      });
    },
  };
}

export type RoomKeyService = ReturnType<typeof createRoomKeyService>;
