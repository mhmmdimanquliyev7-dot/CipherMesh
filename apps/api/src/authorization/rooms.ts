import {
  decideRoomAction,
  ErrorCode,
  type RoomActionId,
  type RoomDecision,
  type RoomDecisionInput,
  type RoomDenyReason,
  type RoomMembershipFacts,
  type RoomResourceFacts,
  type ProfilePolicy,
  type RoomRole,
  type SensitiveOperation,
} from '@ciphermesh/shared';
import type { SecurityEventSink } from '../auth/security-events';
import type { Actor } from '../auth/sessions';
import type { RoomAccessStore, RoomMembershipRecord } from '../db/room-access-store';
import { HttpError } from '../http/errors';
import { enforceRoomAccess, enforceSensitiveOperation } from './policy';

/**
 * Central room authorization for the API (CM-T029, INV-05, INV-06, authorization model section 6).
 *
 * The route registry calls `authorize` for every room route before the handler runs; handlers
 * never repeat or replace this check. One request takes these steps:
 *   1. Load the caller's membership for (room ID from the validated path, session user) from the
 *      database (OL-01). No header, body or query field can supply a role, and the platform role
 *      is never consulted: a PLATFORM_ADMIN without a membership is an outsider (PA-05).
 *   2. Decide with the shared, pure matrix function (`decideRoomAction`, packages/shared). A caller
 *      without an ACTIVE membership in an ACTIVE room gets the generic 404 here.
 *   3. Apply the profile access gates PC-01 and PC-02 of the room's stored policy (Phase 10,
 *      CM-T047, ./policy.ts); an unsupported stored policy version fails closed.
 *   4. Only if the membership and the role allow it, load the target object within the room
 *      (routes whose cells depend on the object declare the loader) and decide again with its
 *      facts (OL-02, OL-04).
 *   5. For a sensitive operation, apply PC-03 (a recent step-up in RESTRICTED rooms).
 *   6. Deny with the generic 404 or 403 of the authorization model, or the policy's stable code,
 *      and record the reason code; otherwise hand the handler the database-loaded scope and policy.
 *
 * The decision describes the database state at the start of the request. A handler that changes
 * membership or ownership must re-check the stored state inside its own transaction (conditional
 * update or row lock), so a concurrent change cannot slip between this check and the write.
 */

/** The caller's standing in the addressed room, loaded from the database for this request. */
export interface RoomMembershipScope {
  readonly roomId: string;
  readonly membershipId: string;
  readonly role: RoomRole;
  readonly room: {
    readonly keyState: RoomMembershipRecord['room']['keyState'];
    readonly securityProfile: RoomMembershipRecord['room']['securityProfile'];
    readonly policyVersion: number;
  };
}

/** What a room route handler receives through `roomOf(ctx)`. */
export interface RoomAccess extends RoomMembershipScope {
  readonly action: RoomActionId;
  /** The object facts the decision used, when the route declares a resource loader. */
  readonly resource: RoomResourceFacts | undefined;
  /** The room's policy, resolved from its stored profile and version for this request. */
  readonly policy: ProfilePolicy;
}

export interface RoomAuthorizationRequest {
  readonly actor: Actor;
  /** The room ID from the validated request path. */
  readonly roomId: string;
  readonly action: RoomActionId;
  readonly requestId: string;
  /** The server clock at the request, for the session-age and step-up gates. */
  readonly now: Date;
  /** The PC-03 operation the route performs, if any (declared by the route, never by the request). */
  readonly sensitive?: SensitiveOperation;
  /** Loads the target object's facts within the room; null when it does not exist there. */
  readonly loadResource?: (scope: RoomMembershipScope) => Promise<RoomResourceFacts | null>;
}

export interface RoomAuthorizer {
  /** The caller's access for one request, or the generic 404 or 403 as an HttpError. */
  authorize(request: RoomAuthorizationRequest): Promise<RoomAccess>;
}

/** The decision's reasons, plus a resource loader that found nothing in the room. */
export type RoomDenial = RoomDenyReason | 'RESOURCE_NOT_FOUND';

const DENIAL_STATUS: Readonly<Record<RoomDenial, 403 | 404>> = {
  // Indistinguishable from a room or object that does not exist (OL-01, OL-02, OL-12).
  NOT_A_MEMBER: 404,
  MEMBERSHIP_MISMATCH: 404,
  MEMBERSHIP_NOT_ACTIVE: 404,
  ROOM_NOT_ACTIVE: 404,
  UNKNOWN_ROLE: 404,
  RESOURCE_OUTSIDE_ROOM: 404,
  RESOURCE_NOT_FOUND: 404,
  // Only the recipient learns that a secret exists (OL-06).
  NOT_RECIPIENT: 404,
  // An active member without the permission for this action (section 7).
  UNKNOWN_ACTION: 403,
  ROLE_NOT_PERMITTED: 403,
  INHERITED_ACTION: 403,
  RESOURCE_REQUIRED: 403,
  NOT_OWN_ITEM: 403,
  TARGET_ROLE_NOT_PERMITTED: 403,
};

/** The response for a denial. The same 404 as for an unknown room; the reason stays server-side. */
export function roomDenialError(reason: RoomDenial): HttpError {
  return DENIAL_STATUS[reason] === 404
    ? new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found')
    : new HttpError(403, ErrorCode.FORBIDDEN, 'You do not have permission for this action');
}

const membershipFacts = (record: RoomMembershipRecord): RoomMembershipFacts => ({
  roomId: record.roomId,
  userId: record.userId,
  role: record.role,
  status: record.status,
  roomStatus: record.room.status,
});

const scopeOf = (record: RoomMembershipRecord): RoomMembershipScope => ({
  roomId: record.roomId,
  membershipId: record.membershipId,
  role: record.role,
  room: {
    keyState: record.room.keyState,
    securityProfile: record.room.securityProfile,
    policyVersion: record.room.policyVersion,
  },
});

/** Records a denial (action and reason only) and returns the response to throw. */
export function roomDenial(
  events: SecurityEventSink,
  request: { readonly actorUserId: string; readonly requestId: string; readonly action: RoomActionId },
  reason: RoomDenial,
): HttpError {
  events.record({
    name: 'ROOM_ACCESS_DENIED',
    outcome: 'DENIED',
    actorUserId: request.actorUserId,
    requestId: request.requestId,
    details: { action: request.action, reason },
  });
  return roomDenialError(reason);
}

/**
 * Re-runs the central decision on state the caller has locked inside its own transaction. The
 * gate's decision describes the start of the request; a membership, role or ownership change
 * must not rely on it after a concurrent change of the actor's role, the target's role or the
 * room's state (CM-T031). Denies with the same responses and events as the gate.
 */
export function reauthorizeRoomAction(
  events: SecurityEventSink,
  request: { readonly actorUserId: string; readonly requestId: string },
  input: RoomDecisionInput,
): RoomRole {
  const decision = decideRoomAction(input);
  if (decision.allowed) return decision.role;
  throw roomDenial(events, { ...request, action: input.action }, decision.reason);
}

export function createRoomAuthorizer(deps: {
  readonly store: RoomAccessStore;
  readonly events: SecurityEventSink;
}): RoomAuthorizer {
  const denied = (request: RoomAuthorizationRequest, reason: RoomDenial): HttpError =>
    roomDenial(
      deps.events,
      { actorUserId: request.actor.userId, requestId: request.requestId, action: request.action },
      reason,
    );

  return {
    async authorize(request) {
      const { actor, roomId, action } = request;
      const record = await deps.store.findActiveMembership(roomId, actor.userId);
      const input: RoomDecisionInput = {
        actorUserId: actor.userId,
        roomId,
        membership: record === null ? null : membershipFacts(record),
        action,
      };
      let decision: RoomDecision = decideRoomAction(input);
      // Not an active member of an active room: the generic 404 before any policy is consulted,
      // so an outsider learns nothing about the room's profile (OL-01).
      if (!decision.allowed && DENIAL_STATUS[decision.reason] === 404) throw denied(request, decision.reason);
      if (record === null) throw denied(request, 'NOT_A_MEMBER');
      const policyRequest = { actorUserId: actor.userId, requestId: request.requestId, action };
      const policy = enforceRoomAccess(deps.events, policyRequest, actor, record.room, request.now);
      let resource: RoomResourceFacts | undefined;
      // Objects are looked up only once the membership and the role permit a first step, so a
      // non-member or a role without the permission never triggers an object lookup.
      if (request.loadResource !== undefined && (decision.allowed || decision.reason === 'RESOURCE_REQUIRED')) {
        const loaded = await request.loadResource(scopeOf(record));
        if (loaded === null) throw denied(request, 'RESOURCE_NOT_FOUND');
        resource = loaded;
        decision = decideRoomAction({ ...input, resource });
      }
      if (!decision.allowed) throw denied(request, decision.reason);
      if (request.sensitive !== undefined) {
        enforceSensitiveOperation(deps.events, policyRequest, actor, policy, request.now);
      }
      return { ...scopeOf(record), action, resource, policy };
    },
  };
}
