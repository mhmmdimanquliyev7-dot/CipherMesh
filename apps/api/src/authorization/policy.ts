import {
  decideRoomAccess,
  decideSensitiveOperation,
  ErrorCode,
  resolveRoomPolicy,
  type PolicyDecision,
  type PolicyDenyReason,
  type ProfilePolicy,
  type RoomActionId,
  type SecurityProfile,
} from '@ciphermesh/shared';
import type { SecurityEventSink } from '../auth/security-events';
import type { Actor } from '../auth/sessions';
import { HttpError } from '../http/errors';

/**
 * Server-side policy gates (Phase 10, CM-T047, INV-08).
 *
 * Authorization (./rooms.ts) decides whether the caller's role may perform an action on a
 * resource. The policy gates decide whether the room's security profile allows it for this
 * session. Both must pass. The gates read:
 *   - the room's stored profile and policy version, loaded from the database for this request or
 *     locked inside the writing transaction; never a profile or version from the request;
 *   - the session timestamps of the server-side session row (MFA, password sign-in, step-up);
 *   - the server clock.
 * The decisions themselves are the pure functions of the shared catalogue (packages/shared,
 * policy.ts). This module maps their reasons to the stable responses of the authorization model
 * (section 7) and records every refusal as ROOM_ACCESS_DENIED with the reason code only.
 */

/** A room's stored policy reference, as loaded from the database. */
export interface StoredRoomPolicy {
  readonly securityProfile: SecurityProfile;
  readonly policyVersion: number;
}

export interface PolicyRequest {
  readonly actorUserId: string;
  readonly requestId: string;
  readonly action: RoomActionId;
}

/** The response for a policy refusal. Generic messages; the reason stays in the event. */
export function policyDenialError(reason: PolicyDenyReason): HttpError {
  switch (reason) {
    case 'PROFILE_PC_01':
      return new HttpError(403, ErrorCode.MFA_REQUIRED, 'This room requires a session verified with MFA');
    case 'PROFILE_PC_02':
      return new HttpError(401, ErrorCode.REAUTH_REQUIRED, 'Sign in again to continue in this room');
    case 'PROFILE_PC_03':
    case 'PROFILE_DOWNGRADE_STEP_UP':
      return new HttpError(401, ErrorCode.STEP_UP_REQUIRED, 'Confirm your identity to continue');
    default:
      // POLICY_UNSUPPORTED: this server does not know the room's policy version. It refuses
      // instead of guessing (no fallback to another version or a weaker profile).
      return new HttpError(503, ErrorCode.POLICY_UNSUPPORTED, 'This room cannot be served right now');
  }
}

/**
 * The policy of a stored room, for rules applied after the gates passed (expiry bounds, invitation
 * rules, PC-12, PC-13). Fails closed like the gates when the version is unknown.
 */
export function policyOf(room: StoredRoomPolicy): ProfilePolicy {
  const policy = resolveRoomPolicy(room.securityProfile, room.policyVersion);
  if (policy === undefined) throw policyDenialError('POLICY_UNSUPPORTED');
  return policy;
}

/** Records a policy refusal (action and reason code only) and returns the response to throw. */
export function policyDenial(events: SecurityEventSink, request: PolicyRequest, reason: PolicyDenyReason): HttpError {
  events.record({
    name: 'ROOM_ACCESS_DENIED',
    outcome: 'DENIED',
    actorUserId: request.actorUserId,
    requestId: request.requestId,
    details: { action: request.action, reason },
  });
  return policyDenialError(reason);
}

function enforce(events: SecurityEventSink, request: PolicyRequest, decision: PolicyDecision): void {
  if (!decision.allowed) throw policyDenial(events, request, decision.reason);
}

/**
 * PC-01 and PC-02 (and the stored version) for one room request. Returns the room's policy, which
 * every later rule of the request uses, so all of them come from the same stored state.
 */
export function enforceRoomAccess(
  events: SecurityEventSink,
  request: PolicyRequest,
  actor: Actor,
  room: StoredRoomPolicy,
  now: Date,
): ProfilePolicy {
  const policy = resolveRoomPolicy(room.securityProfile, room.policyVersion);
  enforce(events, request, decideRoomAccess(policy, actor.session, now));
  // decideRoomAccess refuses an undefined policy; this guard only narrows the type.
  if (policy === undefined) throw policyDenial(events, request, 'POLICY_UNSUPPORTED');
  return policy;
}

/** PC-03 for a sensitive operation, under the policy the request resolved. */
export function enforceSensitiveOperation(
  events: SecurityEventSink,
  request: PolicyRequest,
  actor: Actor,
  policy: ProfilePolicy,
  now: Date,
): void {
  enforce(events, request, decideSensitiveOperation(policy, actor.session, now));
}

/**
 * The gates again, on the room row a writing transaction has locked. The gate at the start of the
 * request saw the state of that moment; a profile change commits under the same row lock, so the
 * write either sees the old profile and commits first, or waits and is judged by the new one. A
 * concurrent upgrade can therefore never let a write through under the weaker rules.
 */
export function reapplyRoomPolicy(
  events: SecurityEventSink,
  request: PolicyRequest,
  actor: Actor,
  room: StoredRoomPolicy,
  now: Date,
  sensitive: boolean,
): ProfilePolicy {
  const policy = enforceRoomAccess(events, request, actor, room, now);
  if (sensitive) enforceSensitiveOperation(events, request, actor, policy, now);
  return policy;
}
