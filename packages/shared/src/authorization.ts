/**
 * Room authorization matrix and the central decision function (CM-T029).
 *
 * Normative source: docs/security/authorization-model.md sections 2 to 5. The matrix is data, so
 * the API enforces it (apps/api/src/authorization/rooms.ts, INV-05) and the web client may read it
 * to hide controls, which is UX only and never authorization. tests/security/authz-matrix.test.ts
 * compares this file with the tables of the authorization model, so the two cannot drift apart.
 *
 * What a decision uses, and what it never uses:
 * - the caller's membership as loaded from the database for (room ID, session user), never a
 *   role, owner or room field taken from a request (OL-01, OL-04, INV-06);
 * - the room's status: only an ACTIVE membership in an ACTIVE room grants anything;
 * - facts about the target object, loaded from the database within the same room (OL-02).
 * The platform role is deliberately not an input. PLATFORM_ADMIN confers nothing inside a room
 * (PA-05), so a platform administrator is an outsider to every room they are not a member of.
 *
 * Profile conditions (PC-01 to PC-16, security-policy-profiles.md) apply on top of this matrix.
 * They arrive with the policy engine (CM-T046, CM-T047); this module does not implement them.
 */

export const ROOM_ROLES = ['OWNER', 'ADMIN', 'MEMBER', 'VIEWER'] as const;
export type RoomRole = (typeof ROOM_ROLES)[number];

/** Membership states (data-model 4.7). Only ACTIVE grants access; SUSPENDED keeps the role for reinstatement. */
export const MEMBERSHIP_STATUSES = ['ACTIVE', 'SUSPENDED', 'REMOVED', 'LEFT'] as const;
export type MembershipStatus = (typeof MEMBERSHIP_STATUSES)[number];

/** Room states (data-model 4.6). A DELETING or DELETED room refuses every request at once. */
export const ROOM_STATUSES = ['ACTIVE', 'DELETING', 'DELETED'] as const;
export type RoomStatus = (typeof ROOM_STATUSES)[number];

/**
 * One cell of the room matrix.
 * - `allow`, `deny`: Y and N in the authorization model.
 * - `own`: only on items the caller created (author, uploader, sender or inviter, OL-04).
 * - `recipient`: only the recipient of the item (OL-06).
 * - `targetRoles`: only when every role the action touches is in the list: the target member's
 *   current role, and for role changes and invitations the requested role. This encodes the role
 *   ceilings, for example that an ADMIN never creates, removes or demotes an ADMIN.
 * - `inherited`: no permission of its own (AZ-27); the read rule of the inspected item applies.
 */
export type RoomRule =
  | { readonly kind: 'allow' }
  | { readonly kind: 'deny' }
  | { readonly kind: 'own' }
  | { readonly kind: 'recipient' }
  | { readonly kind: 'targetRoles'; readonly roles: readonly RoomRole[] }
  | { readonly kind: 'inherited' };

export interface RoomActionDefinition {
  readonly title: string;
  readonly rules: Readonly<Record<RoomRole, RoomRule>>;
  /** A step-up is required in every profile (AZ-04, AZ-05); routes must declare it. */
  readonly stepUp?: 'always';
}

/** Deep-freezes the catalogues, so no code path can widen a permission at runtime. */
function freezeDeep<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) freezeDeep(nested);
    Object.freeze(value);
  }
  return value;
}

const Y: RoomRule = { kind: 'allow' };
const N: RoomRule = { kind: 'deny' };
const OWN: RoomRule = { kind: 'own' };
const RECIPIENT: RoomRule = { kind: 'recipient' };
const INHERITED: RoomRule = { kind: 'inherited' };
const targets = (...roles: RoomRole[]): RoomRule => ({ kind: 'targetRoles', roles });
const row = (owner: RoomRule, admin: RoomRule, member: RoomRule, viewer: RoomRule): Record<RoomRole, RoomRule> => ({
  OWNER: owner,
  ADMIN: admin,
  MEMBER: member,
  VIEWER: viewer,
});

// Columns: OWNER, ADMIN, MEMBER, VIEWER. Notes that are profile conditions (PC-xx) or key-state
// locks (PC-16) are not cells: they belong to the policy engine (CM-T047).
const ROOM_MATRIX = {
  'AZ-01': { title: 'View room metadata, member list, profile', rules: row(Y, Y, Y, Y) },
  'AZ-02': { title: 'Rename room', rules: row(Y, Y, N, N) },
  'AZ-03': { title: 'Change security profile', rules: row(Y, N, N, N) },
  'AZ-04': { title: 'Delete room', rules: row(Y, N, N, N), stepUp: 'always' },
  // The cell says Y; the action itself restricts the new owner to a current ADMIN.
  'AZ-05': { title: 'Transfer ownership to an ADMIN', rules: row(targets('ADMIN'), N, N, N), stepUp: 'always' },
  'AZ-06': {
    title: 'Create invitation',
    rules: row(targets('ADMIN', 'MEMBER', 'VIEWER'), targets('MEMBER', 'VIEWER'), N, N),
  },
  'AZ-07': { title: 'Approve an ADMIN-created invitation', rules: row(Y, N, N, N) },
  'AZ-08': { title: 'Revoke a pending invitation', rules: row(Y, OWN, N, N) },
  'AZ-09': {
    title: 'Remove a member',
    rules: row(targets('ADMIN', 'MEMBER', 'VIEWER'), targets('MEMBER', 'VIEWER'), N, N),
  },
  'AZ-10': {
    title: 'Change a member role',
    rules: row(targets('ADMIN', 'MEMBER', 'VIEWER'), targets('MEMBER', 'VIEWER'), N, N),
  },
  'AZ-11': { title: 'Leave room', rules: row(N, Y, Y, Y) },
  // Own envelopes only: selected by recipient = caller in the query (OL-05), not by an object rule.
  'AZ-12': { title: 'Fetch own key envelopes', rules: row(Y, Y, Y, Y) },
  // The operation rules of OL-13 (only the starter finalizes; the starter or the OWNER cancels)
  // depend on the operation row and are enforced by the rekey state machine (CM-T050).
  'AZ-13': { title: 'Start, finalize or cancel a rekey operation', rules: row(Y, Y, N, N) },
  'AZ-14': { title: 'Re-share keys to a new identity key of a member', rules: row(Y, Y, N, N) },
  'AZ-15': {
    title: 'View key state, rekey status, key-version metadata and commitments',
    rules: row(Y, Y, Y, Y),
  },
  'AZ-16': { title: 'Upload file', rules: row(Y, Y, Y, N) },
  'AZ-17': {
    title: 'Get file key material (wrapped FEK, encrypted manifest) and ciphertext',
    rules: row(Y, Y, Y, Y),
  },
  'AZ-18': { title: 'Delete file', rules: row(Y, Y, OWN, N) },
  'AZ-19': { title: 'Create note', rules: row(Y, Y, Y, N) },
  'AZ-20': { title: 'Read note', rules: row(Y, Y, Y, Y) },
  'AZ-21': { title: 'Update note', rules: row(Y, Y, OWN, N) },
  'AZ-22': { title: 'Delete note', rules: row(Y, Y, OWN, N) },
  'AZ-23': { title: 'Create secret for an ACTIVE room member', rules: row(Y, Y, Y, N) },
  'AZ-24': { title: 'Reveal a secret', rules: row(RECIPIENT, RECIPIENT, RECIPIENT, RECIPIENT) },
  'AZ-25': { title: 'Revoke an unrevealed secret', rules: row(Y, Y, OWN, N) },
  'AZ-26': { title: 'Create external one-time link (stretch)', rules: row(Y, Y, Y, N) },
  'AZ-27': { title: 'Open Crypto Inspector for an item', rules: row(INHERITED, INHERITED, INHERITED, INHERITED) },
  'AZ-28': { title: 'View room audit log', rules: row(Y, Y, N, N) },
  'AZ-29': { title: 'Report a key-commitment mismatch', rules: row(Y, Y, Y, Y) },
  'AZ-30': { title: 'Record a Room Safety Code comparison or report a mismatch', rules: row(Y, Y, Y, Y) },
} satisfies Record<string, RoomActionDefinition>;

export type RoomActionId = keyof typeof ROOM_MATRIX;
export const ROOM_ACTIONS: Readonly<Record<RoomActionId, RoomActionDefinition>> = freezeDeep(ROOM_MATRIX);
export const ROOM_ACTION_IDS: readonly RoomActionId[] = Object.freeze(Object.keys(ROOM_MATRIX) as RoomActionId[]);

export interface AccountActionDefinition {
  readonly title: string;
  /** `none` marks an explicit deny that no route can declare (PA-05). */
  readonly scope: 'platform' | 'self' | 'none';
  /** A step-up is required every time (PA-03, PA-04); routes must declare it. */
  readonly stepUp?: 'always';
}

// Section 4 of the authorization model. Platform actions additionally need PLATFORM_ADMIN with an
// MFA-verified session (the route registry's platform administrator gate).
const ACCOUNT_MATRIX = {
  'PA-01': { title: 'View Security Dashboard (aggregates)', scope: 'platform' },
  'PA-02': { title: 'Run and view audit-chain verification', scope: 'platform' },
  'PA-03': { title: 'Disable or enable a user account', scope: 'platform', stepUp: 'always' },
  'PA-04': { title: 'Administrator-assisted password or MFA reset', scope: 'platform', stepUp: 'always' },
  'PA-05': { title: 'Room content, membership, envelopes', scope: 'none' },
  'SS-01': { title: 'Manage own profile, sessions, MFA', scope: 'self' },
  'SS-02': { title: 'Create, unlock, re-wrap or reset own vault', scope: 'self' },
  'SS-03': { title: 'View, accept or decline own invitations', scope: 'self' },
  'SS-04': { title: 'Create a room', scope: 'self' },
  'SS-05': { title: 'Look up a user by exact email to invite', scope: 'self' },
  // Added in Phase 5 (CM-T030): listing one's rooms is a query over the caller's own memberships,
  // not an action inside one room, so no AZ action can authorize it (OL-08).
  'SS-06': { title: 'List own rooms', scope: 'self' },
} satisfies Record<string, AccountActionDefinition>;

export type AccountActionId = keyof typeof ACCOUNT_MATRIX;
export const ACCOUNT_ACTIONS: Readonly<Record<AccountActionId, AccountActionDefinition>> = freezeDeep(ACCOUNT_MATRIX);

export function isRoomRole(value: unknown): value is RoomRole {
  return typeof value === 'string' && (ROOM_ROLES as readonly string[]).includes(value);
}

export function isRoomActionId(value: unknown): value is RoomActionId {
  // Own keys only: '__proto__', 'constructor' or 'toString' are never actions.
  return typeof value === 'string' && Object.hasOwn(ROOM_ACTIONS, value);
}

const DENY_RULE: RoomRule = N;

/** The cell for a role and action. Unknown roles and actions get `deny` (fail closed). */
export function roomRuleFor(action: unknown, role: unknown): RoomRule {
  return isRoomActionId(action) && isRoomRole(role) ? ROOM_ACTIONS[action].rules[role] : DENY_RULE;
}

const needsResource = (rule: RoomRule): boolean =>
  rule.kind === 'own' || rule.kind === 'recipient' || rule.kind === 'targetRoles';

/** What the route registry needs to know about a declared action ID (AZ-xx, PA-xx, SS-xx). */
export interface MatrixActionInfo {
  readonly id: string;
  readonly scope: 'room' | 'platform' | 'self' | 'none';
  readonly stepUpAlways: boolean;
  /** Some cell depends on facts about the target object, so the route must load them. */
  readonly needsResource: boolean;
  /** No permission of its own (AZ-27). */
  readonly inherited: boolean;
}

export function describeMatrixAction(id: string): MatrixActionInfo | undefined {
  if (isRoomActionId(id)) {
    const rules = Object.values(ROOM_ACTIONS[id].rules);
    return {
      id,
      scope: 'room',
      stepUpAlways: ROOM_ACTIONS[id].stepUp === 'always',
      needsResource: rules.some(needsResource),
      inherited: rules.every((rule) => rule.kind === 'inherited'),
    };
  }
  if (Object.hasOwn(ACCOUNT_ACTIONS, id)) {
    const action = ACCOUNT_ACTIONS[id as AccountActionId];
    return {
      id,
      scope: action.scope,
      stepUpAlways: action.stepUp === 'always',
      needsResource: false,
      inherited: false,
    };
  }
  return undefined;
}

/** The caller's membership row for the addressed room, exactly as the database returned it. */
export interface RoomMembershipFacts {
  readonly roomId: string;
  readonly userId: string;
  readonly role: RoomRole;
  readonly status: MembershipStatus;
  readonly roomStatus: RoomStatus;
}

/** Facts about the target object, loaded from the database by (object ID, room ID) (OL-02). */
export interface RoomResourceFacts {
  /** The room the object belongs to, as stored. Must equal the addressed room. */
  readonly roomId: string;
  /** The stored author, uploader, sender or inviter, for `own` cells (OL-04). */
  readonly createdById?: string;
  /** The stored recipient, for `recipient` cells (OL-06). */
  readonly recipientUserId?: string;
  /** Every role the action touches, for `targetRoles` cells: stored target role, requested role. */
  readonly roles?: readonly RoomRole[];
}

export interface RoomDecisionInput {
  /** The authenticated caller, from the server-side session only. */
  readonly actorUserId: string;
  /** The room addressed by the request path (OL-01). */
  readonly roomId: string;
  /** The caller's membership loaded for (roomId, actorUserId), or null when there is none. */
  readonly membership: RoomMembershipFacts | null;
  readonly action: RoomActionId;
  readonly resource?: RoomResourceFacts;
}

/** Why a request was denied. Logged as a reason code; never shown to the caller. */
export type RoomDenyReason =
  | 'NOT_A_MEMBER'
  | 'MEMBERSHIP_MISMATCH'
  | 'MEMBERSHIP_NOT_ACTIVE'
  | 'ROOM_NOT_ACTIVE'
  | 'UNKNOWN_ROLE'
  | 'UNKNOWN_ACTION'
  | 'ROLE_NOT_PERMITTED'
  | 'INHERITED_ACTION'
  | 'RESOURCE_REQUIRED'
  | 'RESOURCE_OUTSIDE_ROOM'
  | 'NOT_OWN_ITEM'
  | 'NOT_RECIPIENT'
  | 'TARGET_ROLE_NOT_PERMITTED';

export type RoomDecision =
  { readonly allowed: true; readonly role: RoomRole } | { readonly allowed: false; readonly reason: RoomDenyReason };

const deny = (reason: RoomDenyReason): RoomDecision => ({ allowed: false, reason });

/**
 * The central room authorization decision: pure, deterministic and fail-closed. Anything it does
 * not recognise (a missing membership, an inactive state, an unknown role or action, a missing or
 * foreign object) is a denial. `RESOURCE_REQUIRED` means the cell depends on the target object:
 * the caller loads its facts within the room and asks again.
 */
export function decideRoomAction(input: RoomDecisionInput): RoomDecision {
  const { membership } = input;
  if (membership === null) return deny('NOT_A_MEMBER');
  // A membership of another room or another user never authorizes this request (BOLA, T-06).
  if (membership.roomId !== input.roomId || membership.userId !== input.actorUserId) {
    return deny('MEMBERSHIP_MISMATCH');
  }
  if (membership.roomStatus !== 'ACTIVE') return deny('ROOM_NOT_ACTIVE');
  if (membership.status !== 'ACTIVE') return deny('MEMBERSHIP_NOT_ACTIVE');
  const { role } = membership;
  if (!isRoomRole(role)) return deny('UNKNOWN_ROLE');
  if (!isRoomActionId(input.action)) return deny('UNKNOWN_ACTION');
  return applyRule(ROOM_ACTIONS[input.action].rules[role], role, input);
}

function applyRule(rule: RoomRule, role: RoomRole, input: RoomDecisionInput): RoomDecision {
  const allow: RoomDecision = { allowed: true, role };
  if (rule.kind === 'deny') return deny('ROLE_NOT_PERMITTED');
  if (rule.kind === 'inherited') return deny('INHERITED_ACTION');
  const { resource } = input;
  if (resource === undefined) return rule.kind === 'allow' ? allow : deny('RESOURCE_REQUIRED');
  // An object takes part in a decision only if it belongs to the addressed room (OL-02).
  if (resource.roomId !== input.roomId) return deny('RESOURCE_OUTSIDE_ROOM');
  switch (rule.kind) {
    case 'allow':
      return allow;
    case 'own':
      return resource.createdById === input.actorUserId ? allow : deny('NOT_OWN_ITEM');
    case 'recipient':
      return resource.recipientUserId === input.actorUserId ? allow : deny('NOT_RECIPIENT');
    case 'targetRoles': {
      const ceiling = rule.roles;
      const touched = resource.roles ?? [];
      return touched.length > 0 && touched.every((r) => ceiling.includes(r))
        ? allow
        : deny('TARGET_ROLE_NOT_PERMITTED');
    }
    default: {
      // Unreachable with the typed catalogue; a corrupted rule still fails closed.
      const _unreachable: never = rule;
      return deny('UNKNOWN_ACTION');
    }
  }
}
