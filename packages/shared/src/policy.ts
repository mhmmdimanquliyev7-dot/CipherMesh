/**
 * The versioned security policy catalogue (Phase 10, CM-T046).
 *
 * Normative source: docs/security/security-policy-profiles.md, the single source of truth for
 * profile values. tests/security/policy-catalogue.test.ts compares every value here with the
 * table of that document, so code and documentation cannot drift apart.
 *
 * Why code and not a table (data-model 4.16): policy values change only through a reviewed pull
 * request. No database row can widen a profile at runtime, so a database-level attacker cannot
 * weaken every room at once by editing one table. A room stores only its profile and the catalogue
 * version it is governed by; the rules themselves are the frozen data below.
 *
 * Versioning: a version is never edited after release. A change of any value adds a new version
 * (with an ADR when it weakens a control) and keeps the old one, so every stored room keeps the
 * rules it was governed by until a reviewed migration or a profile change moves it. A stored
 * version this code does not know resolves to no policy, and the API then refuses the room (fail
 * closed): it never falls back to another version or to a weaker profile.
 *
 * Nothing here reads a request. Callers resolve the policy from the room's stored profile and
 * version, loaded from the database (INV-08); a profile or version in a request body is never an
 * input.
 */

/** Security profiles: the information classes of a room (ISO/IEC 27001 Annex A 5.12). */
export const SECURITY_PROFILES = ['STANDARD', 'CONFIDENTIAL', 'RESTRICTED'] as const;
export type SecurityProfile = (typeof SECURITY_PROFILES)[number];

/** PC-13: what the audit emitter records (security-policy-profiles.md section 3). */
export const AUDIT_LEVELS = ['BASELINE', 'EXTENDED', 'FULL'] as const;
export type AuditLevel = (typeof AUDIT_LEVELS)[number];

/**
 * The sensitive operations of PC-03 (step-up within 15 minutes in RESTRICTED rooms), in the order
 * of the profile table. Routes name the operation they perform; START_REKEY has no route before
 * the rekey state machine (Phase 11, CM-T050).
 */
export const SENSITIVE_OPERATIONS = [
  'SECRET_REVEAL',
  'FILE_DOWNLOAD_URL',
  'INVITE',
  'APPROVE_INVITATION',
  'REMOVE_MEMBER',
  'START_REKEY',
  'CHANGE_PROFILE',
  'DELETE_ROOM',
] as const;
export type SensitiveOperation = (typeof SENSITIVE_OPERATIONS)[number];

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** The rules one profile imposes, under one catalogue version. Every field is a PC control. */
export interface ProfilePolicy {
  readonly version: number;
  readonly profile: SecurityProfile;
  /** Strictness order: an upgrade moves to a higher rank, a downgrade to a lower one. */
  readonly rank: number;
  /** PC-01 and PC-02: what a session needs to access the room at all. */
  readonly access: {
    readonly mfaVerifiedSession: boolean;
    readonly maxAuthenticationAgeMs: number;
  };
  /** PC-03: a step-up (password and TOTP) within the window for the sensitive operations. */
  readonly sensitiveStepUp: { readonly required: boolean; readonly windowMs: number };
  /** PC-04 to PC-07. */
  readonly invitations: {
    readonly adminInvitationNeedsApproval: boolean;
    readonly fingerprintConfirmation: 'optional' | 'prompted' | 'required';
    readonly validityMs: number;
    readonly keyHistory: 'all-retained' | 'current-only';
  };
  /** PC-08: expiry of files and notes. A null maximum means no maximum. */
  readonly contentExpiry: {
    readonly required: boolean;
    readonly maxMs: number | null;
    readonly defaultMs: number | null;
  };
  /** PC-09 and PC-10. */
  readonly secrets: {
    readonly maxLifetimeMs: number;
    readonly defaultLifetimeMs: number;
    readonly burnMandatory: boolean;
  };
  /** PC-11: external one-time links (stretch feature CM-T045, not built). */
  readonly externalLinks: { readonly allowed: boolean; readonly maxLifetimeMs: number | null };
  /** PC-12: whether a VIEWER may obtain file key material and ciphertext. */
  readonly viewerMayObtainFileKeys: boolean;
  /** PC-13. */
  readonly auditLevel: AuditLevel;
  /** PC-14: the room-key cryptoperiod; null means event-driven only. Enforced by CM-T052. */
  readonly cryptoperiodMs: number | null;
  /** PC-15: losing a member requires a rekey, in every profile. */
  readonly rekeyAfterMemberLoss: true;
  /** PC-16: content writes and invitations are blocked while REKEY_REQUIRED or REKEYING. */
  readonly writesBlockedWhileRekeying: true;
}

/** Rules of a profile change (security-policy-profiles.md section 4). */
export interface ProfileChangeRules {
  /** A downgrade needs a step-up within this window, regardless of profile. */
  readonly downgradeStepUpMs: number;
}

/** Deep-freezes the catalogue, so no code path can widen a value at runtime. */
function freezeDeep<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) freezeDeep(nested);
    Object.freeze(value);
  }
  return value;
}

/** Catalogue version 1: the profile table approved in Phase 0.5 (rooms of Phases 5 to 9 carry it). */
const VERSION_1: Record<SecurityProfile, ProfilePolicy> = {
  STANDARD: {
    version: 1,
    profile: 'STANDARD',
    rank: 0,
    access: { mfaVerifiedSession: false, maxAuthenticationAgeMs: 12 * HOUR },
    sensitiveStepUp: { required: false, windowMs: 15 * MINUTE },
    invitations: {
      adminInvitationNeedsApproval: false,
      fingerprintConfirmation: 'optional',
      validityMs: 7 * DAY,
      keyHistory: 'all-retained',
    },
    contentExpiry: { required: false, maxMs: null, defaultMs: null },
    secrets: { maxLifetimeMs: 7 * DAY, defaultLifetimeMs: 24 * HOUR, burnMandatory: false },
    externalLinks: { allowed: true, maxLifetimeMs: 24 * HOUR },
    viewerMayObtainFileKeys: true,
    auditLevel: 'BASELINE',
    cryptoperiodMs: null,
    rekeyAfterMemberLoss: true,
    writesBlockedWhileRekeying: true,
  },
  CONFIDENTIAL: {
    version: 1,
    profile: 'CONFIDENTIAL',
    rank: 1,
    access: { mfaVerifiedSession: true, maxAuthenticationAgeMs: 4 * HOUR },
    sensitiveStepUp: { required: false, windowMs: 15 * MINUTE },
    invitations: {
      adminInvitationNeedsApproval: true,
      fingerprintConfirmation: 'prompted',
      validityMs: 72 * HOUR,
      keyHistory: 'all-retained',
    },
    contentExpiry: { required: true, maxMs: 90 * DAY, defaultMs: 30 * DAY },
    secrets: { maxLifetimeMs: 72 * HOUR, defaultLifetimeMs: 24 * HOUR, burnMandatory: false },
    externalLinks: { allowed: false, maxLifetimeMs: null },
    viewerMayObtainFileKeys: true,
    auditLevel: 'EXTENDED',
    cryptoperiodMs: 180 * DAY,
    rekeyAfterMemberLoss: true,
    writesBlockedWhileRekeying: true,
  },
  RESTRICTED: {
    version: 1,
    profile: 'RESTRICTED',
    rank: 2,
    access: { mfaVerifiedSession: true, maxAuthenticationAgeMs: 1 * HOUR },
    sensitiveStepUp: { required: true, windowMs: 15 * MINUTE },
    invitations: {
      adminInvitationNeedsApproval: true,
      fingerprintConfirmation: 'required',
      validityMs: 24 * HOUR,
      keyHistory: 'current-only',
    },
    contentExpiry: { required: true, maxMs: 30 * DAY, defaultMs: 7 * DAY },
    secrets: { maxLifetimeMs: 24 * HOUR, defaultLifetimeMs: 1 * HOUR, burnMandatory: true },
    externalLinks: { allowed: false, maxLifetimeMs: null },
    viewerMayObtainFileKeys: false,
    auditLevel: 'FULL',
    cryptoperiodMs: 90 * DAY,
    rekeyAfterMemberLoss: true,
    writesBlockedWhileRekeying: true,
  },
};

const CATALOGUE: Readonly<Record<string, Readonly<Record<SecurityProfile, ProfilePolicy>>>> = freezeDeep({
  '1': VERSION_1,
});

/** The version new rooms and profile changes are recorded with. */
export const POLICY_CATALOGUE_VERSION = 1;

/** Every version this code can evaluate. A stored version outside this list fails closed. */
export const SUPPORTED_POLICY_VERSIONS: readonly number[] = Object.freeze(Object.keys(CATALOGUE).map(Number));

export const PROFILE_CHANGE_RULES: ProfileChangeRules = Object.freeze({ downgradeStepUpMs: 5 * MINUTE });

export function isSecurityProfile(value: unknown): value is SecurityProfile {
  return typeof value === 'string' && (SECURITY_PROFILES as readonly string[]).includes(value);
}

/**
 * The policy of a stored (profile, version) pair, or undefined when either is not one this code
 * knows: an unknown, malformed or non-integer version, or an unknown profile. Callers refuse the
 * request on undefined; there is no default and no fallback (fail closed).
 */
export function resolveRoomPolicy(profile: unknown, version: unknown): ProfilePolicy | undefined {
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || !isSecurityProfile(profile)) return undefined;
  const key = String(version);
  // Own keys only: '__proto__' or 'constructor' are never versions.
  return Object.hasOwn(CATALOGUE, key) ? CATALOGUE[key]?.[profile] : undefined;
}

/** The current catalogue version's policy for a profile: what a new room or a profile change gets. */
export function currentPolicy(profile: SecurityProfile): ProfilePolicy {
  const policy = resolveRoomPolicy(profile, POLICY_CATALOGUE_VERSION);
  // Unreachable with the frozen catalogue; a missing entry must never become a weaker default.
  if (policy === undefined) throw new Error('The current policy catalogue version is incomplete');
  return policy;
}

/** Whether events of `required` are recorded at `level` (BASELINE < EXTENDED < FULL). */
export function auditLevelIncludes(level: AuditLevel, required: AuditLevel): boolean {
  return AUDIT_LEVELS.indexOf(level) >= AUDIT_LEVELS.indexOf(required);
}

// ------------------------------------------------------------------------------- gate decisions

/** The session timestamps a gate reads, from the server-side session row only. */
export interface PolicySessionFacts {
  readonly authenticatedAt: Date;
  readonly mfaVerifiedAt: Date | null;
  readonly stepUpAt: Date | null;
}

/** Why a policy gate refused. Logged as a reason code; mapped to a stable error code by the API. */
export type PolicyDenyReason =
  'POLICY_UNSUPPORTED' | 'PROFILE_PC_01' | 'PROFILE_PC_02' | 'PROFILE_PC_03' | 'PROFILE_DOWNGRADE_STEP_UP';

export type PolicyDecision =
  { readonly allowed: true } | { readonly allowed: false; readonly reason: PolicyDenyReason };

const ALLOW: PolicyDecision = Object.freeze({ allowed: true });
const refuse = (reason: PolicyDenyReason): PolicyDecision => ({ allowed: false, reason });

/** A step-up within the window; one dated in the future (clock skew, tampering) never counts. */
export function stepUpIsRecent(stepUpAt: Date | null, windowMs: number, now: Date): boolean {
  return stepUpAt !== null && stepUpAt.getTime() <= now.getTime() && now.getTime() - stepUpAt.getTime() <= windowMs;
}

/**
 * PC-01 and PC-02, the access gates of every room request (evaluation order step 3). An undefined
 * policy (unsupported stored version) is refused before anything else.
 */
export function decideRoomAccess(
  policy: ProfilePolicy | undefined,
  session: PolicySessionFacts,
  now: Date,
): PolicyDecision {
  if (policy === undefined) return refuse('POLICY_UNSUPPORTED');
  if (policy.access.mfaVerifiedSession && session.mfaVerifiedAt === null) return refuse('PROFILE_PC_01');
  const age = now.getTime() - session.authenticatedAt.getTime();
  if (!(age <= policy.access.maxAuthenticationAgeMs)) return refuse('PROFILE_PC_02');
  return ALLOW;
}

/** PC-03 for one sensitive operation (evaluation order step 5). */
export function decideSensitiveOperation(
  policy: ProfilePolicy | undefined,
  session: PolicySessionFacts,
  now: Date,
): PolicyDecision {
  if (policy === undefined) return refuse('POLICY_UNSUPPORTED');
  if (!policy.sensitiveStepUp.required) return ALLOW;
  return stepUpIsRecent(session.stepUpAt, policy.sensitiveStepUp.windowMs, now) ? ALLOW : refuse('PROFILE_PC_03');
}

export type ProfileChangeDirection = 'UPGRADE' | 'DOWNGRADE' | 'UNCHANGED';

export function profileChangeDirection(from: ProfilePolicy, to: ProfilePolicy): ProfileChangeDirection {
  if (to.rank > from.rank) return 'UPGRADE';
  if (to.rank < from.rank) return 'DOWNGRADE';
  return 'UNCHANGED';
}

/**
 * The extra requirements of a profile change (section 4), on top of the gates of the current
 * profile that every room request passes. An upgrade needs the OWNER to meet the new profile's
 * access requirements (PC-01, PC-02) and, when the new profile has PC-03, its step-up: the change
 * is a sensitive operation of the room it produces (decision D-10-03). A downgrade needs a step-up
 * within 5 minutes, regardless of profile.
 */
export function decideProfileChange(
  from: ProfilePolicy,
  to: ProfilePolicy,
  session: PolicySessionFacts,
  now: Date,
): PolicyDecision {
  switch (profileChangeDirection(from, to)) {
    case 'UPGRADE': {
      const access = decideRoomAccess(to, session, now);
      return access.allowed ? decideSensitiveOperation(to, session, now) : access;
    }
    case 'DOWNGRADE':
      return stepUpIsRecent(session.stepUpAt, PROFILE_CHANGE_RULES.downgradeStepUpMs, now)
        ? ALLOW
        : refuse('PROFILE_DOWNGRADE_STEP_UP');
    default:
      return ALLOW;
  }
}

/**
 * Expiry clamping on an upgrade: an existing expiry becomes at most `changedAt + maxMs`; no expiry
 * (unbounded) becomes exactly that; a null maximum leaves the expiry as it is. Never later than
 * the stored value, so no profile change extends a lifetime.
 */
export function clampedExpiry(current: Date | null, changedAt: Date, maxMs: number | null): Date | null {
  if (maxMs === null) return current;
  const cap = new Date(changedAt.getTime() + maxMs);
  return current === null || current.getTime() > cap.getTime() ? cap : current;
}
