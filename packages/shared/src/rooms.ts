/**
 * Room constants shared by the API and the web client (Phase 5, CM-T030). Room names are metadata
 * that the server stores and shows in plaintext (data-model 4.6, T-28); the client warns about it.
 */

/** Security profiles (security-policy-profiles.md), the information classes of a room. */
export const SECURITY_PROFILES = ['STANDARD', 'CONFIDENTIAL', 'RESTRICTED'] as const;
export type SecurityProfile = (typeof SECURITY_PROFILES)[number];

export const ROOM_NAME_MAX_LENGTH = 100;

/** Roles a role change can set (AZ-10). OWNER changes hands only through a transfer (AZ-05). */
export const ASSIGNABLE_ROOM_ROLES = ['ADMIN', 'MEMBER', 'VIEWER'] as const;
export type AssignableRoomRole = (typeof ASSIGNABLE_ROOM_ROLES)[number];

const HOUR = 60 * 60_000;

/**
 * The access requirements of each profile: PC-01 (an MFA-verified session) and PC-02 (the maximum
 * time since the last password authentication), from the table in security-policy-profiles.md,
 * which tests/security/profile-requirements.test.ts compares with these values. A creator must
 * meet them for the chosen profile (SS-04). Enforcing them on every room request is a policy
 * gate (CM-T047), which also absorbs these values into the versioned policy catalogue (CM-T046).
 */
export const PROFILE_ACCESS_REQUIREMENTS: Readonly<
  Record<SecurityProfile, { readonly mfaVerifiedSession: boolean; readonly maxAuthenticationAgeMs: number }>
> = Object.freeze({
  STANDARD: Object.freeze({ mfaVerifiedSession: false, maxAuthenticationAgeMs: 12 * HOUR }),
  CONFIDENTIAL: Object.freeze({ mfaVerifiedSession: true, maxAuthenticationAgeMs: 4 * HOUR }),
  RESTRICTED: Object.freeze({ mfaVerifiedSession: true, maxAuthenticationAgeMs: 1 * HOUR }),
});

/** Largest page of a room or member list (OL-08: lists are paginated with a maximum page size). */
export const ROOM_LIST_PAGE_SIZE = 50;
export const MEMBER_LIST_PAGE_SIZE = 100;
