/**
 * Room constants shared by the API and the web client (Phase 5, CM-T030). Room names are metadata
 * that the server stores and shows in plaintext (data-model 4.6, T-28); the client warns about it.
 * The profile rules (PC-01 to PC-16) are in the versioned policy catalogue, ./policy.ts (CM-T046).
 */

export { SECURITY_PROFILES, type SecurityProfile } from './policy';

export const ROOM_NAME_MAX_LENGTH = 100;

/** Roles a role change can set (AZ-10). OWNER changes hands only through a transfer (AZ-05). */
export const ASSIGNABLE_ROOM_ROLES = ['ADMIN', 'MEMBER', 'VIEWER'] as const;
export type AssignableRoomRole = (typeof ASSIGNABLE_ROOM_ROLES)[number];

/** Largest page of a room or member list (OL-08: lists are paginated with a maximum page size). */
export const ROOM_LIST_PAGE_SIZE = 50;
export const MEMBER_LIST_PAGE_SIZE = 100;
/** Largest page of an invitation list (the room's for AZ-31, the invitee's own for SS-03). */
export const INVITATION_LIST_PAGE_SIZE = 50;

/**
 * Rekey operations (Phase 11, CP-25, ADR-013, key-lifecycle 1.3 and 1.7). The lease bounds how long
 * one operation can hold a room in REKEYING; a crashed browser's operation is ABANDONED after it.
 */
export const REKEY_RULES = Object.freeze({
  leaseMs: 10 * 60_000,
  /** CP-25: at most 10 operation starts per room per hour. */
  maxStartsPerHour: 10,
  /** CP-25: at most 100 members plus pending invitees, so a finalize carries at most 100 envelopes. */
  maxRecipients: 100,
  /** PC-14: the reminder appears this long before a cryptoperiod ends (R6). */
  cryptoperiodReminderMs: 14 * 24 * 60 * 60_000,
  /** Closed operations are purged after 90 days (data-model section 5); the version row stays. */
  closedRetentionMs: 90 * 24 * 60 * 60_000,
});

/** Why a room needs a rekey (key-lifecycle 1.3, R1 to R7). */
export const REKEY_REASONS = [
  'MEMBER_REMOVED',
  'MEMBER_LEFT',
  'MEMBER_SUSPENDED',
  'MEMBER_DELETED',
  'IDENTITY_KEY_COMPROMISED',
  'CRYPTOPERIOD_EXPIRED',
  'WRAP_LIMIT_REACHED',
] as const;
export type RekeyReason = (typeof REKEY_REASONS)[number];
