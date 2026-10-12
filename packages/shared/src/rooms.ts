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
