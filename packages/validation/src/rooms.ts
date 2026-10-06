import {
  ASSIGNABLE_ROOM_ROLES,
  isUuidV4,
  MEMBER_LIST_PAGE_SIZE,
  ROOM_LIST_PAGE_SIZE,
  ROOM_NAME_MAX_LENGTH,
  ROOM_ROLES,
  SECURITY_PROFILES,
} from '@ciphermesh/shared';
import { isoTimestampSchema, uuidV4Schema } from './schemas';
import { z } from './zod';

/**
 * Room request and response schemas (Phase 5, CM-T030, CM-T031). Every request object is strict,
 * so a role, owner, user, status or key field is rejected rather than ignored (OL-03, OL-04, mass
 * assignment). No request carries key material: room keys arrive with their own schemas in
 * Phase 6. Responses are the explicit projections the API may send.
 */

/** Unicode NFKC and trimmed, like display names. Disallowed characters are refused, not stripped. */
export function normalizeRoomName(value: string): string {
  return value.normalize('NFKC').trim();
}

// Control characters and the bidirectional embedding, override and isolate controls, which can
// make a name display as something it is not to the other members (T-28).
const DISALLOWED_NAME_CHARACTERS = /[\p{Cc}‪-‮⁦-⁩]/u;

export const roomNameSchema = z
  .string()
  .max(ROOM_NAME_MAX_LENGTH * 2)
  .transform(normalizeRoomName)
  .pipe(
    z
      .string()
      .min(1)
      .max(ROOM_NAME_MAX_LENGTH)
      .refine((v) => !DISALLOWED_NAME_CHARACTERS.test(v), { message: 'Control characters are not allowed' }),
  );

export const securityProfileSchema = z.enum(SECURITY_PROFILES);
export const roomRoleSchema = z.enum(ROOM_ROLES);
const keyStateSchema = z.enum(['ACTIVE', 'REKEY_REQUIRED', 'REKEYING']);

/** Path parameters of room routes. A malformed value is the generic 404 (route registry). */
export const roomParamsSchema = z.strictObject({ roomId: uuidV4Schema });
export const roomMemberParamsSchema = z.strictObject({ roomId: uuidV4Schema, userId: uuidV4Schema });

// Keyset pagination (OL-08): the cursor is the sort key of the last item returned,
// `<ISO 8601 UTC timestamp with milliseconds>_<UUIDv4>`. It names nothing the caller has not seen.
const CURSOR = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)_(.+)$/;

export function parseListCursor(value: string): { readonly at: Date; readonly id: string } | undefined {
  const match = CURSOR.exec(value);
  if (match === null) return undefined;
  const [, iso = '', id = ''] = match;
  const at = new Date(iso);
  return !Number.isNaN(at.getTime()) && at.toISOString() === iso && isUuidV4(id) ? { at, id } : undefined;
}

export function formatListCursor(at: Date, id: string): string {
  return `${at.toISOString()}_${id}`;
}

export const listCursorSchema = z
  .string()
  .max(64)
  .refine((v) => parseListCursor(v) !== undefined, { message: 'Invalid cursor' });

export const listQuerySchema = z.strictObject({ cursor: listCursorSchema.optional() });

// ------------------------------------------------------------------------------------- requests

export const roomCreateRequestSchema = z.strictObject({
  roomId: uuidV4Schema,
  name: roomNameSchema,
  securityProfile: securityProfileSchema,
});

export const roomRenameRequestSchema = z.strictObject({ name: roomNameSchema });

/** OWNER is not assignable: ownership changes only through a transfer (AZ-05). */
export const memberRoleChangeRequestSchema = z.strictObject({ role: z.enum(ASSIGNABLE_ROOM_ROLES) });

// ------------------------------------------------------------------------------------ responses

export const roomSummarySchema = z.strictObject({
  id: uuidV4Schema,
  name: z.string(),
  securityProfile: securityProfileSchema,
  /** The caller's own role in the room. */
  role: roomRoleSchema,
  keyState: keyStateSchema,
  createdAt: isoTimestampSchema,
});
export type RoomSummary = z.infer<typeof roomSummarySchema>;

export const roomListResponseSchema = z.strictObject({
  rooms: z.array(roomSummarySchema).max(ROOM_LIST_PAGE_SIZE),
  nextCursor: listCursorSchema.nullable(),
});

export const roomDetailResponseSchema = z.strictObject({
  room: z.strictObject({
    id: uuidV4Schema,
    name: z.string(),
    securityProfile: securityProfileSchema,
    keyState: keyStateSchema,
    createdAt: isoTimestampSchema,
    updatedAt: isoTimestampSchema,
  }),
  membership: z.strictObject({ role: roomRoleSchema }),
});
export type RoomDetail = z.infer<typeof roomDetailResponseSchema>;

export const roomMemberSchema = z.strictObject({
  userId: uuidV4Schema,
  displayName: z.string(),
  role: roomRoleSchema,
  status: z.enum(['ACTIVE', 'SUSPENDED']),
  joinedAt: isoTimestampSchema,
});
export type RoomMember = z.infer<typeof roomMemberSchema>;

export const memberListResponseSchema = z.strictObject({
  members: z.array(roomMemberSchema).max(MEMBER_LIST_PAGE_SIZE),
  nextCursor: listCursorSchema.nullable(),
});

export const roomRenamedResponseSchema = z.strictObject({
  id: uuidV4Schema,
  name: z.string(),
  updatedAt: isoTimestampSchema,
});

export const roomDeletedResponseSchema = z.strictObject({ status: z.literal('deleting') });

export const memberRoleChangedResponseSchema = z.strictObject({ userId: uuidV4Schema, role: roomRoleSchema });

/** The room is write-locked until an OWNER or ADMIN completes a rekey (ADR-013, DF-10). */
export const memberRemovedResponseSchema = z.strictObject({
  userId: uuidV4Schema,
  status: z.literal('REMOVED'),
  rekeyRequired: z.literal(true),
});

export const ownershipTransferredResponseSchema = z.strictObject({
  ownerUserId: uuidV4Schema,
  formerOwnerRole: z.literal('ADMIN'),
});
