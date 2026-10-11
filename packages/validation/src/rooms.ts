import {
  ASSIGNABLE_ROOM_ROLES,
  MEMBER_LIST_PAGE_SIZE,
  ROOM_LIST_PAGE_SIZE,
  ROOM_NAME_MAX_LENGTH,
  ROOM_ROLES,
  SECURITY_PROFILES,
} from '@ciphermesh/shared';
import { grantProofSchema, roomCreationKeysSchema } from './room-keys';
import { isoTimestampSchema, uuidV4Schema } from './schemas';
import { z } from './zod';

/**
 * Room request and response schemas (Phase 5, CM-T030, CM-T031). Every request object is strict,
 * so a role, owner, user, status or key field is rejected rather than ignored (OL-03, OL-04, mass
 * assignment). No request carries key material: since Phase 6, room creation carries key version
 * 1 as public values and ciphertext only (room-keys.ts). Responses are the explicit projections the
 * API may send.
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

// Keyset pagination (OL-08) lives in list.ts; re-exported here for the room routes.
export { formatListCursor, listCursorSchema, listQuerySchema, parseListCursor } from './list';
import { listCursorSchema } from './list';

// ------------------------------------------------------------------------------------- requests

export const roomCreateRequestSchema = z.strictObject({
  roomId: uuidV4Schema,
  name: roomNameSchema,
  securityProfile: securityProfileSchema,
  /** Key version 1, created in the browser (CM-T033, DF-05). Required: no new room is keyless. */
  keys: roomCreationKeysSchema,
});

export const roomRenameRequestSchema = z.strictObject({ name: roomNameSchema });

/**
 * OWNER is not assignable: ownership changes only through a transfer (AZ-05). Granting ADMIN
 * carries the OWNER's signed membership grant for the member's identity key (ADR-015 section 4);
 * other roles carry none.
 */
export const memberRoleChangeRequestSchema = z
  .strictObject({ role: z.enum(ASSIGNABLE_ROOM_ROLES), grant: grantProofSchema.optional() })
  .refine((body) => (body.role === 'ADMIN') === (body.grant !== undefined), {
    message: 'A grant is required exactly for the ADMIN role',
    path: ['grant'],
  });

/** AZ-05: the OWNER's signed grant of the OWNER role to the new owner's identity key (ADR-015). */
export const ownershipTransferRequestSchema = z.strictObject({ grant: grantProofSchema });

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
