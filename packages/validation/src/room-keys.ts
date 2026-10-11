import { ECDSA, ROOM_KEYS, RSA_OAEP, SUITE } from '@ciphermesh/crypto/params';
import { ASSIGNABLE_ROOM_ROLES, INVITATION_LIST_PAGE_SIZE, ROOM_ROLES, SECURITY_PROFILES } from '@ciphermesh/shared';
import { listCursorSchema } from './list';
import { base64Url, isoTimestampSchema, uuidV4Schema } from './schemas';
import { fingerprintSchema, publicIdentitySchema } from './vault';
import { z } from './zod';

/**
 * Room key, signed statement and invitation schemas (Phase 6, CM-T033 to CM-T036, CM-T085). Every
 * request object is strict. No field can carry room key material: commitments are 32-byte public
 * values, envelopes are 384-byte RSA-OAEP ciphertexts and signatures are 64-byte ECDSA values, and
 * an extra field (a raw key, an RWK, a Room Safety Code, a caller ID or a role claim) is rejected
 * as unknown (INV-01, INV-04, INV-18, OL-04). The API decodes each value strictly and checks the
 * signatures with @ciphermesh/crypto/identity.
 */

const signatureSchema = base64Url(ECDSA.signatureBytes);
const commitmentSchema = base64Url(ROOM_KEYS.commitmentBytes);
const envelopeSchema = base64Url(RSA_OAEP.ciphertextBytes);
/** Key versions are positive integers within PostgreSQL's integer range. */
export const keyVersionSchema = z.number().int().min(1).max(2_147_483_647);
const roomRoleSchema = z.enum(ROOM_ROLES);
const keyStateSchema = z.enum(['ACTIVE', 'REKEY_REQUIRED', 'REKEYING']);

// ------------------------------------------------------------------------------------- requests

/** What room creation adds to the name and profile: key version 1 (CM-T033, DF-05). */
export const roomCreationKeysSchema = z.strictObject({
  /** The creator's own ACTIVE identity key, which receives the envelope and signs both statements. */
  creatorKeyId: uuidV4Schema,
  commitment: commitmentSchema,
  envelope: envelopeSchema,
  genesisSignature: signatureSchema,
  keyVersionSignature: signatureSchema,
});

/** A membership grant signed by the caller for the subject's ACTIVE identity key (ADR-015). */
export const grantProofSchema = z.strictObject({ subjectKeyId: uuidV4Schema, signature: signatureSchema });

/** POST /rooms/{roomId}/invitations (AZ-06, CM-T034, DF-06). */
export const invitationCreateRequestSchema = z.strictObject({
  inviteeUserId: uuidV4Schema,
  inviteeKeyId: uuidV4Schema,
  role: z.enum(ASSIGNABLE_ROOM_ROLES),
  /** The fingerprint the inviter compared out of band: required in RESTRICTED rooms (PC-05). */
  confirmedFingerprint: fingerprintSchema.nullable(),
  /** cm.room.membership-grant signed by the inviter for the invitee's key and the role. */
  grantSignature: signatureSchema,
  envelopes: z
    .array(z.strictObject({ keyVersion: keyVersionSchema, wrappedKey: envelopeSchema }))
    .min(1)
    .max(ROOM_KEYS.maxRecipients),
});

/** POST /rooms/{roomId}/key-reports (AZ-29): a refused room key, the version only. */
export const keyReportRequestSchema = z.strictObject({
  keyVersion: keyVersionSchema,
  problem: z.enum(['AUTHENTICATION_FAILED', 'COMMITMENT_MISMATCH']),
});

/**
 * POST /rooms/{roomId}/safety-code (AZ-30): a member's statement that they compared the code for
 * a version, or a mismatch report. The key version only: there is no field for the code (INV-18).
 */
export const safetyCodeRecordRequestSchema = z.strictObject({
  keyVersion: keyVersionSchema,
  result: z.enum(['MATCH', 'MISMATCH']),
});

export const invitationParamsSchema = z.strictObject({ roomId: uuidV4Schema, invitationId: uuidV4Schema });
export const ownInvitationParamsSchema = z.strictObject({ invitationId: uuidV4Schema });

// ------------------------------------------------------------------------------------ responses

const recipientSchema = z.strictObject({ userId: uuidV4Schema, keyId: uuidV4Schema });

/** A public identity with its user, for verifying signatures (current or retired keys). */
export const signerIdentitySchema = publicIdentitySchema.extend({ userId: uuidV4Schema });

/** GET /rooms/{roomId}/key-versions (AZ-15): every statement a member needs to verify a key. */
export const keyVersionsResponseSchema = z.strictObject({
  currentKeyVersion: keyVersionSchema,
  keyState: keyStateSchema,
  /** Null only for rooms created before Phase 6, which have no key version (L-43). */
  genesis: z
    .strictObject({
      creatorUserId: uuidV4Schema,
      creatorKeyId: uuidV4Schema,
      suite: z.literal(SUITE),
      signature: signatureSchema,
    })
    .nullable(),
  keyVersions: z
    .array(
      z.strictObject({
        keyVersion: keyVersionSchema,
        status: z.enum(['ACTIVE', 'RETIRED', 'DESTROYED']),
        suite: z.literal(SUITE),
        commitment: commitmentSchema,
        previousCommitment: commitmentSchema.nullable(),
        creatorUserId: uuidV4Schema,
        creatorKeyId: uuidV4Schema,
        recipients: z.array(recipientSchema).min(1).max(ROOM_KEYS.maxRecipients),
        signature: signatureSchema,
        createdAt: isoTimestampSchema,
      }),
    )
    .max(1_000),
  grants: z
    .array(
      z.strictObject({
        subjectUserId: uuidV4Schema,
        subjectKeyId: uuidV4Schema,
        role: roomRoleSchema,
        grantorUserId: uuidV4Schema,
        grantorKeyId: uuidV4Schema,
        signature: signatureSchema,
      }),
    )
    .max(1_000),
  identities: z.array(signerIdentitySchema).max(500),
});
export type KeyVersionsResponse = z.infer<typeof keyVersionsResponseSchema>;

/** GET /rooms/{roomId}/envelopes (AZ-12, OL-05): the caller's own ACTIVE envelopes only. */
export const envelopesResponseSchema = z.strictObject({
  envelopes: z
    .array(z.strictObject({ keyVersion: keyVersionSchema, recipientKeyId: uuidV4Schema, wrappedKey: envelopeSchema }))
    .max(1_000),
});
export type EnvelopesResponse = z.infer<typeof envelopesResponseSchema>;

/** GET /rooms/{roomId}/members/{userId}/identity (AZ-01): a member's current public identity. */
export const memberIdentityResponseSchema = z.strictObject({
  userId: uuidV4Schema,
  identity: publicIdentitySchema.extend({ createdAt: isoTimestampSchema }),
});
export type MemberIdentityResponse = z.infer<typeof memberIdentityResponseSchema>;

const invitationStatusSchema = z.enum(['PENDING_APPROVAL', 'PENDING', 'ACCEPTED', 'DECLINED', 'REVOKED', 'EXPIRED']);
const invitationRoleSchema = z.enum(ASSIGNABLE_ROOM_ROLES);

/** An invitation as the room's OWNER and ADMINs see it (AZ-31, OL-11). */
export const roomInvitationSchema = z.strictObject({
  id: uuidV4Schema,
  invitee: z.strictObject({ userId: uuidV4Schema, displayName: z.string(), keyId: uuidV4Schema }),
  invitedBy: z.strictObject({ userId: uuidV4Schema, displayName: z.string() }),
  role: invitationRoleSchema,
  status: invitationStatusSchema,
  fingerprintConfirmed: z.boolean(),
  approvedByUserId: uuidV4Schema.nullable(),
  expiresAt: isoTimestampSchema,
  createdAt: isoTimestampSchema,
});
export type RoomInvitation = z.infer<typeof roomInvitationSchema>;

export const roomInvitationListResponseSchema = z.strictObject({
  invitations: z.array(roomInvitationSchema).max(INVITATION_LIST_PAGE_SIZE),
  nextCursor: listCursorSchema.nullable(),
});

export const invitationCreatedResponseSchema = z.strictObject({ invitation: roomInvitationSchema });

/** An invitation as its invitee sees it (SS-03, OL-11). */
export const ownInvitationSchema = z.strictObject({
  id: uuidV4Schema,
  room: z.strictObject({ id: uuidV4Schema, name: z.string(), securityProfile: z.enum(SECURITY_PROFILES) }),
  invitedBy: z.strictObject({ userId: uuidV4Schema, displayName: z.string() }),
  role: invitationRoleSchema,
  status: z.enum(['PENDING_APPROVAL', 'PENDING']),
  inviteeKeyId: uuidV4Schema,
  expiresAt: isoTimestampSchema,
  createdAt: isoTimestampSchema,
});
export type OwnInvitation = z.infer<typeof ownInvitationSchema>;

export const ownInvitationListResponseSchema = z.strictObject({
  invitations: z.array(ownInvitationSchema).max(INVITATION_LIST_PAGE_SIZE),
  nextCursor: listCursorSchema.nullable(),
});

export const invitationAcceptedResponseSchema = z.strictObject({
  roomId: uuidV4Schema,
  role: invitationRoleSchema,
  status: z.literal('ACCEPTED'),
});
export const invitationClosedResponseSchema = z.strictObject({ status: z.enum(['DECLINED', 'REVOKED']) });
export const invitationApprovedResponseSchema = z.strictObject({ status: z.literal('PENDING') });
export const recordedResponseSchema = z.strictObject({ status: z.literal('recorded') });
