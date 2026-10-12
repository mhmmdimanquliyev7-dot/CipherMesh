import { ECDSA, ROOM_KEYS, RSA_OAEP } from '@ciphermesh/crypto/params';
import { REKEY_REASONS, ROOM_ROLES } from '@ciphermesh/shared';
import { keyVersionSchema, signerIdentitySchema } from './room-keys';
import { base64Url, isoTimestampSchema, uuidV4Schema } from './schemas';
import { fingerprintSchema } from './vault';
import { z } from './zod';

/**
 * Key rotation schemas (Phase 11, CM-T050 to CM-T053, ADR-013, DF-10). Requests are strict: no field
 * can carry room key material (only the 32-byte public commitment, 64-byte signatures and 384-byte
 * RSA-OAEP envelopes), and nothing a client sends names the recipients' roles, the snapshot, the
 * epoch or the base version: the server takes those from its own records (OL-13, INV-01, INV-04).
 */

const signatureSchema = base64Url(ECDSA.signatureBytes);
const commitmentSchema = base64Url(ROOM_KEYS.commitmentBytes);
const envelopeSchema = base64Url(RSA_OAEP.ciphertextBytes);

export const rekeyOperationParamsSchema = z.strictObject({ roomId: uuidV4Schema, operationId: uuidV4Schema });

/** POST /rooms/{roomId}/rekey-operations/{operationId}/finalize (AZ-13, ADR-013 step 3). */
export const rekeyFinalizeRequestSchema = z.strictObject({
  targetVersion: keyVersionSchema,
  /** RKC_(v+1), the public commitment; never the key material. */
  commitment: commitmentSchema,
  /** cm.room.key-version signed by the starter's ACTIVE identity (ADR-015 section 4). */
  statementSignature: signatureSchema,
  envelopes: z
    .array(z.strictObject({ recipientUserId: uuidV4Schema, recipientKeyId: uuidV4Schema, wrappedKey: envelopeSchema }))
    .min(1)
    .max(ROOM_KEYS.maxRecipients),
});
export type RekeyFinalizeRequest = z.infer<typeof rekeyFinalizeRequestSchema>;

/** POST /rooms/{roomId}/members/{userId}/reshare (AZ-14, CM-T053): the same proofs as an invitation. */
export const reshareRequestSchema = z.strictObject({
  /** The member's current ACTIVE identity key, to which the envelopes are wrapped. */
  subjectKeyId: uuidV4Schema,
  /** The fingerprint compared out of band: required in RESTRICTED rooms (PC-05). */
  confirmedFingerprint: fingerprintSchema.nullable(),
  /** cm.room.membership-grant for that key with the member's stored role, signed by the caller. */
  grantSignature: signatureSchema,
  envelopes: z
    .array(z.strictObject({ keyVersion: keyVersionSchema, wrappedKey: envelopeSchema }))
    .min(1)
    .max(ROOM_KEYS.maxRecipients),
});

// ------------------------------------------------------------------------------------ responses

const operationSchema = z.strictObject({
  id: uuidV4Schema,
  mode: z.enum(['MANDATORY', 'MANUAL']),
  status: z.enum(['PENDING', 'COMPLETED', 'ABANDONED', 'SUPERSEDED', 'CANCELLED', 'STALE']),
  startedByUserId: uuidV4Schema,
  baseVersion: keyVersionSchema,
  targetVersion: keyVersionSchema,
  leaseExpiresAt: isoTimestampSchema,
  createdAt: isoTimestampSchema,
});
export type RekeyOperationView = z.infer<typeof operationSchema>;

const grantSchema = z.strictObject({
  subjectUserId: uuidV4Schema,
  subjectKeyId: uuidV4Schema,
  role: z.enum(ROOM_ROLES),
  grantorUserId: uuidV4Schema,
  grantorKeyId: uuidV4Schema,
  signature: signatureSchema,
});

/** POST /rooms/{roomId}/rekey-operations (AZ-13, ADR-013 step 1): the operation and its snapshot. */
export const rekeyStartedResponseSchema = z.strictObject({
  operation: operationSchema,
  /**
   * The server's recipient snapshot: the ACTIVE identity of every ACTIVE member and the key of
   * every pending invitee. The browser verifies each identity and shows it for review.
   */
  recipients: z
    .array(
      z.strictObject({
        userId: uuidV4Schema,
        displayName: z.string(),
        kind: z.enum(['MEMBER', 'INVITEE']),
        identity: signerIdentitySchema,
      }),
    )
    .min(1)
    .max(ROOM_KEYS.maxRecipients),
  /** Grants that name the recipients (memberships and invitations) and their authority chain. */
  grants: z.array(grantSchema).max(1_000),
  identities: z.array(signerIdentitySchema).max(500),
});
export type RekeyStartedResponse = z.infer<typeof rekeyStartedResponseSchema>;

export const rekeyFinalizedResponseSchema = z.strictObject({
  operationId: uuidV4Schema,
  keyVersion: keyVersionSchema,
  completedAt: isoTimestampSchema,
});

export const rekeyCancelledResponseSchema = z.strictObject({
  operationId: uuidV4Schema,
  status: z.literal('CANCELLED'),
  keyState: z.enum(['ACTIVE', 'REKEY_REQUIRED', 'REKEYING']),
});

/** GET /rooms/{roomId}/rekey-operations/current (AZ-15): the room's key state and live operation. */
export const roomKeyStateResponseSchema = z.strictObject({
  keyState: z.enum(['ACTIVE', 'REKEY_REQUIRED', 'REKEYING']),
  rekeyReasons: z.array(z.enum(REKEY_REASONS)).max(REKEY_REASONS.length),
  rekeyRequiredSince: isoTimestampSchema.nullable(),
  currentKeyVersion: keyVersionSchema,
  /** PC-14: when the current version's cryptoperiod ends; null where rotation is event-driven only. */
  cryptoperiodEndsAt: isoTimestampSchema.nullable(),
  /** True within the reminder window before the cryptoperiod ends (R6). */
  cryptoperiodReminder: z.boolean(),
  /** The PENDING operation, or null. Its lease may already have passed (closed at the next start). */
  operation: operationSchema.nullable(),
  /**
   * Members who hold no envelope of the current version for their current identity: an identity
   * changed by a vault reset, or a suspended membership of a re-enabled account (AZ-14).
   */
  membersNeedingKeys: z
    .array(z.strictObject({ userId: uuidV4Schema, reason: z.enum(['IDENTITY_CHANGED', 'SUSPENDED']) }))
    .max(ROOM_KEYS.maxRecipients),
});
export type RoomKeyStateResponse = z.infer<typeof roomKeyStateResponseSchema>;

export const roomLeftResponseSchema = z.strictObject({ status: z.literal('LEFT'), rekeyRequired: z.literal(true) });

export const reshareResponseSchema = z.strictObject({
  userId: uuidV4Schema,
  keyVersions: z.array(keyVersionSchema).min(1).max(ROOM_KEYS.maxRecipients),
  /** True when a SUSPENDED membership of a re-enabled account became ACTIVE again. */
  reinstated: z.boolean(),
});
