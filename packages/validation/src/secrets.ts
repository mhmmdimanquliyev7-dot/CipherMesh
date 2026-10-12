import { AES_GCM, SUITE } from '@ciphermesh/crypto/params';
import { SECRET_LIMITS, SECRET_LIST_PAGE_SIZE, SECRET_STATUSES } from '@ciphermesh/shared';
import { listCursorSchema } from './list';
import { base64Url, isoTimestampSchema, uuidV4Schema } from './schemas';
import { z } from './zod';

/**
 * Recipient-bound secret schemas (Phase 9, CM-T043, CM-T044, DF-09). Every request object is
 * strict: no field can carry secret text, a SEK, a room key, a sender, a status or a role claim,
 * and anything unknown is rejected (INV-01, INV-16, OL-04). Sizes follow CP-29 and the database
 * constraints; the API decodes each value strictly. The reveal request is an empty JSON object: a
 * POST, never a GET, so a link preview or prefetch cannot consume a secret (INV-13).
 */

const ivSchema = base64Url(AES_GCM.ivBytes);
const wrappedSekSchema = base64Url(SECRET_LIMITS.wrappedSekBytes);
const ciphertextSchema = base64Url(SECRET_LIMITS.minCiphertextBytes, SECRET_LIMITS.maxCiphertextBytes);

export const secretParamsSchema = z.strictObject({ roomId: uuidV4Schema, secretId: uuidV4Schema });

export const secretListQuerySchema = z.strictObject({ cursor: listCursorSchema.optional() });

// ------------------------------------------------------------------------------------- requests

/** POST /rooms/{roomId}/secrets (AZ-23): one secret for one recipient, encrypted in the sender's browser. */
export const secretCreateRequestSchema = z.strictObject({
  /** Chosen by the sender's browser: it is part of both contexts of the secret (CD-08). */
  secretId: uuidV4Schema,
  /** Must be an ACTIVE member other than the sender (OL-03). */
  recipientUserId: uuidV4Schema,
  /** Must be the recipient's current ACTIVE identity key: the one the SEK was wrapped to. */
  recipientKeyId: uuidV4Schema,
  suite: z.literal(SUITE),
  wrappedSek: wrappedSekSchema,
  payloadIv: ivSchema,
  ciphertext: ciphertextSchema,
  /** Required; within the profile's lifetime (PC-09) and at least the minimum (D-09-03). */
  expiresAt: isoTimestampSchema,
  /** Mandatory in RESTRICTED rooms (PC-10). */
  burnAfterReading: z.boolean(),
});

// ------------------------------------------------------------------------------------ responses

/**
 * The metadata of one secret as the list projects it (AZ-32, OL-14). There is no text on the
 * server to project, and no list carries the payload or the wrapped SEK (INV-01).
 */
export const secretMetadataSchema = z.strictObject({
  id: uuidV4Schema,
  senderId: uuidV4Schema,
  recipientUserId: uuidV4Schema,
  recipientKeyId: uuidV4Schema,
  status: z.enum(SECRET_STATUSES),
  burnAfterReading: z.boolean(),
  expiresAt: isoTimestampSchema,
  createdAt: isoTimestampSchema,
  revealedAt: isoTimestampSchema.nullable(),
  destroyedAt: isoTimestampSchema.nullable(),
});
export type SecretMetadataView = z.infer<typeof secretMetadataSchema>;

export const secretListResponseSchema = z.strictObject({
  secrets: z.array(secretMetadataSchema).max(SECRET_LIST_PAGE_SIZE),
  nextCursor: listCursorSchema.nullable(),
});

export const secretCreatedResponseSchema = z.strictObject({ secret: secretMetadataSchema });

/**
 * POST /rooms/{roomId}/secrets/{secretId}/reveal (AZ-24): the payload and the wrapped SEK, released
 * to the recipient in the transaction that burns a burn-after-reading secret (at most once).
 */
export const secretRevealResponseSchema = z.strictObject({
  secret: secretMetadataSchema,
  ciphertext: z.strictObject({
    suite: z.literal(SUITE),
    wrappedSek: wrappedSekSchema,
    payloadIv: ivSchema,
    ciphertext: ciphertextSchema,
  }),
});
export type SecretRevealView = z.infer<typeof secretRevealResponseSchema>;

export const secretRevokedResponseSchema = z.strictObject({ status: z.literal('REVOKED') });
