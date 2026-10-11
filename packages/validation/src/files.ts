import { AES_GCM, FILES, SHA256_BYTES, SUITE } from '@ciphermesh/crypto/params';
import { FILE_LIMITS, FILE_LIST_PAGE_SIZE } from '@ciphermesh/shared';
import { listCursorSchema } from './list';
import { keyVersionSchema } from './room-keys';
import { base64Url, isoTimestampSchema, uuidV4Schema } from './schemas';
import { z } from './zod';

/**
 * Encrypted file schemas (Phase 7, CM-T037 to CM-T041, DF-07, DF-08). Every request object is
 * strict: no field can carry a file name, MIME type, plaintext hash, FEK, room key or an owner,
 * uploader or role claim, and anything unknown is rejected (INV-01, INV-16, OL-04). Sizes follow
 * CP-19 and the database constraints; the API decodes each value strictly.
 */

const ivSchema = base64Url(AES_GCM.ivBytes);
/** A manifest holds at least one byte of JSON plus the tag; its upper bound is FILE_LIMITS. */
const manifestSchema = base64Url(AES_GCM.tagBytes + 1, FILE_LIMITS.maxManifestCiphertextBytes);
const ciphertextSizeSchema = z.number().int().min(AES_GCM.tagBytes).max(FILE_LIMITS.maxCiphertextBytes);
const sha256Schema = base64Url(SHA256_BYTES);

/**
 * A presigned storage URL: absolute http(s), no user information, no whitespace or fragment, and
 * bounded. The page's CSP connect-src decides which origin it may actually reach.
 */
const presignedUrlSchema = z
  .string()
  .max(4096)
  .regex(/^https?:\/\/[A-Za-z0-9.:[\]-]+\/[^\s#]*$/, { message: 'Expected an absolute http(s) URL' });

export const fileParamsSchema = z.strictObject({ roomId: uuidV4Schema, fileId: uuidV4Schema });

export const fileListQuerySchema = z.strictObject({ cursor: listCursorSchema.optional() });

// ------------------------------------------------------------------------------------- requests

/** POST /rooms/{roomId}/files (AZ-16, CM-T038): the encrypted record; the bytes go to storage. */
export const fileUploadRequestSchema = z.strictObject({
  /** Chosen by the uploader's browser: it is part of every context of the file (CD-08). */
  fileId: uuidV4Schema,
  /** Must be the room's current key version (PC-16, KEY_VERSION_STALE). */
  keyVersion: keyVersionSchema,
  suite: z.literal(SUITE),
  wrappedFek: base64Url(FILES.wrappedFekBytes),
  fekIv: ivSchema,
  manifest: manifestSchema,
  manifestIv: ivSchema,
  contentIv: ivSchema,
  ciphertextSize: ciphertextSizeSchema,
  ciphertextSha256: sha256Schema,
  /** Required in CONFIDENTIAL and RESTRICTED rooms, bounded by the profile (PC-08). */
  expiresAt: isoTimestampSchema.nullable(),
});

// ------------------------------------------------------------------------------------ responses

/** What a member needs to decrypt a file. Withheld from VIEWERs in RESTRICTED rooms (PC-12). */
const fileKeyMaterialSchema = z.strictObject({
  wrappedFek: base64Url(FILES.wrappedFekBytes),
  fekIv: ivSchema,
  manifest: manifestSchema,
  manifestIv: ivSchema,
  contentIv: ivSchema,
});

/**
 * One file as the API projects it: server-side metadata (sizes, times, key version and the hash
 * of the ciphertext), plus the key material when the caller may have it. No file name, type or
 * plaintext hash exists on the server to project (INV-16).
 */
export const fileRecordSchema = z.strictObject({
  id: uuidV4Schema,
  uploaderId: uuidV4Schema,
  keyVersion: keyVersionSchema,
  suite: z.literal(SUITE),
  status: z.enum(['PENDING_UPLOAD', 'AVAILABLE']),
  ciphertextSize: ciphertextSizeSchema,
  ciphertextSha256: sha256Schema,
  expiresAt: isoTimestampSchema.nullable(),
  createdAt: isoTimestampSchema,
  uploadedAt: isoTimestampSchema.nullable(),
  keyMaterial: fileKeyMaterialSchema.nullable(),
});
export type FileRecordView = z.infer<typeof fileRecordSchema>;

export const fileListResponseSchema = z.strictObject({
  files: z.array(fileRecordSchema).max(FILE_LIST_PAGE_SIZE),
  nextCursor: listCursorSchema.nullable(),
});

export const fileResponseSchema = z.strictObject({ file: fileRecordSchema });

/** A presigned capability for one object and one method, valid until `expiresAt` (CP-20, OL-07). */
const storageCapabilitySchema = z.strictObject({ url: presignedUrlSchema, expiresAt: isoTimestampSchema });

export const fileUploadResponseSchema = z.strictObject({
  file: fileRecordSchema,
  /** PUT exactly `file.ciphertextSize` bytes of ciphertext to this URL. */
  upload: storageCapabilitySchema,
});

export const fileDownloadResponseSchema = z.strictObject({ download: storageCapabilitySchema });

export const fileDeletedResponseSchema = z.strictObject({ status: z.literal('DELETED') });
