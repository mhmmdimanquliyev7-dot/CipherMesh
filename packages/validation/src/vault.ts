import { ECDSA, RSA_OAEP, SUITE, VAULT_KDF, VAULT_VERSION, WRAPPED_KEY_BYTES } from '@ciphermesh/crypto/params';
import { emailSchema } from './auth';
import { isoTimestampSchema, uuidV4Schema } from './schemas';
import { z } from './zod';

/**
 * Vault and public-key directory schemas (Phase 4, CM-T025 to CM-T028; docs/crypto/vault.md).
 * Sizes and parameter ranges come from the parameter register in packages/crypto, so the API,
 * the browser and the database constraints use the same numbers. These schemas check shapes;
 * the API then decodes every value strictly and verifies the public identity cryptographically
 * with the same code the browser uses (@ciphermesh/crypto/identity).
 *
 * No schema here has a field for a passphrase, a vault-derived key or a plaintext private key:
 * such a field would be rejected as unknown by the strict objects (INV-01).
 */

/** Unpadded base64url of exactly or between the given byte lengths. */
function base64Url(minBytes: number, maxBytes: number = minBytes) {
  const length = (bytes: number): number => Math.ceil((bytes * 4) / 3);
  return z
    .string()
    .min(length(minBytes))
    .max(length(maxBytes))
    .regex(/^[A-Za-z0-9_-]*$/);
}

export const fingerprintSchema = z.string().regex(/^[0-9a-f]{64}$/);

export const publicIdentitySchema = z.strictObject({
  keyId: uuidV4Schema,
  suite: z.literal(SUITE),
  encryptionPublicKey: base64Url(RSA_OAEP.spkiBytes),
  signingPublicKey: base64Url(ECDSA.spkiBytes),
  bindingSignature: base64Url(ECDSA.signatureBytes),
  fingerprint: fingerprintSchema,
});

export const vaultKdfSchema = z.strictObject({
  algorithm: z.literal(VAULT_KDF.algorithm),
  version: z.literal(VAULT_KDF.version),
  memoryKiB: z.number().int().min(VAULT_KDF.floor.memoryKiB).max(VAULT_KDF.ceiling.memoryKiB),
  iterations: z.number().int().min(VAULT_KDF.floor.iterations).max(VAULT_KDF.ceiling.iterations),
  parallelism: z.number().int().min(VAULT_KDF.floor.parallelism).max(VAULT_KDF.ceiling.parallelism),
  salt: base64Url(VAULT_KDF.saltBytes),
});

const sealedKeySchema = (bounds: { readonly min: number; readonly max: number }) =>
  z.strictObject({ iv: base64Url(12), ciphertext: base64Url(bounds.min, bounds.max) });

/** A complete vault record: public identity, KDF metadata and the two wrapped private keys. */
export const vaultSchema = z.strictObject({
  vaultVersion: z.literal(VAULT_VERSION),
  identity: publicIdentitySchema,
  kdf: vaultKdfSchema,
  wrappedEncryptionKey: sealedKeySchema(WRAPPED_KEY_BYTES.encryption),
  wrappedSigningKey: sealedKeySchema(WRAPPED_KEY_BYTES.signing),
});
export type VaultPayload = z.infer<typeof vaultSchema>;

/** POST /api/vault (DF-03). */
export const vaultCreateRequestSchema = vaultSchema;

export const vaultCreatedResponseSchema = z.strictObject({
  keyId: uuidV4Schema,
  fingerprint: fingerprintSchema,
  createdAt: isoTimestampSchema,
});

/** GET /api/vault: the caller's own vault only (OL-10). */
export const vaultResponseSchema = z.strictObject({
  vault: vaultSchema,
  createdAt: isoTimestampSchema,
  rewrappedAt: isoTimestampSchema.nullable(),
});
export type VaultResponse = z.infer<typeof vaultResponseSchema>;

/** POST /api/vault/rewrap (CM-T028): signed by the identity's signing key (ADR-015 section 3). */
export const vaultRewrapRequestSchema = z.strictObject({
  keyId: uuidV4Schema,
  previousKdfSalt: base64Url(VAULT_KDF.saltBytes),
  kdf: vaultKdfSchema,
  wrappedEncryptionKey: sealedKeySchema(WRAPPED_KEY_BYTES.encryption),
  wrappedSigningKey: sealedKeySchema(WRAPPED_KEY_BYTES.signing),
  signature: base64Url(ECDSA.signatureBytes),
});

export const vaultRewrapResponseSchema = z.strictObject({ status: z.literal('ok'), rewrappedAt: isoTimestampSchema });

/** POST /api/vault/reset: a new identity replaces a lost one (the old one cannot sign this). */
export const vaultResetRequestSchema = z.strictObject({
  supersedesKeyId: uuidV4Schema,
  vault: vaultSchema,
});

export const vaultResetResponseSchema = z.strictObject({
  keyId: uuidV4Schema,
  fingerprint: fingerprintSchema,
  createdAt: isoTimestampSchema,
  otherSessionsRevoked: z.number().int().min(0),
});

/** POST /api/directory/lookup (SS-05, CM-T027): exact email match, POST so no email enters a URL. */
export const directoryLookupRequestSchema = z.strictObject({ email: emailSchema });

export const directoryEntrySchema = z.strictObject({
  user: z.strictObject({
    id: uuidV4Schema,
    displayName: z.string(),
    /** Email addresses are never verified in the baseline (T-35); clients must say so. */
    emailVerified: z.literal(false),
    accountCreatedAt: isoTimestampSchema,
  }),
  identity: publicIdentitySchema.extend({ createdAt: isoTimestampSchema }),
});
export type DirectoryEntry = z.infer<typeof directoryEntrySchema>;
