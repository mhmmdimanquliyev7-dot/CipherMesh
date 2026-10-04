import { DISPLAY_NAME_MAX_LENGTH, EMAIL_MAX_LENGTH, TOTP_CODE_PATTERN } from '@ciphermesh/shared';
import { uuidV4Schema } from './schemas';
import { z } from './zod';

/**
 * Authentication request and response schemas (Phase 3). Every object is strict, so fields such
 * as `platformRole`, `status`, `mfaEnabled` or `passwordHash` in a request are rejected rather
 * than ignored (mass assignment). Normalization happens here, once, at the trust boundary.
 */

/** Unicode NFKC, trimmed, lower case. Email addresses are identifiers, not verified (T-35). */
export function normalizeEmail(value: string): string {
  return value.normalize('NFKC').trim().toLowerCase();
}

/** Unicode NFKC and trimmed. Control characters are refused, not stripped. */
export function normalizeDisplayName(value: string): string {
  return value.normalize('NFKC').trim();
}

// Raw input bound before normalization; the password policy (CP-06) checks the real limits
// after NFKC normalization on the server. Nothing is ever truncated.
const RAW_PASSWORD_MAX = 1024;
const passwordInput = z.string().min(1).max(RAW_PASSWORD_MAX);

export const emailSchema = z
  .string()
  .max(EMAIL_MAX_LENGTH * 2)
  .transform(normalizeEmail)
  .pipe(z.email().max(EMAIL_MAX_LENGTH));

/** Login accepts any identifier string, so malformed input fails like a wrong password. */
const loginIdentifier = z
  .string()
  .min(1)
  .max(EMAIL_MAX_LENGTH * 2)
  .transform(normalizeEmail);

export const displayNameSchema = z
  .string()
  .max(DISPLAY_NAME_MAX_LENGTH * 2)
  .transform(normalizeDisplayName)
  .pipe(
    z
      .string()
      .min(1)
      .max(DISPLAY_NAME_MAX_LENGTH)
      .refine((v) => !/\p{Cc}/u.test(v), { message: 'Control characters are not allowed' }),
  );

export const totpCodeSchema = z.string().regex(TOTP_CODE_PATTERN);

export const registerRequestSchema = z.strictObject({
  email: emailSchema,
  displayName: displayNameSchema,
  password: passwordInput,
});

export const loginRequestSchema = z.strictObject({ email: loginIdentifier, password: passwordInput });

export const mfaVerifyRequestSchema = z.strictObject({ code: totpCodeSchema });

export const recoveryLoginRequestSchema = z.strictObject({ recoveryCode: z.string().min(1).max(64) });

export const stepUpRequestSchema = z.strictObject({ password: passwordInput, code: totpCodeSchema.optional() });

export const changePasswordRequestSchema = z.strictObject({
  currentPassword: passwordInput,
  newPassword: passwordInput,
  code: totpCodeSchema.optional(),
});

export const totpConfirmRequestSchema = z.strictObject({ code: totpCodeSchema });

export const sessionRevokeRequestSchema = z.strictObject({ sessionId: uuidV4Schema });

export const adminUserRequestSchema = z.strictObject({ userId: uuidV4Schema });

/** For state-changing requests that carry no data; still JSON (INV-19). */
export const emptyBodySchema = z.strictObject({});

// Responses: explicit projections. No hashes, digests, tokens, secrets or internal counters.

export const statusOkResponseSchema = z.strictObject({ status: z.literal('ok') });

export const registerResponseSchema = z.strictObject({ status: z.literal('registered') });

export const loginResponseSchema = z.strictObject({ status: z.enum(['authenticated', 'mfa_required']) });

const isoTimestamp = z.iso.datetime({ offset: false, precision: 3 });

export const sessionInfoResponseSchema = z.strictObject({
  user: z.strictObject({
    id: uuidV4Schema,
    email: z.string(),
    displayName: z.string(),
    platformRole: z.enum(['USER', 'PLATFORM_ADMIN']),
    mfaEnabled: z.boolean(),
  }),
  session: z.strictObject({
    authenticatedAt: isoTimestamp,
    mfaVerifiedAt: isoTimestamp.nullable(),
    stepUpAt: isoTimestamp.nullable(),
    idleExpiresAt: isoTimestamp,
    absoluteExpiresAt: isoTimestamp,
  }),
});
export type SessionInfoResponse = z.infer<typeof sessionInfoResponseSchema>;

export const sessionListResponseSchema = z.strictObject({
  sessions: z.array(
    z.strictObject({
      id: uuidV4Schema,
      current: z.boolean(),
      createdAt: isoTimestamp,
      lastSeenAt: isoTimestamp,
      userAgent: z.string().nullable(),
      ipAddress: z.string().nullable(),
    }),
  ),
});

export const totpEnrollResponseSchema = z.strictObject({
  /** Shown once, for the QR code and manual entry. Never stored by the client. */
  otpauthUri: z.string().startsWith('otpauth://totp/'),
  secret: z.string().regex(/^[A-Z2-7]+$/),
});

export const recoveryCodesResponseSchema = z.strictObject({
  /** Shown once. Only SHA-256 digests are stored. */
  recoveryCodes: z.array(z.string().regex(/^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}$/)).length(10),
});

export const stepUpResponseSchema = z.strictObject({ status: z.literal('ok'), stepUpAt: isoTimestamp });
