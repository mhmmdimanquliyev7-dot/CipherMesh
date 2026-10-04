/**
 * Authentication constants shared by the API and the web client (Phase 3).
 * Design: docs/security/authentication-security.md, docs/security/session-and-csrf.md.
 * The account password is unrelated to the future Vault Passphrase (CD-01): nothing here may be
 * reused for vault key derivation.
 */

/** Account password policy (CP-06), counted in Unicode code points after NFKC normalization. */
export const PASSWORD_POLICY = Object.freeze({ minLength: 12, maxLength: 128 });

/** Reasons a password is refused. Shown to the user; they never contain the password. */
export const PasswordProblem = {
  TOO_SHORT: 'password_too_short',
  TOO_LONG: 'password_too_long',
  COMMON: 'password_common',
  CONTAINS_IDENTITY: 'password_contains_identity',
  MALFORMED: 'password_malformed',
} as const;
export type PasswordProblem = (typeof PasswordProblem)[keyof typeof PasswordProblem];

export const EMAIL_MAX_LENGTH = 254;
export const DISPLAY_NAME_MAX_LENGTH = 80;

/** Cookie names. The `__Host-` prefix forces Secure, Path=/ and no Domain (session-and-csrf.md). */
export const SESSION_COOKIE = '__Host-cm_session';
export const PREAUTH_COOKIE = '__Host-cm_preauth';

/** TOTP codes are six digits (CP-09). */
export const TOTP_CODE_PATTERN = /^[0-9]{6}$/;

/** Recovery codes (CP-10): 20 Crockford base32 characters (100 bits), shown in groups of five. */
export const RECOVERY_CODE_COUNT = 10;
