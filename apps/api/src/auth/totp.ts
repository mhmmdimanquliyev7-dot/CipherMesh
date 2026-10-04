import { randomBytes } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';

/**
 * TOTP (RFC 6238) through the `otpauth` library (LIB-06), with the CP-09 parameters:
 * HMAC-SHA-1, 6 digits, 30-second step, a 160-bit secret from the server CSPRNG, and a window of
 * plus or minus one step (about 90 seconds in total) for clock drift. Replay protection is the
 * caller's job: each accepted time step is stored and a step at or below it is refused.
 * The server clock must be NTP-synchronized (deployment-architecture.md).
 */
export const TOTP_PARAMETERS = Object.freeze({
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  window: 1,
  secretBytes: 20,
  issuer: 'CipherMesh',
});

export function generateTotpSecret(): Buffer {
  return randomBytes(TOTP_PARAMETERS.secretBytes);
}

const secretOf = (bytes: Buffer): Secret =>
  new Secret({ buffer: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });

/** The enrollment URI for authenticator apps. Shown once; never logged or stored. */
export function totpEnrollment(secret: Buffer, accountLabel: string): { uri: string; base32: string } {
  const totp = new TOTP({
    issuer: TOTP_PARAMETERS.issuer,
    label: accountLabel,
    algorithm: TOTP_PARAMETERS.algorithm,
    digits: TOTP_PARAMETERS.digits,
    period: TOTP_PARAMETERS.period,
    secret: secretOf(secret),
  });
  return { uri: totp.toString(), base32: totp.secret.base32 };
}

/** Returns the matched time step, or undefined. The library compares codes in constant time. */
export function verifyTotp(secret: Buffer, code: string, nowMs: number): number | undefined {
  const delta = TOTP.validate({
    token: code,
    secret: secretOf(secret),
    algorithm: TOTP_PARAMETERS.algorithm,
    digits: TOTP_PARAMETERS.digits,
    period: TOTP_PARAMETERS.period,
    timestamp: nowMs,
    window: TOTP_PARAMETERS.window,
  });
  if (delta === null) return undefined;
  return TOTP.counter({ period: TOTP_PARAMETERS.period, timestamp: nowMs }) + delta;
}

/** Test and tooling helper: the code for a time step. */
export function totpCodeAt(secret: Buffer, nowMs: number): string {
  return TOTP.generate({
    secret: secretOf(secret),
    algorithm: TOTP_PARAMETERS.algorithm,
    digits: TOTP_PARAMETERS.digits,
    period: TOTP_PARAMETERS.period,
    timestamp: nowMs,
  });
}
