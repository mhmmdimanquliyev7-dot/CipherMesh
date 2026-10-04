/**
 * Stable API error codes. Clients branch on `code`, never on the message.
 * Codes are added here when a phase implements the behaviour that returns them;
 * docs/security/authorization-model.md section 7 lists the planned codes.
 */
export const ErrorCode = {
  NOT_FOUND: 'NOT_FOUND',
  INVALID_JSON: 'INVALID_JSON',
  PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE',
  UNSUPPORTED_MEDIA_TYPE: 'UNSUPPORTED_MEDIA_TYPE',
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  ORIGIN_REJECTED: 'ORIGIN_REJECTED',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

/** A validation problem: where it is and what kind. Never the rejected value (INV-10). */
export interface ValidationIssue {
  readonly path: string;
  readonly code: string;
}

/** The only error shape the API returns. */
export interface ApiErrorBody {
  readonly error: {
    readonly code: ErrorCode;
    readonly message: string;
    readonly requestId: string;
    readonly issues?: readonly ValidationIssue[];
  };
}

const CODES: ReadonlySet<string> = new Set(Object.values(ErrorCode));

export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === 'string' && CODES.has(value);
}
