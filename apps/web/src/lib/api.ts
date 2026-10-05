import { CIPHERMESH_REQUEST_HEADER, CIPHERMESH_REQUEST_HEADER_VALUE } from '@ciphermesh/shared';
import { apiErrorBodySchema, type z } from '@ciphermesh/validation';
import { publicEnv } from '../config/public-env';

/**
 * The only way the web client talks to the API (session-and-csrf.md section 8):
 * - same-origin fetch() only, never HTML form submissions, so browsers send the real Origin;
 * - JSON bodies and the X-CipherMesh-Request header on every state-changing request;
 * - the session lives in an HttpOnly cookie the page cannot read; nothing is stored in
 *   localStorage, sessionStorage or IndexedDB;
 * - every response is validated against the shared schema before use.
 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly issues: readonly { path: string; code: string }[] = [],
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/**
 * Called when the API reports that the session is gone (expired, revoked, account disabled). The
 * vault controller registers here so it can lock at once: a valid server session is a
 * precondition for keeping the vault unlocked in this tab (CP-22).
 */
let unauthenticatedListener: (() => void) | undefined;
export function onUnauthenticated(listener: (() => void) | undefined): void {
  unauthenticatedListener = listener;
}

export async function api<S extends z.ZodType>(
  method: 'GET' | 'POST',
  path: string,
  schema: S,
  body?: unknown,
): Promise<z.output<S>> {
  const response = await fetch(`${publicEnv.apiBasePath}${path}`, {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    headers:
      method === 'POST'
        ? { 'content-type': 'application/json', [CIPHERMESH_REQUEST_HEADER]: CIPHERMESH_REQUEST_HEADER_VALUE }
        : {},
    ...(method === 'POST' ? { body: JSON.stringify(body ?? {}) } : {}),
  });
  const data: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const error = apiErrorBodySchema.safeParse(data);
    if (error.success) {
      if (response.status === 401 && error.data.error.code === 'UNAUTHENTICATED') unauthenticatedListener?.();
      throw new ApiError(response.status, error.data.error.code, error.data.error.message, error.data.error.issues);
    }
    throw new ApiError(response.status, 'UNKNOWN', 'Unexpected response from the server');
  }
  const parsed = schema.safeParse(data);
  if (!parsed.success) throw new ApiError(response.status, 'INVALID_RESPONSE', 'Unexpected response from the server');
  return parsed.data;
}

/** Human-readable text for the password policy issue codes (CP-06). */
export const PASSWORD_PROBLEM_TEXT: Readonly<Record<string, string>> = {
  password_too_short: 'Use at least 12 characters.',
  password_too_long: 'Use at most 128 characters.',
  password_common: 'This password appears in lists of breached passwords. Choose another one.',
  password_contains_identity: 'Do not build the password from your email address, name or the product name.',
  password_malformed: 'The password contains characters that cannot be processed.',
};

export function describeError(error: unknown): string {
  if (!(error instanceof ApiError)) return 'The request failed. Check your connection and try again.';
  if (error.code === 'PASSWORD_REJECTED') {
    return error.issues.map((issue) => PASSWORD_PROBLEM_TEXT[issue.code] ?? 'The password was rejected.').join(' ');
  }
  if (error.code === 'RATE_LIMITED') return 'Too many attempts. Wait a little and try again.';
  return error.message;
}

/** Reads a text field of a submitted form; file inputs or missing fields give ''. */
export function formText(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === 'string' ? value : '';
}
