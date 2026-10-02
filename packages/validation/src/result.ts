import type { ValidationIssue } from '@ciphermesh/shared';
import type { z } from 'zod';

export type ParseResult<T> =
  | { readonly success: true; readonly data: T }
  | { readonly success: false; readonly issues: readonly ValidationIssue[] };

/**
 * Converts zod issues into paths and issue codes only. Rejected values and zod's
 * human-readable messages are dropped, so validation errors can never echo a
 * password, token or key back to a client or into a log (INV-10).
 */
export function toValidationIssues(error: z.ZodError): ValidationIssue[] {
  return error.issues.map((issue) => ({
    path: issue.path.length === 0 ? '(root)' : issue.path.map(String).join('.'),
    code: issue.code,
  }));
}

export function parseWith<S extends z.ZodType>(schema: S, input: unknown): ParseResult<z.output<S>> {
  const result = schema.safeParse(input);
  return result.success
    ? { success: true, data: result.data }
    : { success: false, issues: toValidationIssues(result.error) };
}
