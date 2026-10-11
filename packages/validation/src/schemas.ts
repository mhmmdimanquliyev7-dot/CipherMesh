import { ErrorCode, isUuidV4 } from '@ciphermesh/shared';
import { z } from './zod';

/**
 * Every object schema at a trust boundary is strict: unknown keys are rejected,
 * including `__proto__`, `constructor` and `prototype` that JSON.parse creates as own keys.
 */
export const uuidV4Schema = z.string().refine(isUuidV4, { message: 'Expected a UUID version 4' });

/**
 * Unpadded base64url of exactly or between the given byte lengths. The API decodes every value
 * strictly afterwards (canonical form, exact size); this schema rejects the wrong alphabet and
 * impossible lengths at the boundary.
 */
export function base64Url(minBytes: number, maxBytes: number = minBytes) {
  const length = (bytes: number): number => Math.ceil((bytes * 4) / 3);
  return z
    .string()
    .min(length(minBytes))
    .max(length(maxBytes))
    .regex(/^[A-Za-z0-9_-]*$/);
}

/** ISO 8601 UTC with milliseconds, the timestamp format of every API response. */
export const isoTimestampSchema = z.iso.datetime({ offset: false, precision: 3 });

/** Used by routes that accept no query parameters. */
export const emptyQuerySchema = z.strictObject({});

export const healthResponseSchema = z.strictObject({ status: z.literal('ok') });
export type HealthResponse = z.infer<typeof healthResponseSchema>;

export const readinessResponseSchema = z.strictObject({ status: z.enum(['ready', 'not-ready']) });
export type ReadinessResponse = z.infer<typeof readinessResponseSchema>;

const errorCodeSchema = z.enum(Object.values(ErrorCode) as [ErrorCode, ...ErrorCode[]]);

export const apiErrorBodySchema = z.strictObject({
  error: z.strictObject({
    code: errorCodeSchema,
    message: z.string(),
    requestId: uuidV4Schema,
    issues: z.array(z.strictObject({ path: z.string(), code: z.string() })).optional(),
  }),
});
