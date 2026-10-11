import { isUuidV4 } from '@ciphermesh/shared';
import { z } from './zod';

// Keyset pagination (OL-08): the cursor is the sort key of the last item returned,
// `<ISO 8601 UTC timestamp with milliseconds>_<UUIDv4>`. It names nothing the caller has not seen.
const CURSOR = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)_(.+)$/;

export function parseListCursor(value: string): { readonly at: Date; readonly id: string } | undefined {
  const match = CURSOR.exec(value);
  if (match === null) return undefined;
  const [, iso = '', id = ''] = match;
  const at = new Date(iso);
  return !Number.isNaN(at.getTime()) && at.toISOString() === iso && isUuidV4(id) ? { at, id } : undefined;
}

export function formatListCursor(at: Date, id: string): string {
  return `${at.toISOString()}_${id}`;
}

export const listCursorSchema = z
  .string()
  .max(64)
  .refine((v) => parseListCursor(v) !== undefined, { message: 'Invalid cursor' });

export const listQuerySchema = z.strictObject({ cursor: listCursorSchema.optional() });
