/**
 * Database error description for logs (INV-10). Prisma validation errors can quote query
 * arguments and PostgreSQL driver errors can quote row values, so only the error class and code
 * are ever logged. This module has no Prisma import, so HTTP code can use it cheaply.
 */
export function describeDatabaseError(error: unknown): { errorName: string; code?: string } {
  if (typeof error !== 'object' || error === null) return { errorName: typeof error };
  const name = error instanceof Error ? error.name : 'UnknownError';
  const code = 'code' in error && typeof error.code === 'string' ? error.code : undefined;
  return code === undefined ? { errorName: name } : { errorName: name, code };
}

/** Errors raised by the Prisma client or its PostgreSQL driver adapter, recognised by class name. */
export function isDatabaseError(error: unknown): boolean {
  return error instanceof Error && /^(PrismaClient\w*Error|DriverAdapterError)$/.test(error.name);
}
