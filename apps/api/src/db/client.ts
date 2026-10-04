import { PrismaPg } from '@prisma/adapter-pg';
import type { SecretValue } from '../config/secret';
import { PrismaClient } from '../generated/prisma/client';
import type { Logger } from '../logging/logger';
import { describeDatabaseError } from './errors';

export { describeDatabaseError } from './errors';

/**
 * The single database access module of the API (CM-T013). ESLint forbids importing Prisma or pg
 * anywhere else in apps/api/src, so connection handling, logging and error handling stay here.
 *
 * Security properties:
 * - Connects as the least-privilege API role from DATABASE_URL (validated in config/env.ts).
 *   The role cannot change the schema, modify audit rows or create roles (CM-T014).
 * - No query logging: queries carry ciphertext, digests and personal data. Driver errors are
 *   logged by class and code only, never by message, because PostgreSQL messages can contain
 *   row values (INV-10).
 * - The connection string is revealed only to the driver and never logged.
 * - Connections are opened lazily, so the process starts while the database is unavailable and
 *   readiness reports the outage instead.
 */
export interface DatabaseHealth {
  /** True when a trivial query succeeds within the timeout. Never throws. */
  ping(): Promise<boolean>;
}

export interface Database extends DatabaseHealth {
  readonly prisma: PrismaClient;
  close(): Promise<void>;
}

export interface DatabaseOptions {
  readonly url: SecretValue;
  readonly logger: Logger;
  readonly poolMax?: number;
}

const PING_TIMEOUT_MS = 2_000;

export function createDatabase(options: DatabaseOptions): Database {
  const { logger } = options;
  const adapter = new PrismaPg(
    {
      connectionString: options.url.reveal(),
      max: options.poolMax ?? 10,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
      application_name: 'ciphermesh-api',
    },
    {
      onPoolError: (error) => {
        logger.error('database pool error', describeDatabaseError(error));
      },
      onConnectionError: (error) => {
        logger.error('database connection error', describeDatabaseError(error));
      },
    },
  );
  const prisma = new PrismaClient({ adapter, errorFormat: 'minimal' });

  return {
    prisma,
    async ping() {
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<false>((resolve) => {
        timer = setTimeout(() => {
          resolve(false);
        }, PING_TIMEOUT_MS);
      });
      // The rejection handler is attached before racing, so a query that fails after the
      // timeout has already answered can never become an unhandled rejection.
      const query = prisma.$queryRaw`SELECT 1`.then(
        () => true,
        (error: unknown) => {
          logger.warn('database not reachable', describeDatabaseError(error));
          return false;
        },
      );
      try {
        return await Promise.race([query, timeout]);
      } finally {
        clearTimeout(timer);
      }
    },
    async close() {
      await prisma.$disconnect();
    },
  };
}
