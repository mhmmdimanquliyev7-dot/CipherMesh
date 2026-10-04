// `pnpm db:seed`: inserts the synthetic seed data (scripts/db/synthetic.ts) into the local
// development database. Idempotent. It connects as the least-privilege API role through the
// same configuration and database module as the API, so it can do nothing the API cannot.
// Refuses production and any non-loopback database. Exits non-zero on failure.
import { existsSync } from 'node:fs';
import { ConfigError, loadConfig } from '../../apps/api/src/config/env';
import { createDatabase, describeDatabaseError } from '../../apps/api/src/db/client';
import { createLogger } from '../../apps/api/src/logging/logger';
import { PLACEHOLDER_PHC, SEED_TIMESTAMP, SYNTHETIC_USERS } from './synthetic';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

async function main(): Promise<void> {
  if (existsSync('.env')) process.loadEnvFile('.env');
  const config = loadConfig(process.env);
  if (config.isProduction) throw new Error('db:seed refuses to run with NODE_ENV=production');
  if (!LOOPBACK_HOSTS.has(new URL(config.database.url.reveal()).hostname)) {
    throw new Error('db:seed only seeds a database on a loopback host');
  }

  const logger = createLogger({ level: 'warn', base: { service: 'db-seed' } });
  const database = createDatabase({ url: config.database.url, logger, poolMax: 1 });
  try {
    await database.prisma.$transaction(async (tx) => {
      for (const user of SYNTHETIC_USERS) {
        await tx.user.upsert({
          where: { email: user.email },
          create: {
            email: user.email,
            displayName: user.displayName,
            passwordHash: PLACEHOLDER_PHC,
            passwordChangedAt: SEED_TIMESTAMP,
            status: 'DISABLED',
            createdAt: SEED_TIMESTAMP,
          },
          update: {},
          select: { id: true },
        });
      }
    });
    console.log(
      `db:seed: ${String(SYNTHETIC_USERS.length)} synthetic users present (DISABLED, no credentials, no key material)`,
    );
  } finally {
    await database.close();
  }
}

main().catch((error: unknown) => {
  const message =
    error instanceof ConfigError || (error instanceof Error && error.message.startsWith('db:seed'))
      ? error.message
      : `database error ${JSON.stringify(describeDatabaseError(error))}`;
  console.error(`db:seed failed: ${message}`);
  process.exitCode = 1;
});
