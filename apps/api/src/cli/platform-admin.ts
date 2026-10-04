import { changePlatformRole } from '../auth/admin';
import { logSecurityEventSink } from '../auth/security-events';
import { ConfigError, loadConfigFromProcessEnv } from '../config/env';
import { authDataAccess } from '../db/auth-store';
import { createDatabase, describeDatabaseError } from '../db/client';
import { createLogger } from '../logging/logger';

/**
 * Server-side CLI for the PLATFORM_ADMIN role (CM-T022). Run on the server by the operator:
 *   pnpm admin:platform-role grant user@example.test
 *   pnpm admin:platform-role revoke user@example.test
 * There is no API for this, so a stolen session or a compromised browser cannot grant it.
 * Granting requires MFA on the account; removing the last active administrator is refused;
 * every change revokes all sessions of the account and records PLATFORM_ROLE_CHANGED.
 * The account is identified by email; nothing secret is read from the command line.
 */
async function main(): Promise<void> {
  const [command, email] = process.argv.slice(2);
  if ((command !== 'grant' && command !== 'revoke') || email === undefined) {
    throw new Error('Usage: platform-admin grant|revoke <email>');
  }
  const config = loadConfigFromProcessEnv();
  const logger = createLogger({ level: 'info', base: { service: 'platform-admin-cli' } });
  const database = createDatabase({ url: config.database.url, logger, poolMax: 1 });
  try {
    const data = authDataAccess(database.prisma);
    const outcome = await changePlatformRole(
      { transaction: data.transaction, events: logSecurityEventSink(logger), clock: () => new Date() },
      email.normalize('NFKC').trim().toLowerCase(),
      command === 'grant' ? 'PLATFORM_ADMIN' : 'USER',
    );
    process.stdout.write(`platform role ${command}: ${outcome}\n`);
  } finally {
    await database.close();
  }
}

main().catch((error: unknown) => {
  const message =
    error instanceof ConfigError || error instanceof Error
      ? error.message
      : `database error ${JSON.stringify(describeDatabaseError(error))}`;
  process.stderr.write(`platform-admin failed: ${message}\n`);
  process.exitCode = 1;
});
