import { ConfigError, loadWorkerConfigFromProcessEnv } from '../config/env';
import { createDatabase, describeDatabaseError } from '../db/client';
import { runAuthRetention } from '../db/retention';
import { createLogger } from '../logging/logger';

/**
 * One-shot retention job (`pnpm worker:retention`), connecting as cm_worker (CM-T017, CM-T018).
 * Scheduling belongs to the worker container (Phase 12) and the deployment (Phase 17); until then
 * the job is run on demand. It logs counts only.
 */
async function main(): Promise<void> {
  const config = loadWorkerConfigFromProcessEnv();
  const logger = createLogger({ level: config.logLevel, base: { service: 'worker-retention' } });
  const database = createDatabase({
    url: config.database.url,
    logger,
    poolMax: 1,
    applicationName: 'ciphermesh-worker',
  });
  try {
    const removed = await runAuthRetention(database.prisma, new Date());
    logger.info('retention completed', removed);
  } finally {
    await database.close();
  }
}

main().catch((error: unknown) => {
  const message = error instanceof ConfigError ? error.message : JSON.stringify(describeDatabaseError(error));
  process.stderr.write(`worker retention failed: ${message}\n`);
  process.exitCode = 1;
});
