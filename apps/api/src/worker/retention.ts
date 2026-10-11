import { ConfigError, loadWorkerConfigFromProcessEnv } from '../config/env';
import { createDatabase, describeDatabaseError } from '../db/client';
import { runFileCleanup } from '../db/file-cleanup';
import { runNoteCleanup } from '../db/note-cleanup';
import { expireInvitations } from '../db/invitation-store';
import { runAuthRetention } from '../db/retention';
import { runRoomCleanup } from '../db/room-cleanup';
import { createLogger } from '../logging/logger';
import { createObjectStore } from '../storage/object-store';

/**
 * One-shot retention job (`pnpm worker:retention`), connecting as cm_worker (CM-T017, CM-T018),
 * which also finishes room deletions (CM-T030), expires invitations (CM-T035) and cleans up files
 * and their storage objects (CM-T040) and expired and room-deleted notes (CM-T042).
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
    // Open invitations past their expiry (PC-06) become EXPIRED and lose their PENDING envelopes.
    logger.info('invitation expiry completed', await expireInvitations(database.prisma, new Date()));
    // Expired, abandoned and room-deleted files become tombstones; their objects are deleted with
    // retries on later runs (CM-T040). Before the room step, which waits for the objects.
    const storage = createObjectStore(config.storage);
    if (!storage.available) logger.warn('object storage not configured: file objects are not deleted in this run');
    logger.info(
      'file cleanup completed',
      await runFileCleanup(database.prisma, new Date(), storage.available ? (key) => storage.delete(key) : undefined),
    );
    // Expired notes and the notes of rooms being deleted become tombstones (CM-T042).
    logger.info('note cleanup completed', await runNoteCleanup(database.prisma, new Date()));
    // Finishes room deletions (CM-T030): DELETING rooms with nothing left to clean become DELETED.
    logger.info('room cleanup completed', await runRoomCleanup(database.prisma));
  } finally {
    await database.close();
  }
}

main().catch((error: unknown) => {
  const message = error instanceof ConfigError ? error.message : JSON.stringify(describeDatabaseError(error));
  process.stderr.write(`worker retention failed: ${message}\n`);
  process.exitCode = 1;
});
