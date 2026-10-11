import { FILE_LIMITS } from '@ciphermesh/shared';
import type { PrismaClient } from '../generated/prisma/client';
import { fileTombstone } from './file-store';

/**
 * File cleanup, run by the worker as cm_worker (Phase 7, CM-T040; data-model 5, DF-07). Expiry is
 * enforced at read time by the API (INV-14); these steps only finish what reads already refuse:
 *
 *   1. Files past their expiry, uploads abandoned after the completion window, and every file of a
 *      room being deleted become tombstones: status DELETED, wrapped FEK and manifest NULL. Without
 *      the wrapped FEK the item cannot be decrypted from the live system (crypto-shredding);
 *      backups keep their copies until their retention ends (L-12).
 *   2. The storage objects of tombstones are deleted, oldest first, a bounded batch per run. A
 *      failure leaves `object_deleted_at` NULL, so the next run retries; nothing else waits on it
 *      except the final step of a room deletion.
 *
 * Rows are never deleted (cm_worker has no DELETE on encrypted_files): the tombstone stays for
 * audit. Nothing here sees plaintext, keys or file names, which never reach the server.
 */

/** Objects deleted per run at most; the rest wait for the next run. */
export const OBJECT_DELETIONS_PER_RUN = 500;

export async function tombstoneLapsedFiles(
  prisma: PrismaClient,
  now: Date,
): Promise<{ readonly expired: number; readonly abandoned: number; readonly roomDeleted: number }> {
  const live = { status: { not: 'DELETED' as const } };
  const expired = await prisma.encryptedFile.updateMany({
    where: { ...live, expiresAt: { lte: now } },
    data: fileTombstone(now),
  });
  const abandoned = await prisma.encryptedFile.updateMany({
    where: { status: 'PENDING_UPLOAD', createdAt: { lt: new Date(now.getTime() - FILE_LIMITS.completionWindowMs) } },
    data: fileTombstone(now),
  });
  const roomDeleted = await prisma.encryptedFile.updateMany({
    where: { ...live, room: { status: 'DELETING' } },
    data: fileTombstone(now),
  });
  return { expired: expired.count, abandoned: abandoned.count, roomDeleted: roomDeleted.count };
}

/** Tombstones whose storage object has not been deleted yet, oldest first. */
export async function objectsToDelete(
  prisma: PrismaClient,
  limit = OBJECT_DELETIONS_PER_RUN,
): Promise<{ readonly id: string; readonly objectKey: string }[]> {
  return prisma.encryptedFile.findMany({
    where: { status: 'DELETED', objectDeletedAt: null },
    orderBy: [{ deletedAt: 'asc' }, { id: 'asc' }],
    take: limit,
    select: { id: true, objectKey: true },
  });
}

export async function markObjectDeleted(prisma: PrismaClient, fileId: string, now: Date): Promise<void> {
  await prisma.encryptedFile.updateMany({
    where: { id: fileId, status: 'DELETED', objectDeletedAt: null },
    data: { objectDeletedAt: now },
  });
}

/**
 * Runs both steps. `deleteObject` is the storage deletion (absent when storage is not configured
 * outside production: then only step 1 runs and the objects wait).
 */
export async function runFileCleanup(
  prisma: PrismaClient,
  now: Date,
  deleteObject: ((objectKey: string) => Promise<void>) | undefined,
): Promise<{
  readonly expired: number;
  readonly abandoned: number;
  readonly roomDeleted: number;
  readonly objectsDeleted: number;
  readonly objectsFailed: number;
}> {
  const tombstoned = await tombstoneLapsedFiles(prisma, now);
  let objectsDeleted = 0;
  let objectsFailed = 0;
  if (deleteObject !== undefined) {
    for (const file of await objectsToDelete(prisma)) {
      try {
        await deleteObject(file.objectKey);
        await markObjectDeleted(prisma, file.id, now);
        objectsDeleted += 1;
      } catch {
        objectsFailed += 1;
      }
    }
  }
  return { ...tombstoned, objectsDeleted, objectsFailed };
}
