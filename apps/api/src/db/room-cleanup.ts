import type { PrismaClient } from '../generated/prisma/client';

/**
 * Room deletion cleanup, run by the worker as cm_worker (data-model section 5, CM-T030). Deleting
 * a room (AZ-04) moves it to DELETING, which refuses every request at once. This step finishes the
 * deletion: a DELETING room becomes DELETED, the tombstone that stays for audit.
 *
 * It is fail-safe by construction: a room becomes DELETED only when nothing that needs cleanup is
 * left in it, that is no envelope, file, note or secret row. Phase 5 rooms hold none, so they
 * finish at once. The phases that add envelopes and content (6 to 9) add the steps that remove
 * them before this transition; until they do, such a room stays DELETING and inaccessible rather
 * than becoming DELETED with ciphertext left behind. Nothing here destroys key material.
 */
export async function runRoomCleanup(prisma: PrismaClient): Promise<{ roomsDeleted: number }> {
  const result = await prisma.room.updateMany({
    where: {
      status: 'DELETING',
      envelopes: { none: {} },
      files: { none: {} },
      notes: { none: {} },
      secrets: { none: {} },
    },
    data: { status: 'DELETED' },
  });
  return { roomsDeleted: result.count };
}
