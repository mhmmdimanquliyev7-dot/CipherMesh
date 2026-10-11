import type { PrismaClient } from '../generated/prisma/client';
import { noteTombstone } from './note-store';

/**
 * Note cleanup, run by the worker as cm_worker (Phase 8, CM-T042; data-model 5, DF-12). Expiry is
 * enforced at read time by the API (INV-14); this step only finishes what reads already refuse:
 * notes past their expiry, and every note of a room being deleted, become tombstones with the
 * ciphertext and the wrapped NEK set to NULL. Without the wrapped NEK the note cannot be decrypted
 * from the live system (crypto-shredding); backups keep their copies until their retention ends
 * (L-12, L-49).
 *
 * Rows are never deleted (cm_worker has no DELETE on encrypted_notes): the tombstone stays for
 * audit. Nothing here sees a title, body or key, which never reach the server.
 */
export async function runNoteCleanup(
  prisma: PrismaClient,
  now: Date,
): Promise<{ readonly expired: number; readonly roomDeleted: number }> {
  const expired = await prisma.encryptedNote.updateMany({
    where: { deletedAt: null, expiresAt: { lte: now } },
    data: noteTombstone(now),
  });
  const roomDeleted = await prisma.encryptedNote.updateMany({
    where: { deletedAt: null, room: { status: 'DELETING' } },
    data: noteTombstone(now),
  });
  return { expired: expired.count, roomDeleted: roomDeleted.count };
}
