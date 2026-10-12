import type { PrismaClient } from '../generated/prisma/client';

/**
 * Room deletion cleanup, run by the worker as cm_worker (data-model section 5, CM-T030). Deleting
 * a room (AZ-04) moves it to DELETING, which refuses every request at once. This step finishes the
 * deletion: a DELETING room becomes DELETED, the tombstone that stays for audit.
 *
 * Phase 6 adds the key cleanup that must come first (key-lifecycle 1.1 and 1.7, data-model 5): the
 * room's open invitations are revoked, every envelope is deleted, and its key versions become
 * DESTROYED, keeping only the commitment and the signed statement. Nothing here sees or destroys
 * plaintext key material, which never reaches the server; deleting the envelopes removes the live
 * copies of the wrapped keys (backups keep them until their retention ends, L-12).
 *
 * It stays fail-safe: a room becomes DELETED only when no envelope and no ACTIVE secret is left in it,
 * every file is a tombstone whose storage object is gone (Phase 7: the file cleanup tombstones the
 * files of DELETING rooms and deletes their objects first, file-cleanup.ts), and every note is a
 * tombstone without ciphertext or wrapped NEK (Phase 8, note-cleanup.ts, which runs first). The
 * tombstone rows stay for audit (data-model 5). Since Phase 9 every secret must have left ACTIVE
 * (secret-store.ts runSecretCleanup, which runs first, revokes them and removes their payload and
 * wrapped SEK); a room with an ACTIVE secret stays DELETING rather than becoming DELETED with
 * ciphertext left behind.
 */
export async function runRoomCleanup(prisma: PrismaClient): Promise<{
  roomsDeleted: number;
  envelopesDeleted: number;
  invitationsRevoked: number;
  keyVersionsDestroyed: number;
}> {
  const now = new Date();
  const deleting = { status: 'DELETING' as const };
  return prisma.$transaction(
    async (tx) => {
      const invitations = await tx.invitation.updateMany({
        where: { room: deleting, status: { in: ['PENDING_APPROVAL', 'PENDING'] } },
        data: { status: 'REVOKED' },
      });
      const envelopes = await tx.keyEnvelope.deleteMany({ where: { room: deleting } });
      const versions = await tx.roomKeyVersion.updateMany({
        where: { room: deleting, status: { in: ['ACTIVE', 'RETIRED'] } },
        data: { status: 'DESTROYED', destroyedAt: now },
      });
      const rooms = await tx.room.updateMany({
        where: {
          ...deleting,
          envelopes: { none: {} },
          files: { none: { OR: [{ status: { not: 'DELETED' } }, { objectDeletedAt: null }] } },
          notes: { none: { deletedAt: null } },
          // Phase 9: the secret cleanup runs first and leaves only tombstones without material.
          secrets: { none: { status: 'ACTIVE' } },
        },
        data: { status: 'DELETED' },
      });
      return {
        roomsDeleted: rooms.count,
        envelopesDeleted: envelopes.count,
        invitationsRevoked: invitations.count,
        keyVersionsDestroyed: versions.count,
      };
    },
    { isolationLevel: 'ReadCommitted' },
  );
}
