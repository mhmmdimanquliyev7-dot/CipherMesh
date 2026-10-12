import type { ProfilePolicy, SecurityProfile } from '@ciphermesh/shared';
import type { Prisma, PrismaClient } from '../generated/prisma/client';
import { destroyed } from './secret-store';

/**
 * Profile changes (Phase 10, CM-T048, security-policy-profiles.md section 4). Part of the room
 * store: every function runs inside the room service's transaction, after the room row is locked
 * (`lockRoom`), so content writes, invitations and other profile changes of the room wait for it.
 *
 * Nothing here decides who may change a profile; the service does that on the locked state. These
 * writes are conditional on that state and touch only rows of the one room (INV-06).
 */

/** What an upgrade did to the room's existing items; counts only, for the security event. */
export interface ProfileChangeEffects {
  readonly filesClamped: number;
  readonly notesClamped: number;
  readonly secretsClamped: number;
  readonly secretsRevoked: number;
  readonly invitationsClamped: number;
  readonly invitationsRevoked: number;
}

type Db = PrismaClient | Prisma.TransactionClient;

export const NO_EFFECTS: ProfileChangeEffects = Object.freeze({
  filesClamped: 0,
  notesClamped: 0,
  secretsClamped: 0,
  secretsRevoked: 0,
  invitationsClamped: 0,
  invitationsRevoked: 0,
});

const date = (ms: number): Date => new Date(ms);

export function policyStoreFunctions(db: Db) {
  return {
    /**
     * Records the new profile and the catalogue version it is governed by, only if the room is
     * still ACTIVE with the profile the service checked (a stale change updates nothing).
     */
    async setRoomProfile(roomId: string, from: SecurityProfile, to: ProfilePolicy, now: Date): Promise<boolean> {
      const result = await db.room.updateMany({
        where: { id: roomId, status: 'ACTIVE', securityProfile: from },
        data: { securityProfile: to.profile, policyVersion: to.version, updatedAt: now },
      });
      return result.count === 1;
    },

    /**
     * The effects of an upgrade on existing items (section 4): every expiry becomes at most the
     * upgrade time plus the new maximum (an item without expiry gets exactly that), and open items
     * that break the new rules are revoked. Nothing is ever extended: each UPDATE only moves an
     * expiry earlier, which the guard triggers also enforce.
     *   - Files and notes (PC-08): live items only.
     *   - Secrets (PC-09, PC-10): ACTIVE secrets without burn-after-reading are revoked when burn
     *     becomes mandatory (decision D-10-05); the remaining ACTIVE ones are clamped.
     *   - Invitations (PC-04 to PC-07): open invitations that the new rules would not have allowed
     *     are revoked and lose their PENDING envelopes; the others are clamped to the new validity.
     */
    async applyUpgrade(input: {
      readonly roomId: string;
      readonly ownerUserId: string;
      readonly currentKeyVersion: number;
      readonly to: ProfilePolicy;
      readonly now: Date;
    }): Promise<ProfileChangeEffects> {
      const { roomId, to, now } = input;
      const at = now.getTime();

      let filesClamped = 0;
      let notesClamped = 0;
      const contentMax = to.contentExpiry.maxMs;
      if (contentMax !== null) {
        const cap = date(at + contentMax);
        filesClamped = await db.$executeRaw`
          UPDATE encrypted_files SET expires_at = ${cap}
           WHERE room_id = ${roomId}::uuid AND status <> 'DELETED'
             AND (expires_at IS NULL OR expires_at > ${cap})`;
        notesClamped = await db.$executeRaw`
          UPDATE encrypted_notes SET expires_at = ${cap}
           WHERE room_id = ${roomId}::uuid AND deleted_at IS NULL
             AND (expires_at IS NULL OR expires_at > ${cap})`;
      }

      const secretsRevoked = to.secrets.burnMandatory
        ? (
            await db.secret.updateMany({
              where: { roomId, status: 'ACTIVE', burnAfterReading: false },
              data: destroyed('REVOKED', now),
            })
          ).count
        : 0;
      const secretCap = date(at + to.secrets.maxLifetimeMs);
      const secretsClamped = await db.$executeRaw`
        UPDATE secrets SET expires_at = ${secretCap}
         WHERE room_id = ${roomId}::uuid AND status = 'ACTIVE' AND expires_at > ${secretCap}`;

      // Open invitations the new rules would have refused. PC-04: an invitation that is PENDING
      // without an approval and was not created by the current OWNER skipped the two-person rule.
      // PC-05: no confirmed fingerprint where one is required. PC-07: an envelope for any version
      // other than the current one where only the current version may be shared.
      const rules = to.invitations;
      const breaking = await db.$queryRaw<{ id: string }[]>`
        SELECT i.id::text AS id FROM invitations i
         WHERE i.room_id = ${roomId}::uuid AND i.status IN ('PENDING_APPROVAL', 'PENDING')
           AND (
             (${rules.adminInvitationNeedsApproval} AND i.status = 'PENDING' AND i.approved_by_id IS NULL
                AND i.invited_by_id <> ${input.ownerUserId}::uuid)
             OR (${rules.fingerprintConfirmation === 'required'} AND i.confirmed_fingerprint IS NULL)
             OR (${rules.keyHistory === 'current-only'} AND EXISTS (
                   SELECT 1 FROM key_envelopes e
                    WHERE e.invitation_id = i.id AND e.status = 'PENDING'
                      AND e.key_version <> ${input.currentKeyVersion}))
           )
         FOR UPDATE OF i`;
      const revokedIds = breaking.map((row) => row.id);
      let invitationsRevoked = 0;
      if (revokedIds.length > 0) {
        invitationsRevoked = (
          await db.invitation.updateMany({
            where: { id: { in: revokedIds }, roomId, status: { in: ['PENDING_APPROVAL', 'PENDING'] } },
            data: { status: 'REVOKED' },
          })
        ).count;
        await db.keyEnvelope.deleteMany({ where: { invitationId: { in: revokedIds }, roomId, status: 'PENDING' } });
      }
      const invitationCap = date(at + rules.validityMs);
      const invitationsClamped = await db.$executeRaw`
        UPDATE invitations SET expires_at = ${invitationCap}
         WHERE room_id = ${roomId}::uuid AND status IN ('PENDING_APPROVAL', 'PENDING')
           AND expires_at > ${invitationCap}`;

      return { filesClamped, notesClamped, secretsClamped, secretsRevoked, invitationsClamped, invitationsRevoked };
    },
  };
}
