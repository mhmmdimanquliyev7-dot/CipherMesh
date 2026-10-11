import { createVault, signMembershipGrant, vaultRecordToWire } from '@ciphermesh/crypto';
import { randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase } from '../../apps/api/src/db/client';
import { expireInvitations } from '../../apps/api/src/db/invitation-store';
import { createLogger } from '../../apps/api/src/logging/logger';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { grantProof, invitationBody, invite, inviteAndAccept, openRoom, vaultOf } from '../helpers/room-crypto';
import {
  createRoom,
  memberships,
  mfaPersonWithVault,
  personWithVault,
  roomRow,
  stepUp,
  type Person,
} from '../helpers/rooms';
import { newPassphrase, runner } from '../helpers/vault';

// Phase 6, CM-T034 and CM-T035 (DF-06): invitations with pre-wrapped envelopes and signed grants,
// OWNER approval, acceptance and the profile rules PC-03 to PC-07 and PC-16, against the real API
// and PostgreSQL as cm_api. Envelopes and grants are made by packages/crypto with real identities;
// the invitee opens the key with the browser's verification rule (ADR-015 section 4).
let api: AuthTestApi;
let db: pg.Client;

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
});
afterAll(async () => {
  await api.close();
  await db.end();
});

const accept = (who: Person, id: string) => who.browser.request('POST', `/invitations/${id}/accept`, {});
const decline = (who: Person, id: string) => who.browser.request('POST', `/invitations/${id}/decline`, {});
const approve = (who: Person, roomId: string, id: string) =>
  who.browser.request('POST', `/rooms/${roomId}/invitations/${id}/approve`, {});
const revoke = (who: Person, roomId: string, id: string) =>
  who.browser.request('POST', `/rooms/${roomId}/invitations/${id}/revoke`, {});
const idOf = (response: { body: Record<string, unknown> }): string =>
  (response.body['invitation'] as { id: string }).id;
const statusOf = (response: { body: Record<string, unknown> }): unknown =>
  (response.body['invitation'] as { status: string }).status;

async function invitationRow(id: string) {
  const { rows } = await db.query<{ status: string; expires_at: Date; created_at: Date; confirmed: boolean }>(
    `SELECT status::text, expires_at, created_at, confirmed_fingerprint IS NOT NULL AS confirmed
       FROM invitations WHERE id = $1`,
    [id],
  );
  return rows[0];
}
async function envelopeStatuses(roomId: string, userId: string): Promise<string[]> {
  const { rows } = await db.query<{ status: string }>(
    'SELECT status::text FROM key_envelopes WHERE room_id = $1 AND recipient_user_id = $2 ORDER BY key_version',
    [roomId, userId],
  );
  return rows.map((r) => r.status);
}

/** A room of `owner` with an ADMIN who joined through a signed ADMIN invitation. */
async function roomWithAdmin(owner: Person, admin: Person, profile = 'STANDARD'): Promise<string> {
  const roomId = await createRoom(owner, profile);
  await inviteAndAccept(owner, roomId, admin, 'ADMIN');
  return roomId;
}

describe('creating, accepting and opening (STANDARD)', () => {
  it('the invitee accepts, becomes a member with the signed grant, and verifies the key through it', async () => {
    const owner = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const roomId = await createRoom(owner, 'STANDARD', 'Invitation room');
    api.events.length = 0;
    const created = await invite(owner, roomId, invitee, 'MEMBER');
    expect(created.status).toBe(201);
    const id = idOf(created);
    expect(created.body['invitation']).toMatchObject({
      invitee: { userId: invitee.userId, keyId: vaultOf(invitee).identity.keyId },
      invitedBy: { userId: owner.userId },
      role: 'MEMBER',
      status: 'PENDING',
      fingerprintConfirmed: false,
      approvedByUserId: null,
    });
    // PENDING envelopes are never served: the invitee has no access to the room yet.
    expect(await envelopeStatuses(roomId, invitee.userId)).toEqual(['PENDING']);
    expect((await invitee.browser.request('GET', `/rooms/${roomId}/envelopes`)).status).toBe(404);
    // The invitee sees the invitation with the room's name and the inviter.
    const own = await invitee.browser.request('GET', '/invitations');
    expect(own.body['invitations']).toEqual([
      expect.objectContaining({
        id,
        room: { id: roomId, name: 'Invitation room', securityProfile: 'STANDARD' },
        invitedBy: expect.objectContaining({ userId: owner.userId }) as unknown,
        status: 'PENDING',
      }),
    ]);
    const accepted = await accept(invitee, id);
    expect(accepted.status).toBe(200);
    expect(accepted.body).toEqual({ roomId, role: 'MEMBER', status: 'ACCEPTED' });
    expect(await envelopeStatuses(roomId, invitee.userId)).toEqual(['ACTIVE']);
    const { rows } = await db.query(
      `SELECT role::text, status::text, subject_key_id::text, grant_role::text, grantor_user_id::text,
              grantor_key_id::text, first_key_version, invitation_id::text
         FROM room_members WHERE room_id = $1 AND user_id = $2`,
      [roomId, invitee.userId],
    );
    expect(rows).toEqual([
      {
        role: 'MEMBER',
        status: 'ACTIVE',
        subject_key_id: vaultOf(invitee).identity.keyId,
        grant_role: 'MEMBER',
        grantor_user_id: owner.userId,
        grantor_key_id: vaultOf(owner).identity.keyId,
        first_key_version: 1,
        invitation_id: id,
      },
    ]);
    expect((await invitationRow(id))?.status).toBe('ACCEPTED');
    const [opened] = await openRoom(invitee, roomId);
    expect(opened?.authorization).toMatchObject({ kind: 'grant', role: 'MEMBER' });
    // The invitee's early envelope request was refused and recorded (ROOM_ACCESS_DENIED).
    expect(api.events.map((e) => e.name)).toEqual(['INVITATION_CREATED', 'ROOM_ACCESS_DENIED', 'MEMBER_JOINED']);
    for (const event of api.events) expect(JSON.stringify(event.details)).not.toMatch(/[A-Za-z0-9_-]{64,}/);
  });

  it('a member invited by an ADMIN verifies the key through the ADMIN grant signed by the OWNER', async () => {
    const owner = await personWithVault(api, db);
    const admin = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const roomId = await roomWithAdmin(owner, admin);
    const created = await invite(admin, roomId, invitee, 'VIEWER');
    expect(statusOf(created)).toBe('PENDING');
    expect((await accept(invitee, idOf(created))).status).toBe(200);
    const [opened] = await openRoom(invitee, roomId);
    expect(opened?.authorization).toMatchObject({ kind: 'grant', role: 'VIEWER' });
    expect(opened?.authorization.kind === 'grant' && opened.authorization.grantor.userId).toBe(admin.userId);
  });

  it('a member promoted to ADMIN with a signed grant can invite, and the chain verifies (AZ-10, ADR-015)', async () => {
    const owner = await personWithVault(api, db);
    const member = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    await inviteAndAccept(owner, roomId, member, 'MEMBER');
    // A grant signed by someone else, or for another key, is refused before anything changes.
    const forged = await grantProof(member, roomId, member, 'ADMIN');
    const refused = await owner.browser.request('POST', `/rooms/${roomId}/members/${member.userId}/role`, {
      role: 'ADMIN',
      grant: forged,
    });
    expect(refused.status).toBe(422);
    expect(errorCode(refused)).toBe('ROOM_STATEMENT_INVALID');
    const wrongKey = { ...(await grantProof(owner, roomId, member, 'ADMIN')), subjectKeyId: randomUUID() };
    const changed = await owner.browser.request('POST', `/rooms/${roomId}/members/${member.userId}/role`, {
      role: 'ADMIN',
      grant: wrongKey,
    });
    expect(errorCode(changed)).toBe('IDENTITY_KEY_CHANGED');
    expect((await memberships(db, roomId)).find((m) => m.user_id === member.userId)?.role).toBe('MEMBER');
    const promoted = await owner.browser.request('POST', `/rooms/${roomId}/members/${member.userId}/role`, {
      role: 'ADMIN',
      grant: await grantProof(owner, roomId, member, 'ADMIN'),
    });
    expect(promoted.status).toBe(200);
    await inviteAndAccept(member, roomId, invitee, 'MEMBER');
    expect((await openRoom(invitee, roomId))[0]?.authorization).toMatchObject({ kind: 'grant', role: 'MEMBER' });
  });

  it('an ownership transfer carries the OWNER grant, so the new OWNER can invite verifiably', async () => {
    const owner = await personWithVault(api, db);
    const admin = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const roomId = await roomWithAdmin(owner, admin);
    await stepUp(api, owner);
    const transferred = await owner.browser.request(
      'POST',
      `/rooms/${roomId}/members/${admin.userId}/transfer-ownership`,
      { grant: await grantProof(owner, roomId, admin, 'OWNER') },
    );
    expect(transferred.status).toBe(200);
    // The new OWNER invites an ADMIN; the invitee verifies OWNER authority through the transfer grant.
    await inviteAndAccept(admin, roomId, invitee, 'ADMIN');
    expect((await openRoom(invitee, roomId))[0]?.authorization).toMatchObject({ kind: 'grant', role: 'ADMIN' });
  });
});

describe('who may invite whom (AZ-06 role ceilings) and the grant binding', () => {
  it('lets the OWNER invite ADMIN, MEMBER and VIEWER; an ADMIN only MEMBER and VIEWER; MEMBER and VIEWER nobody', async () => {
    const owner = await personWithVault(api, db);
    const admin = await personWithVault(api, db);
    const roomId = await roomWithAdmin(owner, admin);
    for (const role of ['ADMIN', 'MEMBER', 'VIEWER'] as const) {
      expect((await invite(owner, roomId, await personWithVault(api, db), role)).status, role).toBe(201);
    }
    expect((await invite(admin, roomId, await personWithVault(api, db), 'ADMIN')).status).toBe(403);
    expect((await invite(admin, roomId, await personWithVault(api, db), 'MEMBER')).status).toBe(201);
    const member = await personWithVault(api, db);
    const viewer = await personWithVault(api, db);
    await inviteAndAccept(owner, roomId, member, 'MEMBER');
    await inviteAndAccept(owner, roomId, viewer, 'VIEWER');
    for (const caller of [member, viewer]) {
      const response = await invite(caller, roomId, await personWithVault(api, db), 'VIEWER');
      expect(response.status).toBe(403);
      expect(errorCode(response)).toBe('FORBIDDEN');
    }
    const asOwner = await owner.browser.request('POST', `/rooms/${roomId}/invitations`, {
      ...(await invitationBody(owner, roomId, await personWithVault(api, db), 'MEMBER')),
      role: 'OWNER',
    });
    expect(asOwner.status).toBe(400);
  });

  it('binds the invitation to the invitee user, key and role the inviter signed', async () => {
    const owner = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const other = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    const body = await invitationBody(owner, roomId, invitee, 'MEMBER');
    const post = (changes: Record<string, unknown>) =>
      owner.browser.request('POST', `/rooms/${roomId}/invitations`, { ...body, ...changes });
    // The grant names MEMBER: raising the role after signing breaks the signature.
    expect(errorCode(await post({ role: 'VIEWER' }))).toBe('ROOM_STATEMENT_INVALID');
    // Another user with this grant and envelopes, or a key that is not the invitee's current one.
    expect(errorCode(await post({ inviteeUserId: other.userId, inviteeKeyId: vaultOf(other).identity.keyId }))).toBe(
      'ROOM_STATEMENT_INVALID',
    );
    expect(errorCode(await post({ inviteeKeyId: vaultOf(other).identity.keyId }))).toBe('IDENTITY_KEY_CHANGED');
    expect((await post({ inviteeUserId: randomUUID() })).status).toBe(404);
    expect(errorCode(await post({ grantSignature: Buffer.alloc(64, 1).toString('base64url') }))).toBe(
      'ROOM_STATEMENT_INVALID',
    );
    const { rows } = await db.query('SELECT count(*)::int AS n FROM invitations WHERE room_id = $1', [roomId]);
    expect(rows).toEqual([{ n: 0 }]);
    expect((await post({})).status).toBe(201);
  });

  it('refuses duplicates, current members and the inviter itself', async () => {
    const owner = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const member = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    await inviteAndAccept(owner, roomId, member, 'MEMBER');
    expect((await invite(owner, roomId, invitee, 'MEMBER')).status).toBe(201);
    expect(errorCode(await invite(owner, roomId, invitee, 'VIEWER'))).toBe('INVITATION_PENDING');
    expect(errorCode(await invite(owner, roomId, member, 'VIEWER'))).toBe('ALREADY_MEMBER');
    expect(errorCode(await invite(owner, roomId, owner, 'MEMBER'))).toBe('ALREADY_MEMBER');
  });

  it('refuses an envelope set without the current version, with duplicates or with versions the room lacks (PC-07)', async () => {
    const owner = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    const body = await invitationBody(owner, roomId, invitee, 'MEMBER');
    const envelope = (body['envelopes'] as { wrappedKey: string }[])[0]?.wrappedKey ?? '';
    for (const envelopes of [
      [{ keyVersion: 2, wrappedKey: envelope }],
      [
        { keyVersion: 1, wrappedKey: envelope },
        { keyVersion: 1, wrappedKey: envelope },
      ],
      [
        { keyVersion: 1, wrappedKey: envelope },
        { keyVersion: 7, wrappedKey: envelope },
      ],
    ]) {
      const response = await owner.browser.request('POST', `/rooms/${roomId}/invitations`, { ...body, envelopes });
      expect(response.status, JSON.stringify(envelopes.map((e) => e.keyVersion))).toBe(422);
      expect(errorCode(response)).toBe('ENVELOPE_SET_INVALID');
    }
  });
});

describe('profile rules: PC-04 approval, PC-05 fingerprints, PC-06 validity, PC-07 history, PC-03 step-up', () => {
  it('an ADMIN invitation in a CONFIDENTIAL room waits for the OWNER, never the inviter (PC-04)', async () => {
    const owner = await mfaPersonWithVault(api, db);
    const admin = await mfaPersonWithVault(api, db);
    const invitee = await mfaPersonWithVault(api, db);
    const roomId = await roomWithAdmin(owner, admin, 'CONFIDENTIAL');
    const created = await invite(admin, roomId, invitee, 'MEMBER');
    expect(statusOf(created)).toBe('PENDING_APPROVAL');
    const id = idOf(created);
    expect(errorCode(await accept(invitee, id))).toBe('INVITATION_NOT_OPEN');
    expect((await approve(admin, roomId, id)).status).toBe(403);
    api.events.length = 0;
    expect((await approve(owner, roomId, id)).body).toEqual({ status: 'PENDING' });
    expect(api.events.map((e) => e.name)).toEqual(['INVITATION_APPROVED']);
    expect(errorCode(await approve(owner, roomId, id))).toBe('INVITATION_NOT_OPEN');
    expect((await accept(invitee, id)).status).toBe(200);
    // The OWNER's own invitations need no approval; STANDARD rooms never do.
    expect(statusOf(await invite(owner, roomId, await mfaPersonWithVault(api, db), 'MEMBER'))).toBe('PENDING');
    const standard = await roomWithAdmin(owner, admin);
    expect(statusOf(await invite(admin, standard, await mfaPersonWithVault(api, db), 'MEMBER'))).toBe('PENDING');
  });

  it("a RESTRICTED invitation needs the invitee's current fingerprint and a step-up (PC-05, PC-03)", async () => {
    const owner = await mfaPersonWithVault(api, db);
    const invitee = await mfaPersonWithVault(api, db);
    const roomId = await createRoom(owner, 'RESTRICTED');
    const fingerprint = vaultOf(invitee).identity.fingerprint;
    const body = await invitationBody(owner, roomId, invitee, 'MEMBER');
    const post = (changes: Record<string, unknown>) =>
      owner.browser.request('POST', `/rooms/${roomId}/invitations`, { ...body, ...changes });
    expect(errorCode(await post({ confirmedFingerprint: fingerprint }))).toBe('STEP_UP_REQUIRED');
    await stepUp(api, owner, owner.secret);
    expect(errorCode(await post({ confirmedFingerprint: null }))).toBe('FINGERPRINT_REQUIRED');
    expect(errorCode(await post({ confirmedFingerprint: vaultOf(owner).identity.fingerprint }))).toBe(
      'FINGERPRINT_MISMATCH',
    );
    const created = await post({ confirmedFingerprint: fingerprint });
    expect(created.status).toBe(201);
    expect(created.body['invitation']).toMatchObject({ fingerprintConfirmed: true });
    const row = await invitationRow(idOf(created));
    // PC-06: the server sets 24 hours in RESTRICTED; the client cannot choose it.
    expect((row?.expires_at.getTime() ?? 0) - (row?.created_at.getTime() ?? 0)).toBe(24 * 60 * 60_000);
  });

  it('sets the validity from the profile (PC-06) and a wrong confirmed fingerprint is refused anywhere', async () => {
    const owner = await mfaPersonWithVault(api, db);
    const hours: Record<string, number> = { STANDARD: 7 * 24, CONFIDENTIAL: 72 };
    for (const profile of ['STANDARD', 'CONFIDENTIAL']) {
      const roomId = await createRoom(owner, profile);
      const invitee = await mfaPersonWithVault(api, db);
      expect(errorCode(await invite(owner, roomId, invitee, 'MEMBER', { confirmedFingerprint: 'f'.repeat(64) }))).toBe(
        'FINGERPRINT_MISMATCH',
      );
      const created = await invite(owner, roomId, invitee, 'MEMBER', { expiresAt: '2099-01-01T00:00:00.000Z' });
      expect(created.status, 'a client-chosen expiry is a validation error').toBe(400);
      const ok = await invite(owner, roomId, invitee, 'MEMBER');
      const row = await invitationRow(idOf(ok));
      expect((row?.expires_at.getTime() ?? 0) - (row?.created_at.getTime() ?? 0), profile).toBe(
        (hours[profile] ?? 0) * 60 * 60_000,
      );
    }
  });

  it('gives history to new members in STANDARD and the current version only in RESTRICTED (PC-07)', async () => {
    // A synthetic version 2 (the rekey that creates one is Phase 11): version 1 RETIRED, 2 current.
    for (const [profile, both] of [
      ['STANDARD', 201],
      ['RESTRICTED', 422],
    ] as const) {
      const owner = await mfaPersonWithVault(api, db);
      const invitee = await mfaPersonWithVault(api, db);
      const roomId = await createRoom(owner, profile);
      await db.query(`UPDATE room_key_versions SET status = 'RETIRED', retired_at = now() WHERE room_id = $1`, [
        roomId,
      ]);
      await db.query(
        `INSERT INTO room_key_versions (room_id, version, status, commitment, algorithm_suite, reasons, created_by_id,
                                        created_by_key_id, previous_commitment, recipient_user_ids, recipient_key_ids,
                                        statement_signature)
         SELECT room_id, 2, 'ACTIVE', $2, 'CM1', '{MANUAL}', created_by_id, created_by_key_id, commitment,
                recipient_user_ids, recipient_key_ids, $3
           FROM room_key_versions WHERE room_id = $1 AND version = 1`,
        [roomId, randomBytes(32), randomBytes(64)],
      );
      await db.query('UPDATE rooms SET current_key_version = 2 WHERE id = $1', [roomId]);
      if (profile === 'RESTRICTED') await stepUp(api, owner, owner.secret);
      // The server cannot read envelopes; it checks which versions they are for. Filler bytes.
      const signed = await signMembershipGrant(vaultOf(owner), {
        roomId,
        subject: vaultOf(invitee).identity,
        role: 'MEMBER',
      });
      const base = {
        inviteeUserId: invitee.userId,
        inviteeKeyId: vaultOf(invitee).identity.keyId,
        role: 'MEMBER',
        confirmedFingerprint: vaultOf(invitee).identity.fingerprint,
        grantSignature: Buffer.from(signed.signature).toString('base64url'),
      };
      const filler = (): string => randomBytes(384).toString('base64url');
      const post = (versions: number[]) =>
        owner.browser.request('POST', `/rooms/${roomId}/invitations`, {
          ...base,
          envelopes: versions.map((keyVersion) => ({ keyVersion, wrappedKey: filler() })),
        });
      expect(errorCode(await post([1])), `${profile}: the current version is required`).toBe('ENVELOPE_SET_INVALID');
      expect((await post([1, 2])).status, `${profile}: history`).toBe(both);
      if (both !== 201) expect((await post([2])).status).toBe(201);
    }
  });
});

describe('the room must be writable for invitations (PC-16, INV-07)', () => {
  it('refuses inviting, approving and accepting while REKEY_REQUIRED, but allows revoking and declining', async () => {
    const owner = await mfaPersonWithVault(api, db);
    const admin = await mfaPersonWithVault(api, db);
    const leaving = await mfaPersonWithVault(api, db);
    const roomId = await roomWithAdmin(owner, admin, 'CONFIDENTIAL');
    await inviteAndAccept(owner, roomId, leaving, 'MEMBER');
    const pendingApproval = idOf(await invite(admin, roomId, await mfaPersonWithVault(api, db), 'MEMBER'));
    const accepter = await mfaPersonWithVault(api, db);
    const pending = idOf(await invite(owner, roomId, accepter, 'MEMBER'));
    const decliner = await mfaPersonWithVault(api, db);
    const toDecline = idOf(await invite(owner, roomId, decliner, 'MEMBER'));
    // A member loss locks the room (INV-07).
    expect((await owner.browser.request('POST', `/rooms/${roomId}/members/${leaving.userId}/remove`, {})).status).toBe(
      200,
    );
    expect((await roomRow(db, roomId)).key_state).toBe('REKEY_REQUIRED');
    const fresh = await invite(owner, roomId, await mfaPersonWithVault(api, db), 'MEMBER');
    expect(fresh.status).toBe(409);
    expect(errorCode(fresh)).toBe('REKEY_REQUIRED');
    expect(errorCode(await approve(owner, roomId, pendingApproval))).toBe('REKEY_REQUIRED');
    expect(errorCode(await accept(accepter, pending))).toBe('REKEY_REQUIRED');
    expect((await memberships(db, roomId)).some((m) => m.user_id === accepter.userId)).toBe(false);
    expect((await revoke(owner, roomId, pendingApproval)).body).toEqual({ status: 'REVOKED' });
    expect((await decline(decliner, toDecline)).body).toEqual({ status: 'DECLINED' });
    expect(await envelopeStatuses(roomId, decliner.userId)).toEqual([]);
  });
});

describe('revoking, declining, expiring and invalidating', () => {
  it('the OWNER revokes any open invitation, an ADMIN only its own; revoked envelopes are deleted', async () => {
    const owner = await personWithVault(api, db);
    const admin = await personWithVault(api, db);
    const roomId = await roomWithAdmin(owner, admin);
    const byOwnerInvitee = await personWithVault(api, db);
    const byOwner = idOf(await invite(owner, roomId, byOwnerInvitee, 'MEMBER'));
    const byAdmin = idOf(await invite(admin, roomId, await personWithVault(api, db), 'MEMBER'));
    expect((await revoke(admin, roomId, byOwner)).status).toBe(403);
    expect((await revoke(admin, roomId, byAdmin)).status).toBe(200);
    expect((await revoke(owner, roomId, byOwner)).status).toBe(200);
    expect(errorCode(await revoke(owner, roomId, byOwner))).toBe('INVITATION_NOT_OPEN');
    expect(await envelopeStatuses(roomId, byOwnerInvitee.userId)).toEqual([]);
    expect(errorCode(await accept(byOwnerInvitee, byOwner))).toBe('INVITATION_NOT_OPEN');
    expect((await invitationRow(byOwner))?.status).toBe('REVOKED');
  });

  it('only the invitee sees, accepts or declines an invitation; everyone else gets 404 (SS-03, OL-11)', async () => {
    const owner = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const intruder = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    const id = idOf(await invite(owner, roomId, invitee, 'MEMBER'));
    for (const who of [intruder, owner]) {
      expect((await accept(who, id)).status).toBe(404);
      expect((await decline(who, id)).status).toBe(404);
      expect((await who.browser.request('GET', '/invitations')).body['invitations']).toEqual([]);
    }
    expect((await accept(intruder, randomUUID())).status).toBe(404);
    expect((await invitationRow(id))?.status).toBe('PENDING');
    // The room's list (AZ-31) is for the OWNER and ADMINs.
    expect(
      ((await owner.browser.request('GET', `/rooms/${roomId}/invitations`)).body['invitations'] as unknown[]).length,
    ).toBe(1);
    expect((await decline(invitee, id)).body).toEqual({ status: 'DECLINED' });
    expect(errorCode(await accept(invitee, id))).toBe('INVITATION_NOT_OPEN');
  });

  it('an accepted invitation cannot be accepted again', async () => {
    const owner = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    const id = await inviteAndAccept(owner, roomId, invitee, 'MEMBER');
    expect(errorCode(await accept(invitee, id))).toBe('INVITATION_NOT_OPEN');
    expect((await memberships(db, roomId)).filter((m) => m.user_id === invitee.userId)).toHaveLength(1);
  });

  it('an expired invitation is refused at once and later swept by the worker (INV-14, PC-06)', async () => {
    const local = await startAuthApi();
    try {
      const owner = await personWithVault(local, db);
      const invitee = await personWithVault(local, db);
      const roomId = await createRoom(owner);
      const id = idOf(await invite(owner, roomId, invitee, 'MEMBER'));
      local.clock.advance(7 * 24 * 60 * 60_000 + 60_000);
      // Keep both sessions alive across the jump by signing in again.
      for (const who of [invitee]) {
        await who.browser.login({ email: who.email, password: who.password });
      }
      expect(errorCode(await accept(invitee, id))).toBe('INVITATION_EXPIRED');
      const worker = createDatabase({
        url: new SecretValue(testDatabase(inject('databaseName')).url('worker')),
        logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
        poolMax: 1,
      });
      try {
        const swept = await expireInvitations(worker.prisma, new Date(Date.now() + 8 * 24 * 60 * 60_000));
        expect(swept.invitationsExpired).toBeGreaterThanOrEqual(1);
      } finally {
        await worker.close();
      }
      expect((await invitationRow(id))?.status).toBe('EXPIRED');
      expect(await envelopeStatuses(roomId, invitee.userId)).toEqual([]);
    } finally {
      await local.close();
    }
  });

  it('acceptance needs the inviter to still hold the authority it granted with', async () => {
    const owner = await personWithVault(api, db);
    const admin = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const roomId = await roomWithAdmin(owner, admin);
    const id = idOf(await invite(admin, roomId, invitee, 'MEMBER'));
    expect(
      (await owner.browser.request('POST', `/rooms/${roomId}/members/${admin.userId}/role`, { role: 'MEMBER' })).status,
    ).toBe(200);
    expect(errorCode(await accept(invitee, id))).toBe('INVITATION_NOT_OPEN');
  });

  it('a vault reset revokes the invitations addressed to the retired identity (CM-T034)', async () => {
    const owner = await personWithVault(api, db);
    const invitee = await personWithVault(api, db);
    const roomId = await createRoom(owner);
    const id = idOf(await invite(owner, roomId, invitee, 'MEMBER'));
    await stepUp(api, invitee);
    const fresh = await createVault({
      userId: invitee.userId,
      passphrase: newPassphrase(),
      account: { email: invitee.email, displayName: 'Synthetic Test User' },
      runner,
    });
    api.events.length = 0;
    const reset = await invitee.browser.request('POST', '/vault/reset', {
      supersedesKeyId: vaultOf(invitee).identity.keyId,
      vault: vaultRecordToWire(fresh.record),
    });
    expect(reset.status).toBe(201);
    expect((await invitationRow(id))?.status).toBe('REVOKED');
    expect(await envelopeStatuses(roomId, invitee.userId)).toEqual([]);
    expect(api.events.find((e) => e.name === 'INVITATION_INVALIDATED')?.details).toEqual({
      roomId,
      invitationId: id,
      reason: 'INVITEE_KEY_CHANGED',
    });
    expect(errorCode(await accept(invitee, id))).toBe('IDENTITY_KEY_CHANGED');
  });

  it('a CONFIDENTIAL room can be joined only with an MFA-verified session (PC-01 at acceptance)', async () => {
    const owner = await mfaPersonWithVault(api, db);
    const plain = await personWithVault(api, db);
    const roomId = await createRoom(owner, 'CONFIDENTIAL');
    const id = idOf(await invite(owner, roomId, plain, 'MEMBER'));
    const response = await accept(plain, id);
    expect(response.status).toBe(403);
    expect(errorCode(response)).toBe('MFA_REQUIRED');
    expect((await invitationRow(id))?.status).toBe('PENDING');
  });
});
