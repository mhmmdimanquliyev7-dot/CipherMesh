import { CryptoErrorCode, isCryptoError } from '@ciphermesh/crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { Database } from '../../apps/api/src/db/client';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { createdNote, readNote } from '../helpers/notes';
import {
  envelopeVersions,
  finalize,
  finalizeBody,
  keyState,
  rekey,
  reshare,
  resetVault,
  startedOf,
  startRekey,
} from '../helpers/rekey';
import { inviteAndAccept, openRoom } from '../helpers/room-crypto';
import {
  apiDatabase,
  createRoom,
  mfaPersonWithVault,
  personWithVault,
  platformAdministrator,
  roomRow,
  stepUp,
  type Person,
} from '../helpers/rooms';

// Phase 11 (CM-T051, CM-T053; AZ-11, AZ-14, key-lifecycle section 3 and R5): leaving a room, the
// vault-reset procedure with and without the compromise flag, re-sharing keys to a member's new
// identity and reinstating a suspended member, against the real API and PostgreSQL. Browser
// cryptography is the real packages/crypto code; every person is synthetic.

let api: AuthTestApi;
let db: pg.Client;
let database: Database;

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  database = apiDatabase();
});
afterAll(async () => {
  await api.close();
  await db.end();
  await database.close();
});

async function team(profile = 'STANDARD') {
  const make = profile === 'STANDARD' ? () => personWithVault(api, db) : () => mfaPersonWithVault(api, db);
  const owner = await make();
  const admin = await make();
  const member = await make();
  const viewer = await make();
  const roomId = await createRoom(owner, profile);
  if (profile === 'RESTRICTED') await stepUp(api, owner, (owner as Person & { secret: string }).secret);
  for (const [who, role] of [
    [admin, 'ADMIN'],
    [member, 'MEMBER'],
    [viewer, 'VIEWER'],
  ] as const) {
    await inviteAndAccept(
      owner,
      roomId,
      who,
      role,
      profile === 'RESTRICTED' ? { confirmedFingerprint: who.vault?.identity.fingerprint ?? null } : {},
    );
  }
  return { owner, admin, member, viewer, roomId };
}

const leave = (who: Person, roomId: string) => who.browser.request('POST', `/rooms/${roomId}/leave`, {});

async function membership(roomId: string, userId: string) {
  const { rows } = await db.query<{ status: string; removal_reason: string | null }>(
    'SELECT status::text, removal_reason::text FROM room_members WHERE room_id = $1 AND user_id = $2 ORDER BY joined_at DESC LIMIT 1',
    [roomId, userId],
  );
  return rows[0];
}

// ---------------------------------------------------------------------------- AZ-11 leaving

describe('leaving a room (AZ-11, CM-T051, key-lifecycle R2)', () => {
  it('a member leaves: LEFT, every envelope gone, 404 afterwards, the room REKEY_REQUIRED with MEMBER_LEFT', async () => {
    const { owner, member, roomId } = await team();
    api.events.length = 0;
    const left = await leave(member, roomId);
    expect(left.status).toBe(200);
    expect(left.body).toEqual({ status: 'LEFT', rekeyRequired: true });
    expect(await membership(roomId, member.userId)).toEqual({ status: 'LEFT', removal_reason: 'LEFT_ROOM' });
    const { rows } = await db.query('SELECT 1 FROM key_envelopes WHERE room_id = $1 AND recipient_user_id = $2', [
      roomId,
      member.userId,
    ]);
    expect(rows).toEqual([]);
    expect(await roomRow(db, roomId)).toMatchObject({ key_state: 'REKEY_REQUIRED', rekey_reasons: '{MEMBER_LEFT}' });
    for (const path of [
      `/rooms/${roomId}`,
      `/rooms/${roomId}/envelopes`,
      `/rooms/${roomId}/rekey-operations/current`,
    ]) {
      expect((await member.browser.request('GET', path)).status).toBe(404);
    }
    // Then only the refusals of the probes above (404, ROOM_ACCESS_DENIED).
    expect(api.events.slice(0, 2).map((e) => e.name)).toEqual(['MEMBER_LEFT', 'REKEY_REQUIRED']);
    expect(new Set(api.events.slice(2).map((e) => e.name))).toEqual(new Set(['ROOM_ACCESS_DENIED']));
    // The rekey excludes them.
    const started = startedOf(await startRekey(owner, roomId));
    expect(started.recipients.some((r) => r.userId === member.userId)).toBe(false);
  });

  it('the OWNER cannot leave (transfer first), and leaving makes a pending rekey STALE', async () => {
    const { owner, admin, viewer, roomId } = await team();
    const refused = await leave(owner, roomId);
    expect(refused.status).toBe(403);
    expect(await membership(roomId, owner.userId)).toMatchObject({ status: 'ACTIVE' });
    const started = startedOf(await startRekey(admin, roomId));
    const { body } = await finalizeBody(admin, roomId, started);
    expect((await leave(viewer, roomId)).status).toBe(200);
    expect(errorCode(await finalize(admin, roomId, started.operation.id, body))).toBe('REKEY_OPERATION_CLOSED');
    expect((await roomRow(db, roomId)).key_state).toBe('REKEY_REQUIRED');
  });
});

// ------------------------------------------------------------- CM-T053 vault reset in rooms

describe('the vault-reset procedure in rooms (CM-T053, key-lifecycle section 3)', () => {
  it('a reset deletes the old identity envelopes, advances each room, and the next rekey includes the new key', async () => {
    const { owner, member, roomId } = await team();
    const second = await createRoom(owner);
    await inviteAndAccept(owner, second, member, 'MEMBER');
    const { rows: before } = await db.query<{ room_id: string; epoch: string }>(
      'SELECT id::text AS room_id, membership_epoch::text AS epoch FROM rooms WHERE id = ANY($1) ORDER BY id',
      [[roomId, second]],
    );
    api.events.length = 0;
    const reset = await resetVault(api, member);
    const { rows: envelopes } = await db.query('SELECT 1 FROM key_envelopes WHERE recipient_user_id = $1', [
      member.userId,
    ]);
    expect(envelopes).toEqual([]);
    const { rows: after } = await db.query<{ room_id: string; epoch: string }>(
      'SELECT id::text AS room_id, membership_epoch::text AS epoch FROM rooms WHERE id = ANY($1) ORDER BY id',
      [[roomId, second]],
    );
    expect(after.map((r, i) => BigInt(r.epoch) - BigInt(before[i]?.epoch ?? '0'))).toEqual([1n, 1n]);
    // A lost passphrase is not a compromise: the rooms stay writable (no R5).
    expect((await roomRow(db, roomId)).key_state).toBe('ACTIVE');
    expect(
      api.events
        .filter((e) => e.name === 'MEMBER_IDENTITY_REPLACED')
        .map((e) => e.details?.['roomId'])
        .sort(),
    ).toEqual([roomId, second].sort());
    // The room's administrators see who needs keys; the member holds none.
    expect((await keyState(owner, roomId))['membersNeedingKeys']).toEqual([
      { userId: member.userId, reason: 'IDENTITY_CHANGED' },
    ]);
    expect(await envelopeVersions(reset, roomId)).toEqual([]);
    // The next rekey wraps to the new identity (key-hierarchy: "A rekey also wraps the new version").
    const started = startedOf(await startRekey(owner, roomId));
    expect(started.recipients.find((r) => r.userId === member.userId)?.identity.keyId).toBe(
      reset.vault?.identity.keyId,
    );
    const { body } = await finalizeBody(owner, roomId, started);
    expect((await finalize(owner, roomId, started.operation.id, body)).status).toBe(200);
    const keys = await openRoom(reset, roomId);
    expect(keys.map((k) => k.keyVersion)).toEqual([2]);
  });

  it('the compromise flag (R5) sets REKEY_REQUIRED in every room of the user and stales live operations', async () => {
    const { owner, admin, member, roomId } = await team();
    const second = await createRoom(owner);
    await inviteAndAccept(owner, second, member, 'MEMBER');
    const live = startedOf(await startRekey(admin, roomId));
    api.events.length = 0;
    await resetVault(api, member, true);
    for (const id of [roomId, second]) {
      expect(await roomRow(db, id)).toMatchObject({
        key_state: 'REKEY_REQUIRED',
        rekey_reasons: '{IDENTITY_KEY_COMPROMISED}',
      });
    }
    const { rows } = await db.query('SELECT status::text FROM rekey_operations WHERE id = $1', [live.operation.id]);
    expect(rows[0]).toEqual({ status: 'STALE' });
    const names = api.events.map((e) => e.name);
    expect(names.filter((n) => n === 'REKEY_REQUIRED')).toHaveLength(2);
    expect(names).toContain('REKEY_STALE');
    expect(api.events.find((e) => e.name === 'VAULT_RESET')?.details).toMatchObject({
      identityCompromised: true,
      rooms: 2,
    });
  });
});

// ----------------------------------------------------------------------- AZ-14 re-sharing

describe('re-sharing keys to a new identity (AZ-14, CM-T053)', () => {
  it('an ADMIN re-shares the retained history to a reset MEMBER, who reads old content again', async () => {
    const { admin, member, roomId } = await team();
    const note = await createdNote(admin, roomId, 'History', 'written before the reset');
    expect(await rekey(admin, roomId)).toBe(2);
    const reset = await resetVault(api, member);
    api.events.length = 0;
    const shared = await reshare(admin, roomId, reset, 'MEMBER');
    expect(shared.status, JSON.stringify(shared.body)).toBe(200);
    expect(shared.body).toEqual({ userId: member.userId, keyVersions: [1, 2], reinstated: false });
    const keys = await openRoom(reset, roomId);
    expect(keys.map((k) => [k.keyVersion, k.authorization.kind])).toEqual([
      [1, 'grant'],
      [2, 'grant'],
    ]);
    expect((await readNote(reset, roomId, note)).body).toBe('written before the reset');
    expect(api.events.map((e) => e.name)).toEqual(['KEYS_RESHARED']);
    // Nothing to re-share any more.
    expect(errorCode(await reshare(admin, roomId, reset, 'MEMBER'))).toBe('RESHARE_NOT_NEEDED');
  });

  it('applies the invitation role ceilings: an ADMIN re-shares to MEMBERs only; nobody to the OWNER or to themselves', async () => {
    const { owner, admin, member, roomId } = await team();
    const resetAdmin = await resetVault(api, admin);
    // The OWNER may re-share to an ADMIN, with a new ADMIN grant for the new key.
    const byOwner = await reshare(owner, roomId, resetAdmin, 'ADMIN');
    expect(byOwner.status, JSON.stringify(byOwner.body)).toBe(200);
    // A second ADMIN may not re-share to an ADMIN (OWNER grants ADMIN, ADR-015 authority).
    const resetAgain = await resetVault(api, resetAdmin);
    const otherAdmin = await personWithVault(api, db);
    await inviteAndAccept(owner, roomId, otherAdmin, 'ADMIN');
    expect((await reshare(otherAdmin, roomId, resetAgain, 'ADMIN')).status).toBe(403);
    // Nobody can re-share to the OWNER (an OWNER grant needs an OWNER signature).
    const resetOwner = await resetVault(api, owner);
    expect((await reshare(otherAdmin, roomId, { ...resetOwner }, 'MEMBER')).status).toBe(403);
    // MEMBERs and VIEWERs cannot re-share at all.
    expect((await reshare(member, roomId, resetAgain, 'ADMIN')).status).toBe(403);
  });

  it('refuses a stale identity, a wrong grant, a locked room and envelopes the profile does not allow', async () => {
    const { owner, admin, member, viewer, roomId } = await team();
    const reset = await resetVault(api, member);
    // Re-sharing to the old (superseded) identity: the member's key changed.
    expect(errorCode(await reshare(admin, roomId, member, 'MEMBER'))).toBe('IDENTITY_KEY_CHANGED');
    // A grant for the wrong role does not verify against the member's stored role.
    expect(errorCode(await reshare(admin, roomId, reset, 'VIEWER'))).toBe('ROOM_STATEMENT_INVALID');
    // While the room is write-locked (PC-16), nothing is re-shared.
    await stepUp(api, owner);
    expect((await owner.browser.request('POST', `/rooms/${roomId}/members/${viewer.userId}/remove`, {})).status).toBe(
      200,
    );
    expect(errorCode(await reshare(admin, roomId, reset, 'MEMBER'))).toBe('REKEY_REQUIRED');
    const { rows } = await db.query('SELECT 1 FROM key_envelopes WHERE room_id = $1 AND recipient_user_id = $2', [
      roomId,
      member.userId,
    ]);
    expect(rows).toEqual([]);
  });

  it('RESTRICTED: the fingerprint must be confirmed, only the current version is shared, and a step-up is needed', async () => {
    const { owner, member, roomId } = await team('RESTRICTED');
    expect(await rekey(owner, roomId)).toBe(2);
    const reset = await resetVault(api, member);
    await stepUp(api, owner, (owner as Person & { secret: string }).secret);
    expect(errorCode(await reshare(owner, roomId, reset, 'MEMBER', { currentOnly: true }))).toBe(
      'FINGERPRINT_REQUIRED',
    );
    const fingerprint = reset.vault?.identity.fingerprint ?? null;
    expect(errorCode(await reshare(owner, roomId, reset, 'MEMBER', { confirmedFingerprint: fingerprint }))).toBe(
      'ENVELOPE_SET_INVALID',
    );
    const shared = await reshare(owner, roomId, reset, 'MEMBER', {
      currentOnly: true,
      confirmedFingerprint: fingerprint,
    });
    expect(shared.status, JSON.stringify(shared.body)).toBe(200);
    expect(shared.body).toMatchObject({ keyVersions: [2] });
    expect((await openRoom(reset, roomId)).map((k) => k.keyVersion)).toEqual([2]);
  });

  it('reinstates a SUSPENDED member of a re-enabled account only through an explicit re-share', async () => {
    const { owner, member, roomId } = await team();
    const platform = await platformAdministrator(api, database);
    await stepUp(api, platform, platform.secret);
    const account = (action: 'disable' | 'enable') =>
      platform.browser.request('POST', `/admin/users/${action}`, { userId: member.userId });
    expect((await account('disable')).status).toBe(200);
    expect(await membership(roomId, member.userId)).toMatchObject({ status: 'SUSPENDED' });
    expect(await rekey(owner, roomId)).toBe(2);
    expect((await account('enable')).status).toBe(200);
    // Re-enabling restores the login only: still SUSPENDED, no keys (L-44 resolved by AZ-14 below).
    await member.browser.login({ email: member.email, password: member.password });
    expect(await membership(roomId, member.userId)).toMatchObject({ status: 'SUSPENDED' });
    expect((await member.browser.request('GET', `/rooms/${roomId}`)).status).toBe(404);
    expect((await keyState(owner, roomId))['membersNeedingKeys']).toEqual([
      { userId: member.userId, reason: 'SUSPENDED' },
    ]);
    const shared = await reshare(owner, roomId, member, 'MEMBER');
    expect(shared.status, JSON.stringify(shared.body)).toBe(200);
    expect(shared.body).toEqual({ userId: member.userId, keyVersions: [1, 2], reinstated: true });
    expect(await membership(roomId, member.userId)).toEqual({ status: 'ACTIVE', removal_reason: null });
    expect((await openRoom(member, roomId)).map((k) => k.keyVersion)).toEqual([1, 2]);
  });

  it("an ADMIN's reset and re-share keeps the versions and invitations the old key signed verifiable (grant history)", async () => {
    const { owner, admin, roomId } = await team();
    // The ADMIN's old key signs version 2 and invites a new member.
    expect(await rekey(admin, roomId)).toBe(2);
    const invited = await personWithVault(api, db);
    await inviteAndAccept(admin, roomId, invited, 'MEMBER');
    // The ADMIN resets; the OWNER re-shares with a new ADMIN grant, which replaces the stored one.
    const reset = await resetVault(api, admin);
    expect((await reshare(owner, roomId, reset, 'ADMIN')).status).toBe(200);
    const { rows } = await db.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM room_member_grants WHERE room_id = $1 AND subject_user_id = $2 AND role = 'ADMIN'",
      [roomId, admin.userId],
    );
    expect(rows[0]).toEqual({ n: 2 });
    // Everyone still verifies v2 (signed by the old ADMIN key) and the invited member's grant.
    for (const who of [owner, invited, reset]) {
      const keys = await openRoom(who, roomId);
      expect(keys.map((k) => k.keyVersion)).toEqual([1, 2]);
    }
    // The new ADMIN key has authority too: its rekey verifies for everyone.
    expect(await rekey(reset, roomId)).toBe(3);
    expect((await openRoom(invited, roomId)).map((k) => k.keyVersion)).toEqual([1, 2, 3]);
  });

  it("the member's browser refuses keys re-shared without a grant the room's authority accepts", async () => {
    const { owner, member, roomId } = await team();
    const reset = await resetVault(api, member);
    expect((await reshare(owner, roomId, reset, 'MEMBER')).status).toBe(200);
    // A server-side attacker replaces the member's stored grant with one signed by the member's
    // own new key: the API role can write the row, but no member browser accepts the chain.
    const { rows } = await db.query<{ grant_signature: Buffer }>(
      'SELECT grant_signature FROM room_members WHERE room_id = $1 AND user_id = $2 AND status = $3',
      [roomId, member.userId, 'ACTIVE'],
    );
    expect(rows[0]?.grant_signature).toBeDefined();
    await db.query(
      `UPDATE room_members SET grantor_user_id = user_id, grantor_key_id = subject_key_id
        WHERE room_id = $1 AND user_id = $2 AND status = 'ACTIVE'`,
      [roomId, member.userId],
    );
    const refused = await openRoom(reset, roomId).catch((e: unknown) => e);
    expect(isCryptoError(refused, CryptoErrorCode.KEY_AUTHENTICATION_FAILED)).toBe(true);
  });
});
