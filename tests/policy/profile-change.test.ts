import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { requireStorageEnv, uploadFile } from '../helpers/files';
import { createNote } from '../helpers/notes';
import {
  confirmedFingerprint,
  inRoomLockOrder,
  policyDenials,
  roomSnapshot,
  signedInAgo,
  steppedUpAgo,
} from '../helpers/policy';
import { invite, inviteAndAccept } from '../helpers/room-crypto';
import {
  addMember,
  apiDatabase,
  createRoom,
  mfaPersonWithVault,
  personWithVault,
  platformAdministrator,
  stepUp,
  type Person,
} from '../helpers/rooms';
import { createdSecret, createSecret, inFromNow } from '../helpers/secrets';
import type { Database } from '../../apps/api/src/db/client';

// CM-T048: profile changes (security-policy-profiles.md section 4) against the real API and
// PostgreSQL. Who may change a profile (AZ-03), what an upgrade requires and does to existing items
// (expiry clamping, revocation of items that break the new rules, members without MFA locked out),
// what a downgrade requires (a step-up within 5 minutes) and that it extends nothing, stale and
// forged requests, and concurrency with forced lock order: a profile change that commits first
// decides a write that started under the old profile. Every text and key is synthetic.
type MfaPerson = Person & { readonly secret: string };
type Response = { readonly status: number; readonly body: Record<string, unknown> };

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

let api: AuthTestApi;
let db: pg.Client;
let observer: pg.Client;
let database: Database;
let owner: MfaPerson;
let admin: MfaPerson;
let member: MfaPerson;
let viewer: MfaPerson;

const status = (response: Response): [number, unknown] => [response.status, errorCode(response)];
const now = (): Date => api.clock.now();
const change = (who: Person, roomId: string, securityProfile: string, expectedProfile: string) =>
  who.browser.request('POST', `/rooms/${roomId}/profile`, { securityProfile, expectedProfile });

async function roomProfile(roomId: string): Promise<{ profile: string; version: number }> {
  const { rows } = await db.query<{ profile: string; version: number }>(
    'SELECT security_profile::text AS profile, policy_version AS version FROM rooms WHERE id = $1',
    [roomId],
  );
  const row = rows[0];
  if (row === undefined) throw new Error('room not found');
  return row;
}

async function expiries(table: 'encrypted_files' | 'encrypted_notes' | 'secrets', roomId: string) {
  const live =
    table === 'encrypted_files'
      ? "status <> 'DELETED'"
      : table === 'encrypted_notes'
        ? 'deleted_at IS NULL'
        : "status = 'ACTIVE'";
  const { rows } = await db.query<{ id: string; expires_at: Date | null }>(
    `SELECT id::text, expires_at FROM ${table} WHERE room_id = $1 AND ${live} ORDER BY id`,
    [roomId],
  );
  return rows;
}

/** A STANDARD room with the four MFA people of the suite as OWNER, ADMIN, MEMBER and VIEWER. */
async function standardRoom(name: string): Promise<string> {
  const roomId = await createRoom(owner, 'STANDARD', name);
  await inviteAndAccept(owner, roomId, admin, 'ADMIN');
  await inviteAndAccept(owner, roomId, member, 'MEMBER');
  await inviteAndAccept(owner, roomId, viewer, 'VIEWER');
  return roomId;
}

beforeAll(async () => {
  loadDatabaseTestEnv();
  requireStorageEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  observer = await testDatabase(inject('databaseName')).connect('api');
  database = apiDatabase();
  owner = await mfaPersonWithVault(api, db);
  admin = await mfaPersonWithVault(api, db);
  member = await mfaPersonWithVault(api, db);
  viewer = await mfaPersonWithVault(api, db);
}, 240_000);
afterAll(async () => {
  await api.close();
  await db.end();
  await observer.end();
  await database.close();
});

describe('who may change a profile (AZ-03)', () => {
  it('only the OWNER; other roles get 403, outsiders and platform administrators 404, nothing changes', async () => {
    const roomId = await standardRoom('Who changes');
    const outsider = await mfaPersonWithVault(api, db);
    const platform = await platformAdministrator(api, database);
    for (const [who, expected] of [
      [admin, [403, 'FORBIDDEN']],
      [member, [403, 'FORBIDDEN']],
      [viewer, [403, 'FORBIDDEN']],
      [outsider, [404, 'NOT_FOUND']],
      [platform, [404, 'NOT_FOUND']],
    ] as const) {
      const before = await roomSnapshot(db, roomId);
      expect(status(await change(who, roomId, 'CONFIDENTIAL', 'STANDARD'))).toEqual(expected);
      expect(await roomSnapshot(db, roomId)).toBe(before);
    }
    const done = await change(owner, roomId, 'CONFIDENTIAL', 'STANDARD');
    expect(done.status).toBe(200);
    expect(done.body).toEqual({ securityProfile: 'CONFIDENTIAL', policyVersion: 1, change: 'UPGRADE' });
  });

  it('refuses a stale expected profile, unknown profiles and fields that try to choose policy', async () => {
    const roomId = await standardRoom('Stale and forged');
    const before = await roomSnapshot(db, roomId);
    expect(status(await change(owner, roomId, 'CONFIDENTIAL', 'RESTRICTED'))).toEqual([409, 'PROFILE_CHANGED']);
    expect(status(await change(owner, roomId, 'TOP_SECRET', 'STANDARD'))).toEqual([400, 'VALIDATION_FAILED']);
    for (const extra of [{ policyVersion: 0 }, { role: 'OWNER' }, { roomId }, { direction: 'UPGRADE' }]) {
      const response = await owner.browser.request('POST', `/rooms/${roomId}/profile`, {
        securityProfile: 'STANDARD',
        expectedProfile: 'STANDARD',
        ...extra,
      });
      expect(status(response), JSON.stringify(extra)).toEqual([400, 'VALIDATION_FAILED']);
    }
    expect(await roomSnapshot(db, roomId)).toBe(before);
    // The same profile again changes nothing and records nothing.
    const from = api.events.length;
    const same = await change(owner, roomId, 'STANDARD', 'STANDARD');
    expect(same.body).toEqual({ securityProfile: 'STANDARD', policyVersion: 1, change: 'UNCHANGED' });
    expect(api.events.slice(from).filter((e) => e.name.startsWith('PROFILE_'))).toEqual([]);
    expect(await roomSnapshot(db, roomId)).toBe(before);
  });
});

describe('upgrades (CM-T048)', () => {
  it('STANDARD to CONFIDENTIAL: clamps expiry, revokes invitations that skipped approval, locks out members without MFA', async () => {
    const roomId = await standardRoom('Upgrade to confidential');
    const plain = await personWithVault(api, db);
    await addMember(db, roomId, plain.userId, 'MEMBER');
    await uploadFile(owner, roomId, randomBytes(64)); // no expiry: allowed in STANDARD
    expect((await createNote(member, roomId, 'No expiry', 'Synthetic', { expiresAt: null })).response.status).toBe(201);
    const longNote = await createNote(member, roomId, 'Long', 'Synthetic', { expiresAt: inFromNow(200 * DAY, now()) });
    expect(longNote.response.status).toBe(201);
    const secretId = await createdSecret(owner, roomId, member, 'Week-long secret', {
      expiresAt: inFromNow(7 * DAY - MINUTE, now()),
      burnAfterReading: false,
    });
    // An ADMIN's invitation is PENDING without approval in STANDARD; it breaks PC-04 afterwards.
    const byAdmin = await invite(admin, roomId, await mfaPersonWithVault(api, db), 'VIEWER');
    const byOwner = await invite(owner, roomId, await mfaPersonWithVault(api, db), 'VIEWER');
    expect([byAdmin.status, byOwner.status]).toEqual([201, 201]);
    const adminInvitation = (byAdmin.body['invitation'] as { id: string }).id;
    const ownerInvitation = (byOwner.body['invitation'] as { id: string }).id;
    expect((await plain.browser.request('GET', `/rooms/${roomId}`)).status).toBe(200);

    const from = api.events.length;
    const changedAt = now();
    const response = await change(owner, roomId, 'CONFIDENTIAL', 'STANDARD');
    expect(response.body).toEqual({ securityProfile: 'CONFIDENTIAL', policyVersion: 1, change: 'UPGRADE' });
    expect(await roomProfile(roomId)).toEqual({ profile: 'CONFIDENTIAL', version: 1 });

    const cap = (max: number) => changedAt.getTime() + max;
    for (const table of ['encrypted_files', 'encrypted_notes'] as const) {
      for (const row of await expiries(table, roomId)) {
        expect(row.expires_at, table).not.toBeNull();
        expect(row.expires_at?.getTime()).toBeLessThanOrEqual(cap(90 * DAY) + 5_000);
        expect(row.expires_at?.getTime()).toBeGreaterThanOrEqual(cap(90 * DAY) - 5_000);
      }
    }
    const [secret] = await expiries('secrets', roomId);
    expect(secret?.id).toBe(secretId);
    expect(secret?.expires_at?.getTime()).toBeLessThanOrEqual(cap(72 * HOUR) + 5_000);
    const invitations = await db.query<{ id: string; status: string; expires_at: Date; envelopes: number }>(
      `SELECT i.id::text, i.status::text, i.expires_at,
              (SELECT count(*)::int FROM key_envelopes e WHERE e.invitation_id = i.id) AS envelopes
         FROM invitations i WHERE i.id = ANY($1::uuid[])`,
      [[adminInvitation, ownerInvitation]],
    );
    const byId = Object.fromEntries(invitations.rows.map((r) => [r.id, r]));
    expect(byId[adminInvitation]).toMatchObject({ status: 'REVOKED', envelopes: 0 });
    expect(byId[ownerInvitation]?.status).toBe('PENDING');
    expect(byId[ownerInvitation]?.expires_at.getTime()).toBeLessThanOrEqual(cap(72 * HOUR) + 5_000);

    const event = api.events.slice(from).find((e) => e.name === 'PROFILE_UPGRADED');
    expect(event?.details).toEqual({
      roomId,
      from: 'STANDARD',
      to: 'CONFIDENTIAL',
      policyVersion: 1,
      severity: 'NORMAL',
      filesClamped: 1,
      notesClamped: 2,
      secretsClamped: 1,
      secretsRevoked: 0,
      invitationsClamped: 1,
      invitationsRevoked: 1,
    });
    // CM-T048 acceptance: after the upgrade, a member without MFA is denied until they enable it.
    expect(status(await plain.browser.request('GET', `/rooms/${roomId}`))).toEqual([403, 'MFA_REQUIRED']);
    expect((await member.browser.request('GET', `/rooms/${roomId}`)).status).toBe(200);
    // New content follows the new rules at once (PC-08).
    const unbounded = await createNote(member, roomId, 'After', 'Synthetic', { expiresAt: null });
    expect(status(unbounded.response)).toEqual([422, 'EXPIRY_NOT_ALLOWED']);
  });

  it('CONFIDENTIAL to RESTRICTED: needs a step-up, revokes non-burn secrets and unconfirmed or history invitations', async () => {
    const roomId = await createRoom(owner, 'CONFIDENTIAL', 'Upgrade to restricted');
    await inviteAndAccept(owner, roomId, member, 'MEMBER');
    await uploadFile(owner, roomId, randomBytes(64), { overrides: { expiresAt: inFromNow(80 * DAY, now()) } });
    const nonBurn = await createdSecret(owner, roomId, member, 'Re-readable', {
      expiresAt: inFromNow(48 * HOUR, now()),
      burnAfterReading: false,
    });
    const burn = await createdSecret(owner, roomId, member, 'Burnable', { expiresAt: inFromNow(48 * HOUR, now()) });
    const unconfirmed = await invite(owner, roomId, await mfaPersonWithVault(api, db), 'VIEWER');
    const confirmedInvitee = await mfaPersonWithVault(api, db);
    const confirmed = await invite(owner, roomId, confirmedInvitee, 'VIEWER', confirmedFingerprint(confirmedInvitee));
    expect([unconfirmed.status, confirmed.status]).toEqual([201, 201]);

    await steppedUpAgo(db, api, owner, null);
    const before = await roomSnapshot(db, roomId);
    const from = api.events.length;
    expect(status(await change(owner, roomId, 'RESTRICTED', 'CONFIDENTIAL'))).toEqual([401, 'STEP_UP_REQUIRED']);
    expect(policyDenials(api, from)).toEqual([{ action: 'AZ-03', reason: 'PROFILE_PC_03' }]);
    expect(await roomSnapshot(db, roomId)).toBe(before);

    await stepUp(api, owner, owner.secret);
    const changedAt = now();
    expect((await change(owner, roomId, 'RESTRICTED', 'CONFIDENTIAL')).status).toBe(200);
    const secrets = await db.query<{ id: string; status: string; material: boolean; expires_at: Date }>(
      'SELECT id::text, status::text, wrapped_sek IS NOT NULL AS material, expires_at FROM secrets WHERE room_id = $1',
      [roomId],
    );
    const secretById = Object.fromEntries(secrets.rows.map((r) => [r.id, r]));
    expect(secretById[nonBurn]).toMatchObject({ status: 'REVOKED', material: false });
    expect(secretById[burn]).toMatchObject({ status: 'ACTIVE', material: true });
    expect(secretById[burn]?.expires_at.getTime()).toBeLessThanOrEqual(changedAt.getTime() + 24 * HOUR + 5_000);
    for (const row of await expiries('encrypted_files', roomId)) {
      expect(row.expires_at?.getTime()).toBeLessThanOrEqual(changedAt.getTime() + 30 * DAY + 5_000);
    }
    const ids = [unconfirmed, confirmed].map((r) => (r.body['invitation'] as { id: string }).id);
    const rows = await db.query<{ id: string; status: string }>(
      'SELECT id::text, status::text FROM invitations WHERE id = ANY($1::uuid[])',
      [ids],
    );
    expect(Object.fromEntries(rows.rows.map((r) => [r.id, r.status]))).toEqual({
      [ids[0] ?? '']: 'REVOKED',
      [ids[1] ?? '']: 'PENDING',
    });
  });

  it('refuses an upgrade when the OWNER does not meet the new access requirements, changing nothing', async () => {
    const plainOwner = await personWithVault(api, db);
    const noMfaRoom = await createRoom(plainOwner, 'STANDARD', 'Owner without MFA');
    let before = await roomSnapshot(db, noMfaRoom);
    let from = api.events.length;
    expect(status(await change(plainOwner, noMfaRoom, 'CONFIDENTIAL', 'STANDARD'))).toEqual([403, 'MFA_REQUIRED']);
    expect(policyDenials(api, from)).toEqual([{ action: 'AZ-03', reason: 'PROFILE_PC_01' }]);
    expect(await roomSnapshot(db, noMfaRoom)).toBe(before);

    const roomId = await createRoom(owner, 'STANDARD', 'Owner signed in long ago');
    try {
      await signedInAgo(db, api, owner, 5 * HOUR); // fine for STANDARD (12 hours), not CONFIDENTIAL (4)
      before = await roomSnapshot(db, roomId);
      from = api.events.length;
      expect(status(await change(owner, roomId, 'CONFIDENTIAL', 'STANDARD'))).toEqual([401, 'REAUTH_REQUIRED']);
      expect(policyDenials(api, from)).toEqual([{ action: 'AZ-03', reason: 'PROFILE_PC_02' }]);
      expect(await roomSnapshot(db, roomId)).toBe(before);
    } finally {
      await signedInAgo(db, api, owner, 0);
    }
  });

  it('PC-07: an invitation sharing older key versions is revoked when the room becomes RESTRICTED', async () => {
    const roomId = await createRoom(owner, 'STANDARD', 'History invitation');
    // A synthetic version 2 (the rekey that creates one is Phase 11): version 1 RETIRED, 2 current,
    // as in tests/authz/invitations.test.ts. The invitation carries envelopes for both versions.
    await db.query(`UPDATE room_key_versions SET status = 'RETIRED', retired_at = now() WHERE room_id = $1`, [roomId]);
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
    const invitee = await mfaPersonWithVault(api, db);
    const filler = (): string => randomBytes(384).toString('base64url');
    const created = await invite(owner, roomId, invitee, 'VIEWER', {
      ...confirmedFingerprint(invitee),
      envelopes: [
        { keyVersion: 1, wrappedKey: filler() },
        { keyVersion: 2, wrappedKey: filler() },
      ],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const id = (created.body['invitation'] as { id: string }).id;
    await stepUp(api, owner, owner.secret);
    expect((await change(owner, roomId, 'RESTRICTED', 'STANDARD')).status).toBe(200);
    const row = await db.query<{ status: string; envelopes: number }>(
      `SELECT status::text, (SELECT count(*)::int FROM key_envelopes WHERE invitation_id = $1) AS envelopes
         FROM invitations WHERE id = $1`,
      [id],
    );
    expect(row.rows[0]).toEqual({ status: 'REVOKED', envelopes: 0 });
  });
});

describe('downgrades (CM-T048)', () => {
  it('need a step-up within 5 minutes, extend nothing, and are recorded with high severity', async () => {
    const roomId = await createRoom(owner, 'RESTRICTED', 'Downgrade');
    await stepUp(api, owner, owner.secret);
    await inviteAndAccept(owner, roomId, member, 'MEMBER', confirmedFingerprint(member));
    await uploadFile(owner, roomId, randomBytes(64), { overrides: { expiresAt: inFromNow(20 * DAY, now()) } });
    await createdSecret(owner, roomId, member, 'Short', { expiresAt: inFromNow(10 * HOUR, now()) });
    const filesBefore = await expiries('encrypted_files', roomId);
    const secretsBefore = await expiries('secrets', roomId);

    // A step-up 6 minutes old passes PC-03 (15 minutes) but not the downgrade rule (5 minutes).
    await steppedUpAgo(db, api, owner, 6 * MINUTE);
    const before = await roomSnapshot(db, roomId);
    let from = api.events.length;
    expect(status(await change(owner, roomId, 'STANDARD', 'RESTRICTED'))).toEqual([401, 'STEP_UP_REQUIRED']);
    expect(policyDenials(api, from)).toEqual([{ action: 'AZ-03', reason: 'PROFILE_DOWNGRADE_STEP_UP' }]);
    expect(await roomSnapshot(db, roomId)).toBe(before);

    await stepUp(api, owner, owner.secret);
    from = api.events.length;
    const done = await change(owner, roomId, 'STANDARD', 'RESTRICTED');
    expect(done.body).toEqual({ securityProfile: 'STANDARD', policyVersion: 1, change: 'DOWNGRADE' });
    const event = api.events.slice(from).find((e) => e.name === 'PROFILE_DOWNGRADED');
    expect(event?.details).toMatchObject({
      roomId,
      from: 'RESTRICTED',
      to: 'STANDARD',
      severity: 'HIGH',
      filesClamped: 0,
    });
    // EV-10-03: the recorded event, for the report (synthetic identifiers only).
    const dir = resolve('test-results', 'evidence');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'EV-10-03_downgrade-event.json'),
      `${JSON.stringify(event, null, 2)}
`,
    );
    // Nothing is extended by the weaker profile.
    expect(await expiries('encrypted_files', roomId)).toEqual(filesBefore);
    expect(await expiries('secrets', roomId)).toEqual(secretsBefore);
  });

  it('CONFIDENTIAL to STANDARD needs the 5-minute step-up too', async () => {
    const roomId = await createRoom(owner, 'CONFIDENTIAL', 'Confidential downgrade');
    await steppedUpAgo(db, api, owner, null);
    expect(status(await change(owner, roomId, 'STANDARD', 'CONFIDENTIAL'))).toEqual([401, 'STEP_UP_REQUIRED']);
    expect((await roomProfile(roomId)).profile).toBe('CONFIDENTIAL');
    await stepUp(api, owner, owner.secret);
    expect((await change(owner, roomId, 'STANDARD', 'CONFIDENTIAL')).status).toBe(200);
  });

  it('a profile change is allowed while the room is write-locked, and keeps the lock', async () => {
    const roomId = await createRoom(owner, 'STANDARD', 'Locked upgrade');
    const leaving = await personWithVault(api, db);
    await addMember(db, roomId, leaving.userId, 'VIEWER');
    expect((await owner.browser.request('POST', `/rooms/${roomId}/members/${leaving.userId}/remove`, {})).status).toBe(
      200,
    );
    expect((await change(owner, roomId, 'CONFIDENTIAL', 'STANDARD')).status).toBe(200);
    const { rows } = await db.query<{ key_state: string }>('SELECT key_state::text FROM rooms WHERE id = $1', [roomId]);
    expect(rows[0]?.key_state).toBe('REKEY_REQUIRED');
  });
});

describe('concurrency: the profile that commits first decides (CM-T048)', () => {
  it('two concurrent changes from the same stored profile: one wins, the other is stale', async () => {
    const roomId = await standardRoom('Concurrent changes');
    await stepUp(api, owner, owner.secret);
    const locker = await testDatabase(inject('databaseName')).connect('api');
    try {
      const [first, second] = await inRoomLockOrder(observer, locker, roomId, [
        () => change(owner, roomId, 'RESTRICTED', 'STANDARD'),
        () => change(owner, roomId, 'CONFIDENTIAL', 'STANDARD'),
      ]);
      expect(first?.status).toBe(200);
      expect(status(second ?? { status: 0, body: {} })).toEqual([409, 'PROFILE_CHANGED']);
    } finally {
      await locker.end();
    }
    expect((await roomProfile(roomId)).profile).toBe('RESTRICTED');
  });

  it('a note started under STANDARD is judged by RESTRICTED once the upgrade commits first', async () => {
    const roomId = await standardRoom('Upgrade during a write');
    await stepUp(api, owner, owner.secret);
    const locker = await testDatabase(inject('databaseName')).connect('api');
    try {
      const [upgraded, note] = await inRoomLockOrder(observer, locker, roomId, [
        () => change(owner, roomId, 'RESTRICTED', 'STANDARD'),
        async () =>
          (await createNote(member, roomId, 'Raced', 'Synthetic', { expiresAt: inFromNow(60 * DAY, now()) })).response,
      ]);
      expect(upgraded?.status).toBe(200);
      // The gate saw STANDARD (no maximum); the locked re-check sees RESTRICTED (30 days).
      expect(status(note ?? { status: 0, body: {} })).toEqual([422, 'EXPIRY_NOT_ALLOWED']);
    } finally {
      await locker.end();
    }
    expect(await expiries('encrypted_notes', roomId)).toEqual([]);
  });

  it('an ADMIN without MFA who started a write under STANDARD is refused once CONFIDENTIAL commits first', async () => {
    const roomId = await standardRoom('MFA during a write');
    const plainAdmin = await personWithVault(api, db);
    await addMember(db, roomId, plainAdmin.userId, 'ADMIN');
    const locker = await testDatabase(inject('databaseName')).connect('api');
    const from = api.events.length;
    try {
      const [upgraded, rename] = await inRoomLockOrder(observer, locker, roomId, [
        () => change(owner, roomId, 'CONFIDENTIAL', 'STANDARD'),
        () => plainAdmin.browser.request('POST', `/rooms/${roomId}/rename`, { name: 'Renamed in the race' }),
      ]);
      expect(upgraded?.status).toBe(200);
      // The gate passed under STANDARD (no MFA needed); the locked re-check applies PC-01.
      expect(status(rename ?? { status: 0, body: {} })).toEqual([403, 'MFA_REQUIRED']);
    } finally {
      await locker.end();
    }
    expect(policyDenials(api, from)).toEqual([{ action: 'AZ-02', reason: 'PROFILE_PC_01' }]);
    const { rows } = await db.query<{ name: string }>('SELECT name FROM rooms WHERE id = $1', [roomId]);
    expect(rows[0]?.name).toBe('MFA during a write');
  });

  it('a removal started without a step-up under STANDARD is refused once RESTRICTED commits first', async () => {
    const roomId = await standardRoom('Removal during an upgrade');
    const target = await personWithVault(api, db);
    await addMember(db, roomId, target.userId, 'VIEWER');
    await stepUp(api, owner, owner.secret);
    await steppedUpAgo(db, api, admin, null);
    const locker = await testDatabase(inject('databaseName')).connect('api');
    const from = api.events.length;
    try {
      const [upgraded, removal] = await inRoomLockOrder(observer, locker, roomId, [
        () => change(owner, roomId, 'RESTRICTED', 'STANDARD'),
        () => admin.browser.request('POST', `/rooms/${roomId}/members/${target.userId}/remove`, {}),
      ]);
      expect(upgraded?.status).toBe(200);
      // The gate passed under STANDARD; the locked re-check applies RESTRICTED's PC-03.
      expect(status(removal ?? { status: 0, body: {} })).toEqual([401, 'STEP_UP_REQUIRED']);
    } finally {
      await locker.end();
    }
    expect(policyDenials(api, from)).toEqual([{ action: 'AZ-09', reason: 'PROFILE_PC_03' }]);
    const { rows } = await db.query<{ status: string }>(
      'SELECT status::text FROM room_members WHERE room_id = $1 AND user_id = $2',
      [roomId, target.userId],
    );
    expect(rows[0]?.status).toBe('ACTIVE');
  });

  it('a non-burn secret started under CONFIDENTIAL is refused once RESTRICTED commits first', async () => {
    const roomId = await createRoom(owner, 'CONFIDENTIAL', 'Burn during an upgrade');
    await inviteAndAccept(owner, roomId, member, 'MEMBER');
    await stepUp(api, owner, owner.secret);
    const locker = await testDatabase(inject('databaseName')).connect('api');
    try {
      const [upgraded, secret] = await inRoomLockOrder(observer, locker, roomId, [
        () => change(owner, roomId, 'RESTRICTED', 'CONFIDENTIAL'),
        async () =>
          (
            await createSecret(member, roomId, owner, 'Raced secret', {
              burnAfterReading: false,
              expiresAt: inFromNow(HOUR, now()),
            })
          ).response,
      ]);
      expect(upgraded?.status).toBe(200);
      expect(status(secret ?? { status: 0, body: {} })).toEqual([422, 'BURN_REQUIRED']);
    } finally {
      await locker.end();
    }
    const { rows } = await db.query('SELECT 1 FROM secrets WHERE room_id = $1 AND burn_after_reading = false', [
      roomId,
    ]);
    expect(rows).toEqual([]);
  });
});
