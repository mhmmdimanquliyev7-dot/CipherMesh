import { currentPolicy, SECURITY_PROFILES, type SecurityProfile } from '@ciphermesh/shared';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { ROOM_CASES } from '../helpers/bola-cases';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { requireStorageEnv, startUpload, encryptForRoom, uploadFile } from '../helpers/files';
import { createNote } from '../helpers/notes';
import {
  confirmedFingerprint,
  policyDenials,
  roomSnapshot,
  signedInAgo,
  STALE_STEP_UP_MS,
  steppedUpAgo,
} from '../helpers/policy';
import { invite, inviteAndAccept } from '../helpers/room-crypto';
import {
  addMember,
  createRoom,
  mfaPersonWithVault,
  personWithVault,
  roomRow,
  stepUp,
  type Person,
} from '../helpers/rooms';
import { createdSecret, createSecret, inFromNow, reveal } from '../helpers/secrets';

// CM-T049, the policy enforcement matrix: every profile control PC-01 to PC-16 that the API
// enforces, for STANDARD, CONFIDENTIAL and RESTRICTED, with an allowed and a denied request
// against the real API, real sessions (real MFA and step-ups), PostgreSQL as cm_api and the local
// object storage. Each denial asserts the status, the stable error code, the ROOM_ACCESS_DENIED
// reason recorded for it and that the room's rows did not change. Profile changes and their
// concurrency are tests/policy/profile-change.test.ts. Controls without an allowed or denied case
// in Phase 10 say so instead of inventing one: PC-11 (no route, CM-T045) and PC-14 (cryptoperiod,
// CM-T052 in Phase 11). Every text and key is synthetic.
type MfaPerson = Person & { readonly secret: string };
/** What every request helper returns (the helpers' own Response types are supersets). */
type Response = { readonly status: number; readonly body: Record<string, unknown> };

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const PROFILES: readonly SecurityProfile[] = SECURITY_PROFILES;

let api: AuthTestApi;
let db: pg.Client;
let owner: MfaPerson;
let admin: MfaPerson;
let member: MfaPerson;
let viewer: MfaPerson;
/** A member without MFA, placed by fixture in all three rooms (CONFIDENTIAL and RESTRICTED refuse them). */
let plain: Person;
const rooms = {} as Record<SecurityProfile, string>;

const status = (response: Response): [number, unknown] => [response.status, errorCode(response)];
const now = (): Date => api.clock.now();
const restricted = (profile: SecurityProfile): boolean => profile === 'RESTRICTED';
/** Invitation extras: RESTRICTED requires the invitee's fingerprint (PC-05). */
const extrasFor = (profile: SecurityProfile, invitee: Person): Record<string, unknown> =>
  restricted(profile) ? confirmedFingerprint(invitee) : {};
/** A content expiry every profile accepts (PC-08). */
const validExpiry = (): string => inFromNow(DAY, now());

/** Expects a policy refusal: status, code, the recorded reason, and no change to the room. */
async function expectRefused(
  roomId: string,
  request: () => Promise<Response>,
  expected: { readonly status: number; readonly code: string; readonly reason: string; readonly action: string },
): Promise<void> {
  const before = await roomSnapshot(db, roomId);
  const from = api.events.length;
  const response = await request();
  expect(status(response), JSON.stringify(response.body)).toEqual([expected.status, expected.code]);
  expect(policyDenials(api, from)).toEqual([{ action: expected.action, reason: expected.reason }]);
  expect(await roomSnapshot(db, roomId)).toBe(before);
}

beforeAll(async () => {
  loadDatabaseTestEnv();
  requireStorageEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  owner = await mfaPersonWithVault(api, db);
  admin = await mfaPersonWithVault(api, db);
  member = await mfaPersonWithVault(api, db);
  viewer = await mfaPersonWithVault(api, db);
  plain = await personWithVault(api, db);
  for (const profile of PROFILES) {
    const roomId = await createRoom(owner, profile, `Policy matrix ${profile}`);
    rooms[profile] = roomId;
    if (restricted(profile)) await stepUp(api, owner, owner.secret);
    for (const [who, role] of [
      [admin, 'ADMIN'],
      [member, 'MEMBER'],
      [viewer, 'VIEWER'],
    ] as const) {
      await inviteAndAccept(owner, roomId, who, role, extrasFor(profile, who));
    }
    await addMember(db, roomId, plain.userId, 'MEMBER');
  }
}, 300_000);
afterAll(async () => {
  await api.close();
  await db.end();
});

// ----------------------------------------------------------------------- PC-01 and PC-02

describe('PC-01 and PC-02: the access gates apply to every room route', () => {
  it('allows a member who meets the profile, in every profile', async () => {
    for (const profile of PROFILES) {
      const response = await member.browser.request('GET', `/rooms/${rooms[profile]}`);
      expect(response.status, profile).toBe(200);
      expect(response.body['room']).toMatchObject({ securityProfile: profile, policyVersion: 1 });
    }
    // A session without MFA is enough in STANDARD (PC-01 = No).
    expect((await plain.browser.request('GET', `/rooms/${rooms.STANDARD}`)).status).toBe(200);
  });

  it.each(ROOM_CASES.map((c) => [c.key, c] as const))('PC-01 on %s', async (_key, c) => {
    for (const profile of ['CONFIDENTIAL', 'RESTRICTED'] as const) {
      await expectRefused(rooms[profile], () => c.send(plain, { roomId: rooms[profile] }), {
        status: 403,
        code: 'MFA_REQUIRED',
        reason: 'PROFILE_PC_01',
        action: c.action ?? '',
      });
    }
    if (!c.mutates) {
      const response = await c.send(plain, { roomId: rooms.STANDARD });
      expect(errorCode(response), c.key).not.toBe('MFA_REQUIRED');
    }
  });

  it.each(ROOM_CASES.map((c) => [c.key, c] as const))('PC-02 on %s', async (_key, c) => {
    try {
      for (const profile of PROFILES) {
        const maxAge = currentPolicy(profile).access.maxAuthenticationAgeMs;
        await signedInAgo(db, api, member, maxAge + MINUTE);
        await expectRefused(rooms[profile], () => c.send(member, { roomId: rooms[profile] }), {
          status: 401,
          code: 'REAUTH_REQUIRED',
          reason: 'PROFILE_PC_02',
          action: c.action ?? '',
        });
      }
    } finally {
      await signedInAgo(db, api, member, 0);
    }
  });

  it('PC-02 allows a sign-in just inside each limit and refuses it just outside', async () => {
    try {
      for (const profile of PROFILES) {
        const maxAge = currentPolicy(profile).access.maxAuthenticationAgeMs;
        await signedInAgo(db, api, member, maxAge - MINUTE);
        expect((await member.browser.request('GET', `/rooms/${rooms[profile]}`)).status, profile).toBe(200);
        await signedInAgo(db, api, member, maxAge + MINUTE);
        expect(status(await member.browser.request('GET', `/rooms/${rooms[profile]}`)), profile).toEqual([
          401,
          'REAUTH_REQUIRED',
        ]);
      }
    } finally {
      await signedInAgo(db, api, member, 0);
    }
  });

  it("applies each room's own profile: the same session passes STANDARD and is refused in CONFIDENTIAL", async () => {
    expect((await plain.browser.request('GET', `/rooms/${rooms.STANDARD}/members`)).status).toBe(200);
    expect(status(await plain.browser.request('GET', `/rooms/${rooms.CONFIDENTIAL}/members`))).toEqual([
      403,
      'MFA_REQUIRED',
    ]);
  });

  it('never consults a profile for a non-member: outsiders get the generic 404 before any gate', async () => {
    const outsider = await personWithVault(api, db);
    for (const profile of PROFILES) {
      const from = api.events.length;
      const response = await outsider.browser.request('GET', `/rooms/${rooms[profile]}`);
      expect(status(response)).toEqual([404, 'NOT_FOUND']);
      expect(policyDenials(api, from)).toEqual([]);
    }
  });
});

// ------------------------------------------------------------------------------------ PC-03

describe('PC-03: sensitive operations need a step-up within 15 minutes in RESTRICTED only', () => {
  it.each(PROFILES)('reveal a secret (%s)', async (profile) => {
    const roomId = rooms[profile];
    const secretId = await createdSecret(owner, roomId, member, 'Synthetic policy secret', {
      expiresAt: inFromNow(30 * MINUTE, now()),
    });
    await steppedUpAgo(db, api, member, null);
    if (!restricted(profile)) {
      expect((await reveal(member, roomId, secretId)).status).toBe(200);
      return;
    }
    const refusal = { status: 401, code: 'STEP_UP_REQUIRED', reason: 'PROFILE_PC_03', action: 'AZ-24' };
    // Nothing is released or burned by a refused reveal (INV-13): the row is unchanged.
    await expectRefused(roomId, () => reveal(member, roomId, secretId), refusal);
    await steppedUpAgo(db, api, member, STALE_STEP_UP_MS);
    await expectRefused(roomId, () => reveal(member, roomId, secretId), refusal);
    await stepUp(api, member, member.secret);
    expect((await reveal(member, roomId, secretId)).status).toBe(200);
  });

  it.each(PROFILES)('file download URL (%s)', async (profile) => {
    const roomId = rooms[profile];
    const { fileId } = await uploadFile(owner, roomId, randomBytes(256), { overrides: { expiresAt: validExpiry() } });
    const download = () => member.browser.request('POST', `/rooms/${roomId}/files/${fileId}/download-url`, {});
    await steppedUpAgo(db, api, member, null);
    if (!restricted(profile)) {
      expect((await download()).status).toBe(200);
      return;
    }
    const refusal = { status: 401, code: 'STEP_UP_REQUIRED', reason: 'PROFILE_PC_03', action: 'AZ-17' };
    await expectRefused(roomId, download, refusal);
    await steppedUpAgo(db, api, member, STALE_STEP_UP_MS);
    await expectRefused(roomId, download, refusal);
    await stepUp(api, member, member.secret);
    expect((await download()).status).toBe(200);
  });

  it.each(PROFILES)('invite and approve (%s)', async (profile) => {
    const roomId = rooms[profile];
    const invitee = await mfaPersonWithVault(api, db);
    await steppedUpAgo(db, api, owner, null);
    await steppedUpAgo(db, api, admin, null);
    const byOwner = () => invite(owner, roomId, invitee, 'VIEWER', extrasFor(profile, invitee));
    if (restricted(profile)) {
      await expectRefused(roomId, byOwner, {
        status: 401,
        code: 'STEP_UP_REQUIRED',
        reason: 'PROFILE_PC_03',
        action: 'AZ-06',
      });
      await stepUp(api, owner, owner.secret);
    }
    expect((await byOwner()).status).toBe(201);

    // Approval exists where PC-04 applies: an ADMIN's invitation waits for the OWNER.
    if (profile === 'STANDARD') return;
    const second = await mfaPersonWithVault(api, db);
    if (restricted(profile)) await stepUp(api, admin, admin.secret);
    const created = await invite(admin, roomId, second, 'MEMBER', extrasFor(profile, second));
    expect(created.status).toBe(201);
    const invitation = created.body['invitation'] as { id: string; status: string };
    expect(invitation.status).toBe('PENDING_APPROVAL');
    const approve = () => owner.browser.request('POST', `/rooms/${roomId}/invitations/${invitation.id}/approve`, {});
    await steppedUpAgo(db, api, owner, null);
    if (restricted(profile)) {
      await expectRefused(roomId, approve, {
        status: 401,
        code: 'STEP_UP_REQUIRED',
        reason: 'PROFILE_PC_03',
        action: 'AZ-07',
      });
      await stepUp(api, owner, owner.secret);
    }
    expect((await approve()).status).toBe(200);
  });

  it.each(PROFILES)('remove a member, change the profile, delete the room (%s)', async (profile) => {
    const roomId = await createRoom(owner, profile, `Disposable ${profile}`);
    const target = await personWithVault(api, db);
    await addMember(db, roomId, target.userId, 'VIEWER');
    await steppedUpAgo(db, api, owner, null);
    const remove = () => owner.browser.request('POST', `/rooms/${roomId}/members/${target.userId}/remove`, {});
    const downgrade = () =>
      owner.browser.request('POST', `/rooms/${roomId}/profile`, {
        securityProfile: 'STANDARD',
        expectedProfile: profile,
      });
    const destroy = () => owner.browser.request('POST', `/rooms/${roomId}/delete`, {});
    if (restricted(profile)) {
      for (const [request, action] of [
        [remove, 'AZ-09'],
        [downgrade, 'AZ-03'],
        [destroy, 'AZ-04'],
      ] as const) {
        await expectRefused(roomId, request, {
          status: 401,
          code: 'STEP_UP_REQUIRED',
          reason: 'PROFILE_PC_03',
          action,
        });
      }
      await stepUp(api, owner, owner.secret);
    }
    expect((await remove()).status).toBe(200);
    // Deleting needs a step-up in every profile (AZ-04), as the route has required since Phase 5.
    if (!restricted(profile)) {
      expect(status(await destroy())).toEqual([401, 'STEP_UP_REQUIRED']);
      await stepUp(api, owner, owner.secret);
    }
    expect((await destroy()).status).toBe(200);
  });
});

// ------------------------------------------------------------------------------ PC-04 to PC-07

describe('PC-04 to PC-07: invitation rules', () => {
  it.each(PROFILES)(
    'PC-04 and PC-06: approval of ADMIN invitations and the server-set validity (%s)',
    async (profile) => {
      const roomId = rooms[profile];
      const invitee = await mfaPersonWithVault(api, db);
      if (restricted(profile)) await stepUp(api, admin, admin.secret);
      const created = await invite(admin, roomId, invitee, 'VIEWER', {
        ...extrasFor(profile, invitee),
        // A client cannot choose the validity: the strict schema refuses the field.
      });
      expect(created.status).toBe(201);
      const id = (created.body['invitation'] as { id: string }).id;
      const { rows } = await db.query<{ status: string; ms: number }>(
        `SELECT status::text, (extract(epoch FROM expires_at - created_at) * 1000)::bigint AS ms FROM invitations WHERE id = $1`,
        [id],
      );
      const rules = currentPolicy(profile).invitations;
      expect(rows[0]?.status).toBe(rules.adminInvitationNeedsApproval ? 'PENDING_APPROVAL' : 'PENDING');
      expect(Number(rows[0]?.ms)).toBe(rules.validityMs);
      const chosen = await invite(admin, roomId, await mfaPersonWithVault(api, db), 'VIEWER', {
        expiresAt: inFromNow(30 * DAY, now()),
      });
      expect(status(chosen)).toEqual([400, 'VALIDATION_FAILED']);
    },
  );

  it.each(PROFILES)('PC-05: the fingerprint confirmation (%s)', async (profile) => {
    const roomId = rooms[profile];
    const invitee = await mfaPersonWithVault(api, db);
    if (restricted(profile)) await stepUp(api, owner, owner.secret);
    const without = await invite(owner, roomId, invitee, 'VIEWER');
    if (restricted(profile)) {
      expect(status(without)).toEqual([422, 'FINGERPRINT_REQUIRED']);
      const wrong = await invite(owner, roomId, invitee, 'VIEWER', { confirmedFingerprint: '0'.repeat(64) });
      expect(status(wrong)).toEqual([409, 'FINGERPRINT_MISMATCH']);
      expect((await invite(owner, roomId, invitee, 'VIEWER', confirmedFingerprint(invitee))).status).toBe(201);
    } else {
      expect(without.status).toBe(201);
    }
  });

  it('PC-07: history in STANDARD and CONFIDENTIAL, the current version only in RESTRICTED', () => {
    // Allowed and denied requests need a second key version, which only the rekey of Phase 11
    // creates. tests/authz/invitations.test.ts ("gives history to new members ... (PC-07)")
    // builds a synthetic version 2 and asserts 201 in STANDARD and 422 in RESTRICTED; here the
    // values the invitation service reads come from the catalogue.
    expect(PROFILES.map((p) => currentPolicy(p).invitations.keyHistory)).toEqual([
      'all-retained',
      'all-retained',
      'current-only',
    ]);
  });
});

// ------------------------------------------------------------------------------------- PC-08

describe('PC-08: expiry of files and notes', () => {
  const cases = (profile: SecurityProfile) => {
    const max = currentPolicy(profile).contentExpiry.maxMs;
    return {
      allowed: max === null ? [null, inFromNow(400 * DAY, now())] : [inFromNow(max - MINUTE, now())],
      denied: max === null ? [] : [null, inFromNow(max + MINUTE, now())],
    };
  };

  it.each(PROFILES)('notes (%s)', async (profile) => {
    const roomId = rooms[profile];
    const { allowed, denied } = cases(profile);
    for (const expiresAt of allowed) {
      const { response } = await createNote(member, roomId, 'Synthetic', 'Policy body', { expiresAt });
      expect(response.status, String(expiresAt)).toBe(201);
    }
    for (const expiresAt of denied) {
      const before = await roomSnapshot(db, roomId);
      const { response } = await createNote(member, roomId, 'Synthetic', 'Policy body', { expiresAt });
      expect(status(response), String(expiresAt)).toEqual([422, 'EXPIRY_NOT_ALLOWED']);
      expect(await roomSnapshot(db, roomId)).toBe(before);
    }
  });

  it.each(PROFILES)('files (%s)', async (profile) => {
    const roomId = rooms[profile];
    const { allowed, denied } = cases(profile);
    for (const expiresAt of allowed) {
      const file = await encryptForRoom(member, roomId, randomBytes(64));
      expect((await startUpload(member, roomId, file, { expiresAt })).status, String(expiresAt)).toBe(201);
    }
    for (const expiresAt of denied) {
      const before = await roomSnapshot(db, roomId);
      const file = await encryptForRoom(member, roomId, randomBytes(64));
      expect(status(await startUpload(member, roomId, file, { expiresAt })), String(expiresAt)).toEqual([
        422,
        'EXPIRY_NOT_ALLOWED',
      ]);
      expect(await roomSnapshot(db, roomId)).toBe(before);
    }
  });
});

// ------------------------------------------------------------------------------ PC-09, PC-10

describe('PC-09 and PC-10: secret lifetime and burn-after-reading', () => {
  it.each(PROFILES)('%s', async (profile) => {
    const roomId = rooms[profile];
    const { maxLifetimeMs, burnMandatory } = currentPolicy(profile).secrets;
    const attempt = (overrides: Record<string, unknown>) =>
      createSecret(owner, roomId, member, 'Synthetic lifetime', overrides);
    expect((await attempt({ expiresAt: inFromNow(maxLifetimeMs - MINUTE, now()) })).response.status).toBe(201);
    const before = await roomSnapshot(db, roomId);
    const tooLong = await attempt({ expiresAt: inFromNow(maxLifetimeMs + MINUTE, now()) });
    expect(status(tooLong.response)).toEqual([422, 'EXPIRY_NOT_ALLOWED']);
    const noBurn = await attempt({ burnAfterReading: false, expiresAt: inFromNow(HOUR / 2, now()) });
    if (burnMandatory) {
      expect(status(noBurn.response)).toEqual([422, 'BURN_REQUIRED']);
      expect(await roomSnapshot(db, roomId)).toBe(before);
    } else {
      expect(noBurn.response.status).toBe(201);
    }
  });
});

// ---------------------------------------------------------------------------- PC-11, PC-12

describe('PC-11 and PC-12', () => {
  it('PC-11: no external-link route exists before CM-T045, in any profile', async () => {
    expect(ROOM_CASES.filter((c) => c.action === 'AZ-26')).toEqual([]);
    for (const profile of PROFILES) {
      const response = await member.browser.request('POST', `/rooms/${rooms[profile]}/external-links`, {});
      expect(response.status).toBe(404);
    }
  });

  it.each(PROFILES)('PC-12: file key material and download URLs for a VIEWER (%s)', async (profile) => {
    const roomId = rooms[profile];
    const { fileId } = await uploadFile(owner, roomId, randomBytes(128), { overrides: { expiresAt: validExpiry() } });
    await stepUp(api, viewer, viewer.secret);
    const read = () => viewer.browser.request('GET', `/rooms/${roomId}/files/${fileId}`);
    const download = () => viewer.browser.request('POST', `/rooms/${roomId}/files/${fileId}/download-url`, {});
    if (currentPolicy(profile).viewerMayObtainFileKeys) {
      expect((await read()).status).toBe(200);
      expect((await download()).status).toBe(200);
      return;
    }
    for (const request of [read, download]) {
      await expectRefused(roomId, request, {
        status: 403,
        code: 'FORBIDDEN',
        reason: 'PROFILE_PC_12',
        action: 'AZ-17',
      });
    }
    // The list still shows that the file exists, without key material.
    const list = await viewer.browser.request('GET', `/rooms/${roomId}/files`);
    expect(list.status).toBe(200);
  });
});

// ------------------------------------------------------------------------------------- PC-13

describe('PC-13: what each audit level records', () => {
  it.each(PROFILES)('%s', async (profile) => {
    const roomId = rooms[profile];
    const level = currentPolicy(profile).auditLevel;
    const { fileId } = await uploadFile(owner, roomId, randomBytes(64), { overrides: { expiresAt: validExpiry() } });
    const { response: note } = await createNote(member, roomId, 'Audit', 'Synthetic', { expiresAt: validExpiry() });
    const noteId = (note.body['note'] as { id: string }).id;
    await stepUp(api, member, member.secret);
    const from = api.events.length;
    expect((await member.browser.request('POST', `/rooms/${roomId}/files/${fileId}/download-url`, {})).status).toBe(
      200,
    );
    expect((await member.browser.request('GET', `/rooms/${roomId}/notes/${noteId}`)).status).toBe(200);
    expect((await member.browser.request('GET', `/rooms/${roomId}/members`)).status).toBe(200);
    expect((await member.browser.request('GET', `/rooms/${roomId}/envelopes`)).status).toBe(200);
    const names = api.events.slice(from).map((e) => e.name);
    const extended = level !== 'BASELINE';
    const full = level === 'FULL';
    expect(names.includes('FILE_DOWNLOAD_ISSUED'), 'download URL').toBe(extended);
    expect(names.includes('NOTE_READ'), 'note read').toBe(extended);
    expect(names.includes('MEMBER_LIST_VIEWED'), 'member list').toBe(full);
    expect(names.includes('ENVELOPES_FETCHED'), 'envelopes').toBe(full);
    // FULL events carry the room and a count only.
    for (const event of api.events
      .slice(from)
      .filter((e) => e.name.endsWith('_VIEWED') || e.name.endsWith('_FETCHED'))) {
      expect(Object.keys(event.details ?? {}).sort()).toEqual(['count', 'roomId']);
      expect(event.details?.['roomId']).toBe(roomId);
    }
  });
});

// ------------------------------------------------------------------------------ PC-14 to PC-16

describe('PC-14 to PC-16: key lifecycle rules', () => {
  it('PC-14: the cryptoperiod is a catalogue value enforced by the rekey worker of CM-T052 (Phase 11)', () => {
    // No allowed or denied request exists in Phase 10: nothing sets CRYPTOPERIOD_EXPIRED yet, and
    // the room page lists the cryptoperiod as not yet enforced.
    expect(PROFILES.map((p) => currentPolicy(p).cryptoperiodMs)).toEqual([null, 180 * DAY, 90 * DAY]);
  });

  it.each(PROFILES)('PC-15 and PC-16: losing a member write-locks the room in every profile (%s)', async (profile) => {
    const roomId = await createRoom(owner, profile, `Rekey ${profile}`);
    if (restricted(profile)) await stepUp(api, owner, owner.secret);
    await inviteAndAccept(owner, roomId, member, 'MEMBER', extrasFor(profile, member));
    const leaving = await personWithVault(api, db);
    await addMember(db, roomId, leaving.userId, 'VIEWER');
    const secretId = await createdSecret(owner, roomId, member, 'Before the lock', {
      expiresAt: inFromNow(30 * MINUTE, now()),
    });
    expect((await owner.browser.request('POST', `/rooms/${roomId}/members/${leaving.userId}/remove`, {})).status).toBe(
      200,
    );
    expect((await roomRow(db, roomId)).key_state).toBe('REKEY_REQUIRED');
    // PC-16: content writes and invitations are refused; reveals stay possible.
    const before = await roomSnapshot(db, roomId);
    const note = await createNote(member, roomId, 'Locked', 'Synthetic', { expiresAt: validExpiry() });
    expect(status(note.response)).toEqual([409, 'REKEY_REQUIRED']);
    const secret = await createSecret(owner, roomId, member, 'Locked', { expiresAt: inFromNow(HOUR / 2, now()) });
    expect(status(secret.response)).toEqual([409, 'REKEY_REQUIRED']);
    const invitee = await mfaPersonWithVault(api, db);
    expect(status(await invite(owner, roomId, invitee, 'VIEWER', extrasFor(profile, invitee)))).toEqual([
      409,
      'REKEY_REQUIRED',
    ]);
    expect(await roomSnapshot(db, roomId)).toBe(before);
    if (restricted(profile)) await stepUp(api, member, member.secret);
    expect((await reveal(member, roomId, secretId)).status).toBe(200);
  });
});

// ------------------------------------------------------------------------ policy versions

describe('stored policy versions (CM-T046): an unknown version fails closed', () => {
  it('refuses every request to a room whose version this server does not know, then serves it again', async () => {
    const roomId = await createRoom(owner, 'STANDARD', 'Future policy');
    const invitee = await mfaPersonWithVault(api, db);
    const created = await invite(owner, roomId, invitee, 'VIEWER');
    expect(created.status).toBe(201);
    const invitationId = (created.body['invitation'] as { id: string }).id;
    await db.query('UPDATE rooms SET policy_version = 2 WHERE id = $1', [roomId]);
    try {
      for (const [request, action] of [
        [() => owner.browser.request('GET', `/rooms/${roomId}`), 'AZ-01'],
        [() => owner.browser.request('POST', `/rooms/${roomId}/rename`, { name: 'Renamed' }), 'AZ-02'],
        [
          () =>
            owner.browser.request('POST', `/rooms/${roomId}/profile`, {
              securityProfile: 'STANDARD',
              expectedProfile: 'STANDARD',
            }),
          'AZ-03',
        ],
      ] as const) {
        await expectRefused(roomId, request, {
          status: 503,
          code: 'POLICY_UNSUPPORTED',
          reason: 'POLICY_UNSUPPORTED',
          action,
        });
      }
      // Joining is refused too (no fallback to version 1 or to STANDARD).
      const before = await roomSnapshot(db, roomId);
      const accepted = await invitee.browser.request('POST', `/invitations/${invitationId}/accept`, {});
      expect(status(accepted)).toEqual([503, 'POLICY_UNSUPPORTED']);
      expect(await roomSnapshot(db, roomId)).toBe(before);
    } finally {
      await db.query('UPDATE rooms SET policy_version = 1 WHERE id = $1', [roomId]);
    }
    expect((await owner.browser.request('GET', `/rooms/${roomId}`)).status).toBe(200);
  });

  it('never takes a profile or policy version from the request', async () => {
    const roomId = rooms.RESTRICTED;
    await steppedUpAgo(db, api, member, null);
    const secretId = await createdSecret(owner, roomId, member, 'Forged profile', {
      expiresAt: inFromNow(30 * MINUTE, now()),
    });
    // A forged profile or version in the body is refused by the strict schema; in a header or the
    // query string it changes nothing: the stored RESTRICTED profile still requires the step-up.
    expect(
      status(
        await member.browser.request('POST', `/rooms/${roomId}/secrets/${secretId}/reveal`, {
          securityProfile: 'STANDARD',
          policyVersion: 1,
        }),
      ),
    ).toEqual([400, 'VALIDATION_FAILED']);
    const queried = await member.browser.request(
      'POST',
      `/rooms/${roomId}/secrets/${secretId}/reveal?securityProfile=STANDARD&policyVersion=0`,
      {},
    );
    expect(status(queried)).toEqual([400, 'VALIDATION_FAILED']);
    const from = api.events.length;
    const headed = await member.browser.request(
      'POST',
      `/rooms/${roomId}/secrets/${secretId}/reveal`,
      {},
      {
        'x-security-profile': 'STANDARD',
        'x-policy-version': '0',
      },
    );
    expect(status(headed)).toEqual([401, 'STEP_UP_REQUIRED']);
    expect(policyDenials(api, from)).toEqual([{ action: 'AZ-24', reason: 'PROFILE_PC_03' }]);
    const row = await db.query<{ status: string; material: boolean }>(
      'SELECT status::text, payload_ciphertext IS NOT NULL AS material FROM secrets WHERE id = $1',
      [secretId],
    );
    expect(row.rows[0]).toEqual({ status: 'ACTIVE', material: true });
  });
});

// ------------------------------------------------------------------------------- evidence

describe('EV-10-02: denials in a RESTRICTED room (MFA, step-up, VIEWER download)', () => {
  it('records the three API responses, with their reasons, for the report', async () => {
    const roomId = rooms.RESTRICTED;
    const { fileId } = await uploadFile(owner, roomId, randomBytes(32), { overrides: { expiresAt: validExpiry() } });
    const secretId = await createdSecret(owner, roomId, member, 'Evidence secret', {
      expiresAt: inFromNow(30 * MINUTE, now()),
    });
    await steppedUpAgo(db, api, member, null);
    await stepUp(api, viewer, viewer.secret);
    const from = api.events.length;
    const captured = [
      ['member without MFA opens the room', await plain.browser.request('GET', `/rooms/${roomId}`)],
      ['member without a recent step-up reveals a secret', await reveal(member, roomId, secretId)],
      [
        'VIEWER (with a step-up) asks for a download URL',
        await viewer.browser.request('POST', `/rooms/${roomId}/files/${fileId}/download-url`, {}),
      ],
    ] as const;
    expect(captured.map(([, r]) => status(r))).toEqual([
      [403, 'MFA_REQUIRED'],
      [401, 'STEP_UP_REQUIRED'],
      [403, 'FORBIDDEN'],
    ]);
    const reasons = policyDenials(api, from);
    expect(reasons.map((r) => r.reason)).toEqual(['PROFILE_PC_01', 'PROFILE_PC_03', 'PROFILE_PC_12']);
    const dir = resolve('test-results', 'evidence');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'EV-10-02_restricted-denials.json'),
      `${JSON.stringify(
        {
          evidence: 'EV-10-02 denials in a RESTRICTED room; synthetic accounts, local PostgreSQL',
          responses: captured.map(([request, r]) => ({ request, status: r.status, body: r.body })),
          recordedReasons: reasons,
        },
        null,
        2,
      )}\n`,
    );
  });
});
