import { CryptoErrorCode, isCryptoError } from '@ciphermesh/crypto';
import { randomBytes } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { runRekeyMaintenance } from '../../apps/api/src/db/rekey-cleanup';
import { createLogger } from '../../apps/api/src/logging/logger';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { encryptForRoom, startUpload } from '../helpers/files';
import { createNote, createdNote, readNote } from '../helpers/notes';
import { inRoomLockOrder, steppedUpAgo, STALE_STEP_UP_MS } from '../helpers/policy';
import {
  cancel,
  envelopeVersions,
  finalize,
  finalizeBody,
  keyState,
  rekey,
  startedOf,
  startRekey,
} from '../helpers/rekey';
import { invite, inviteAndAccept, openRoom } from '../helpers/room-crypto';
import { createRoom, mfaPersonWithVault, personWithVault, roomRow, stepUp, type Person } from '../helpers/rooms';

// Phase 11 (CM-T050, CM-T051, CM-T052; ADR-013, DF-10): the rekey state machine against the real
// API and PostgreSQL, with the starter's browser cryptography from packages/crypto. Every room is
// new, every person synthetic.

let api: AuthTestApi;
let db: pg.Client;
let observer: pg.Client;
let locker: pg.Client;

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  observer = await testDatabase(inject('databaseName')).connect('api');
  locker = await testDatabase(inject('databaseName')).connect('api');
});
afterAll(async () => {
  await api.close();
  await db.end();
  await observer.end();
  await locker.end();
});

function workerDatabase(): Database {
  return createDatabase({
    url: new SecretValue(testDatabase(inject('databaseName')).url('worker')),
    logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
    poolMax: 1,
  });
}

/** A STANDARD room with an OWNER, an ADMIN and two MEMBERs, all joined through real invitations. */
async function team(profile = 'STANDARD') {
  const make = profile === 'STANDARD' ? () => personWithVault(api, db) : () => mfaPersonWithVault(api, db);
  const owner = await make();
  const admin = await make();
  const member = await make();
  const other = await make();
  const roomId = await createRoom(owner, profile);
  if (profile === 'RESTRICTED') await stepUp(api, owner, (owner as Person & { secret: string }).secret);
  for (const [who, role] of [
    [admin, 'ADMIN'],
    [member, 'MEMBER'],
    [other, 'MEMBER'],
  ] as const) {
    await inviteAndAccept(owner, roomId, who, role, profile === 'RESTRICTED' ? fingerprintOf(who) : {});
  }
  return { owner, admin, member, other, roomId };
}
const fingerprintOf = (who: Person) => ({ confirmedFingerprint: who.vault?.identity.fingerprint ?? null });

const remove = (who: Person, roomId: string, target: Person) =>
  who.browser.request('POST', `/rooms/${roomId}/members/${target.userId}/remove`, {});

async function operationRow(id: string) {
  const { rows } = await db.query<{ status: string; closed_reason: string | null; mode: string }>(
    'SELECT status::text, closed_reason, mode::text FROM rekey_operations WHERE id = $1',
    [id],
  );
  return rows[0];
}
async function versions(roomId: string) {
  const { rows } = await db.query<{
    version: number;
    status: string;
    reasons: string;
    created_by_operation_id: string | null;
  }>(
    'SELECT version, status::text, reasons::text, created_by_operation_id::text FROM room_key_versions WHERE room_id = $1 ORDER BY version',
    [roomId],
  );
  return rows;
}
const eventNames = (from = 0) => api.events.slice(from).map((e) => e.name);

// ------------------------------------------------------------------- member removal (DF-10, A)

describe('member removal and the mandatory rekey (CM-T050, CM-T051, DF-10)', () => {
  it('removal locks the room; the rekey activates v2 for exactly the remaining members and unlocks it', async () => {
    const { owner, admin, member, other, roomId } = await team();
    expect(await envelopeVersions(member, roomId)).toEqual([1]);
    const noteV1 = await createdNote(member, roomId, 'Before', 'written under version 1');

    await stepUp(api, owner);
    expect((await remove(owner, roomId, other)).status).toBe(200);
    expect(await roomRow(db, roomId)).toMatchObject({ key_state: 'REKEY_REQUIRED', rekey_reasons: '{MEMBER_REMOVED}' });
    // Writes and invitations are refused while locked; reads continue (PC-16).
    expect(errorCode((await createNote(member, roomId, 'Locked', 'refused')).response)).toBe('REKEY_REQUIRED');
    expect((await readNote(member, roomId, noteV1)).body).toBe('written under version 1');

    const from = api.events.length;
    const started = startedOf(await startRekey(admin, roomId));
    expect(started.operation).toMatchObject({ mode: 'MANDATORY', status: 'PENDING', baseVersion: 1, targetVersion: 2 });
    expect(started.recipients.map((r) => r.userId).sort()).toEqual([owner.userId, admin.userId, member.userId].sort());
    expect(started.recipients.every((r) => r.kind === 'MEMBER')).toBe(true);
    expect((await roomRow(db, roomId)).key_state).toBe('REKEYING');
    expect(errorCode((await createNote(member, roomId, 'Still locked', 'refused')).response)).toBe('REKEY_REQUIRED');

    const { body } = await finalizeBody(admin, roomId, started);
    const done = await finalize(admin, roomId, started.operation.id, body);
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    expect(done.body).toMatchObject({ operationId: started.operation.id, keyVersion: 2 });

    expect(await roomRow(db, roomId)).toMatchObject({ key_state: 'ACTIVE', rekey_reasons: '{}' });
    expect(await versions(roomId)).toEqual([
      { version: 1, status: 'RETIRED', reasons: '{INITIAL}', created_by_operation_id: null },
      { version: 2, status: 'ACTIVE', reasons: '{MEMBER_REMOVED}', created_by_operation_id: started.operation.id },
    ]);
    expect(await operationRow(started.operation.id)).toMatchObject({ status: 'COMPLETED' });
    // Every remaining member verifies v2 in "the browser" (signed by an ADMIN, chained to v1).
    for (const who of [owner, admin, member]) {
      const keys = await openRoom(who, roomId);
      expect(keys.map((k) => k.keyVersion)).toEqual([1, 2]);
      expect(keys[1]?.creator.userId).toBe(admin.userId);
    }
    // The removed member has no envelope of any version and no access.
    const { rows } = await db.query('SELECT 1 FROM key_envelopes WHERE room_id = $1 AND recipient_user_id = $2', [
      roomId,
      other.userId,
    ]);
    expect(rows).toEqual([]);
    expect((await other.browser.request('GET', `/rooms/${roomId}/rekey-operations/current`)).status).toBe(404);
    // New content uses v2; content naming v1 is now stale; old content stays readable.
    const stale = await createNote(member, roomId, 'Stale', 'under v1', { keyVersion: 1 });
    expect(errorCode(stale.response)).toBe('KEY_VERSION_STALE');
    const fresh = await createNote(member, roomId, 'After', 'written under version 2');
    expect(fresh.response.status).toBe(201);
    expect((fresh.response.body['note'] as { keyVersion: number }).keyVersion).toBe(2);
    expect((await readNote(owner, roomId, noteV1)).body).toBe('written under version 1');
    expect(eventNames(from).filter((n) => n.startsWith('REKEY') || n.startsWith('KEY_VERSION'))).toEqual([
      'REKEY_STARTED',
      'REKEY_COMPLETED',
      'KEY_VERSION_RETIRED',
    ]);
    // The events carry identifiers, counts and reasons only.
    expect(JSON.stringify(api.events.slice(from))).not.toContain(body.commitment);
  });

  it('a manual rotation (R8) keeps the room writable until activation, then old-version writes are stale', async () => {
    const { owner, member, roomId } = await team();
    const started = startedOf(await startRekey(owner, roomId));
    expect(started.operation.mode).toBe('MANUAL');
    expect((await roomRow(db, roomId)).key_state).toBe('ACTIVE');
    // Writes under v1 continue while the operation is PENDING (no write lock).
    expect((await createNote(member, roomId, 'During', 'still v1')).response.status).toBe(201);
    const { body } = await finalizeBody(owner, roomId, started);
    expect((await finalize(owner, roomId, started.operation.id, body)).status).toBe(200);
    expect((await versions(roomId)).map((v) => [v.version, v.status, v.reasons])).toEqual([
      [1, 'RETIRED', '{INITIAL}'],
      [2, 'ACTIVE', '{MANUAL}'],
    ]);
    expect(errorCode((await createNote(member, roomId, 'After', 'v1', { keyVersion: 1 })).response)).toBe(
      'KEY_VERSION_STALE',
    );
  });

  it('a third version chains to the second; every member opens the whole history', async () => {
    const { owner, admin, member, roomId } = await team();
    expect(await rekey(owner, roomId)).toBe(2);
    expect(await rekey(admin, roomId)).toBe(3);
    const keys = await openRoom(member, roomId);
    expect(keys.map((k) => k.keyVersion)).toEqual([1, 2, 3]);
  });
});

// --------------------------------------------------------------- AZ-13 and OL-13 (authorization)

describe('who may start, finalize and cancel (AZ-13, OL-13)', () => {
  it('MEMBERs cannot start; only the starter finalizes; the starter or the OWNER cancels', async () => {
    const { owner, admin, member, roomId } = await team();
    expect((await startRekey(member, roomId)).status).toBe(403);
    const started = startedOf(await startRekey(admin, roomId));
    const { body } = await finalizeBody(admin, roomId, started);
    // The OWNER is not the starter: it cannot finalize the ADMIN's operation.
    const byOwner = await finalize(owner, roomId, started.operation.id, body);
    expect(byOwner.status).toBe(403);
    expect(errorCode(byOwner)).toBe('REKEY_NOT_STARTER');
    // A MEMBER is refused by the matrix before the operation is even looked up.
    expect(errorCode(await finalize(member, roomId, started.operation.id, body))).toBe('FORBIDDEN');
    expect(errorCode(await cancel(member, roomId, started.operation.id))).toBe('FORBIDDEN');
    // The OWNER can cancel another admin's operation; the room stays as it was (ACTIVE here).
    const cancelled = await cancel(owner, roomId, started.operation.id);
    expect(cancelled.status).toBe(200);
    expect(cancelled.body).toEqual({ operationId: started.operation.id, status: 'CANCELLED', keyState: 'ACTIVE' });
    expect(await operationRow(started.operation.id)).toMatchObject({
      status: 'CANCELLED',
      closed_reason: 'CANCELLED_BY_OWNER',
    });
    // A cancelled operation can never be finalized.
    expect(errorCode(await finalize(admin, roomId, started.operation.id, body))).toBe('REKEY_OPERATION_CLOSED');
    // An ADMIN cannot cancel the OWNER's operation.
    const ownerOp = startedOf(await startRekey(owner, roomId));
    expect(errorCode(await cancel(admin, roomId, ownerOp.operation.id))).toBe('REKEY_NOT_STARTER');
    expect((await cancel(owner, roomId, ownerOp.operation.id)).body).toMatchObject({ status: 'CANCELLED' });
  });

  it('cancelling a mandatory rekey never unlocks the room', async () => {
    const { owner, admin, other, roomId } = await team();
    await stepUp(api, owner);
    await remove(owner, roomId, other);
    const started = startedOf(await startRekey(admin, roomId));
    expect((await roomRow(db, roomId)).key_state).toBe('REKEYING');
    const cancelled = await cancel(admin, roomId, started.operation.id);
    expect(cancelled.body).toMatchObject({ status: 'CANCELLED', keyState: 'REKEY_REQUIRED' });
    expect(await roomRow(db, roomId)).toMatchObject({ key_state: 'REKEY_REQUIRED', rekey_reasons: '{MEMBER_REMOVED}' });
    // Cancelling twice is refused; the room is still locked.
    expect(errorCode(await cancel(admin, roomId, started.operation.id))).toBe('REKEY_OPERATION_CLOSED');
    expect(await rekey(owner, roomId)).toBe(2);
  });

  it('RESTRICTED rooms need a recent step-up to start (PC-03), on the route and on the locked row', async () => {
    const { owner, roomId } = await team('RESTRICTED');
    await steppedUpAgo(db, api, owner, STALE_STEP_UP_MS);
    const refused = await startRekey(owner, roomId);
    expect(refused.status).toBe(401);
    expect(errorCode(refused)).toBe('STEP_UP_REQUIRED');
    await stepUp(api, owner, (owner as Person & { secret: string }).secret);
    expect(await rekey(owner, roomId)).toBe(2);
  });
});

// ------------------------------------------------------------ one live operation, lease, replay

describe('one live operation per room, the lease, and idempotent finalize (ADR-013 steps 1, 4, 6)', () => {
  it("another admin's live operation refuses a start; the starter's own restart supersedes it", async () => {
    const { owner, admin, roomId } = await team();
    const first = startedOf(await startRekey(admin, roomId));
    const busy = await startRekey(owner, roomId);
    expect(busy.status).toBe(409);
    expect(errorCode(busy)).toBe('REKEY_IN_PROGRESS');
    const again = startedOf(await startRekey(admin, roomId));
    expect(await operationRow(first.operation.id)).toMatchObject({ status: 'SUPERSEDED' });
    const { body } = await finalizeBody(admin, roomId, first);
    expect(errorCode(await finalize(admin, roomId, first.operation.id, body))).toBe('REKEY_OPERATION_CLOSED');
    const fresh = await finalizeBody(admin, roomId, again);
    expect((await finalize(admin, roomId, again.operation.id, fresh.body)).status).toBe(200);
  });

  it('an expired lease abandons the operation: finalize is refused, the room stays locked, anyone restarts', async () => {
    const { owner, admin, other, roomId } = await team();
    await stepUp(api, owner);
    await remove(owner, roomId, other);
    const started = startedOf(await startRekey(admin, roomId));
    const { body } = await finalizeBody(admin, roomId, started);
    // The test clock only moves forward; later tests read time from it as well.
    api.clock.advance(10 * 60_000 + 1_000);
    expect(errorCode(await finalize(admin, roomId, started.operation.id, body))).toBe('REKEY_OPERATION_CLOSED');
    expect(await operationRow(started.operation.id)).toMatchObject({
      status: 'ABANDONED',
      closed_reason: 'LEASE_EXPIRED',
    });
    expect((await roomRow(db, roomId)).key_state).toBe('REKEY_REQUIRED');
    // The OWNER recovers at once (no other live operation).
    await stepUp(api, owner);
    expect(await rekey(owner, roomId)).toBe(2);
  });

  it('the worker abandons an expired operation of an idle room (crashed browser, ADR-013 step 6)', async () => {
    const { owner, admin, other, roomId } = await team();
    await stepUp(api, owner);
    await remove(owner, roomId, other);
    const started = startedOf(await startRekey(admin, roomId));
    const worker = workerDatabase();
    try {
      const result = await runRekeyMaintenance(worker.prisma, new Date(api.clock.now().getTime() + 11 * 60_000));
      expect(result.operationsAbandoned).toBeGreaterThanOrEqual(1);
    } finally {
      await worker.close();
    }
    expect(await operationRow(started.operation.id)).toMatchObject({ status: 'ABANDONED' });
    expect(await roomRow(db, roomId)).toMatchObject({ key_state: 'REKEY_REQUIRED', rekey_reasons: '{MEMBER_REMOVED}' });
  });

  it('a repeated identical finalize returns the original result; another payload is refused', async () => {
    const { owner, roomId } = await team();
    const started = startedOf(await startRekey(owner, roomId));
    const { body } = await finalizeBody(owner, roomId, started);
    const first = await finalize(owner, roomId, started.operation.id, body);
    expect(first.status).toBe(200);
    const repeated = await finalize(owner, roomId, started.operation.id, body);
    expect(repeated.status).toBe(200);
    expect(repeated.body).toEqual(first.body);
    // The envelope order does not change the digest; the content does.
    const reordered = { ...body, envelopes: [...body.envelopes].reverse() };
    expect((await finalize(owner, roomId, started.operation.id, reordered)).body).toEqual(first.body);
    const mismatch = { ...body, commitment: randomBytes(32).toString('base64url') };
    expect(errorCode(await finalize(owner, roomId, started.operation.id, mismatch))).toBe('REKEY_PAYLOAD_MISMATCH');
    expect((await versions(roomId)).length).toBe(2);
  });

  it('two concurrent finalizes of one operation activate exactly one version', async () => {
    const { owner, roomId } = await team();
    const started = startedOf(await startRekey(owner, roomId));
    const a = await finalizeBody(owner, roomId, started);
    const b = await finalizeBody(owner, roomId, started);
    const results = await inRoomLockOrder(observer, locker, roomId, [
      () => finalize(owner, roomId, started.operation.id, a.body),
      () => finalize(owner, roomId, started.operation.id, b.body),
    ]);
    expect(results.map((r) => r.status)).toEqual([200, 409]);
    expect(errorCode(results[1] as never)).toBe('REKEY_PAYLOAD_MISMATCH');
    expect((await versions(roomId)).map((v) => [v.version, v.status])).toEqual([
      [1, 'RETIRED'],
      [2, 'ACTIVE'],
    ]);
  });

  it('two admins starting at once: one operation, the other refused (CP-25: one live operation)', async () => {
    const { owner, admin, roomId } = await team();
    const results = await inRoomLockOrder(observer, locker, roomId, [
      () => startRekey(owner, roomId),
      () => startRekey(admin, roomId),
    ]);
    expect(results.map((r) => r.status)).toEqual([201, 409]);
    const { rows } = await db.query(
      "SELECT count(*)::int AS n FROM rekey_operations WHERE room_id = $1 AND status = 'PENDING'",
      [roomId],
    );
    expect(rows[0]).toEqual({ n: 1 });
  });

  it('limits operation starts to 10 per room per hour (CP-25)', async () => {
    const { owner, roomId } = await team();
    for (let i = 0; i < 10; i++) expect((await startRekey(owner, roomId)).status).toBe(201);
    const limited = await startRekey(owner, roomId);
    expect(limited.status).toBe(429);
    expect(errorCode(limited)).toBe('RATE_LIMITED');
  });
});

// ------------------------------------------------------------- the finalize checks (T-21, T-36)

describe('finalize refuses a wrong recipient set, signature, version or commitment (T-21, T-36)', () => {
  it('a missing, an extra (removed member) or a duplicated recipient is 422; nothing is stored', async () => {
    const { owner, admin, member, other, roomId } = await team();
    await stepUp(api, owner);
    await remove(owner, roomId, other);
    const started = startedOf(await startRekey(admin, roomId));
    const { body } = await finalizeBody(admin, roomId, started);
    const missing = { ...body, envelopes: body.envelopes.filter((e) => e.recipientUserId !== member.userId) };
    const extra = {
      ...body,
      envelopes: [
        ...body.envelopes,
        {
          recipientUserId: other.userId,
          recipientKeyId: other.vault?.identity.keyId,
          wrappedKey: body.envelopes[0]?.wrappedKey,
        },
      ],
    };
    const duplicated = { ...body, envelopes: [...body.envelopes, body.envelopes[0]] };
    for (const wrong of [missing, extra, duplicated]) {
      const refused = await finalize(admin, roomId, started.operation.id, wrong);
      expect(refused.status).toBe(422);
      expect(errorCode(refused)).toBe('REKEY_RECIPIENTS_MISMATCH');
    }
    expect((await versions(roomId)).length).toBe(1);
    expect(await operationRow(started.operation.id)).toMatchObject({ status: 'PENDING' });
    expect((await roomRow(db, roomId)).key_state).toBe('REKEYING');
    // A signed set that leaves a member out (the starter's own choice) is also refused.
    const partial = await finalizeBody(admin, roomId, started, {
      recipients: [owner.vault, admin.vault].map((v) => v?.identity).filter((v) => v !== undefined),
    });
    expect(errorCode(await finalize(admin, roomId, started.operation.id, partial.body))).toBe(
      'REKEY_RECIPIENTS_MISMATCH',
    );
    // The correct set still finalizes.
    expect((await finalize(admin, roomId, started.operation.id, body)).status).toBe(200);
    expect(api.events.filter((e) => e.name === 'REKEY_REJECTED').length).toBeGreaterThanOrEqual(4);
  });

  it('refuses a statement that does not verify, a wrong target version and a reused commitment', async () => {
    const { owner, admin, roomId } = await team();
    const started = startedOf(await startRekey(admin, roomId));
    const { body } = await finalizeBody(admin, roomId, started);
    const flipped = Buffer.from(body.statementSignature, 'base64url');
    flipped[5] = (flipped[5] ?? 0) ^ 0x01;
    const badSignature = { ...body, statementSignature: flipped.toString('base64url') };
    expect(errorCode(await finalize(admin, roomId, started.operation.id, badSignature))).toBe('ROOM_STATEMENT_INVALID');
    // The OWNER signs the same set: a valid signature, but not by the starter.
    const ownerMade = await finalizeBody(owner, roomId, started);
    const ownerSigned = {
      ...body,
      statementSignature: ownerMade.body.statementSignature,
      commitment: ownerMade.body.commitment,
    };
    expect(errorCode(await finalize(admin, roomId, started.operation.id, ownerSigned))).toBe('ROOM_STATEMENT_INVALID');
    expect(errorCode(await finalize(admin, roomId, started.operation.id, { ...body, targetVersion: 3 }))).toBe(
      'KEY_VERSION_STALE',
    );
    // Version 1's commitment again (a replayed version) is refused even with a fresh signature.
    const { rows } = await db.query<{ commitment: Buffer }>(
      'SELECT commitment FROM room_key_versions WHERE room_id = $1 AND version = 1',
      [roomId],
    );
    const replayed = { ...body, commitment: Buffer.from(rows[0]?.commitment ?? []).toString('base64url') };
    expect(errorCode(await finalize(admin, roomId, started.operation.id, replayed))).toBe('ROOM_STATEMENT_INVALID');
    expect((await versions(roomId)).length).toBe(1);
    expect((await finalize(admin, roomId, started.operation.id, body)).status).toBe(200);
  });

  it('an operation of another room is not found, even with a valid payload (OL-13)', async () => {
    const one = await team();
    const two = await team();
    const started = startedOf(await startRekey(one.owner, one.roomId));
    const { body } = await finalizeBody(one.owner, one.roomId, started);
    // Room two's OWNER names room one's operation in room two.
    const response = await finalize(two.owner, two.roomId, started.operation.id, body);
    expect(response.status).toBe(404);
    expect(await operationRow(started.operation.id)).toMatchObject({ status: 'PENDING' });
  });
});

// ----------------------------------------------------------------- staleness (ADR-013 step 5)

describe('a membership change makes a pending operation STALE (ADR-013 step 5)', () => {
  it('a removal during the rekey: finalize refused, the new snapshot excludes the departed member', async () => {
    const { owner, admin, member, other, roomId } = await team();
    await stepUp(api, owner);
    await remove(owner, roomId, other);
    const started = startedOf(await startRekey(admin, roomId));
    const { body } = await finalizeBody(admin, roomId, started);
    await remove(owner, roomId, member);
    expect(await operationRow(started.operation.id)).toMatchObject({
      status: 'STALE',
      closed_reason: 'MEMBERSHIP_CHANGED',
    });
    expect(await roomRow(db, roomId)).toMatchObject({
      key_state: 'REKEY_REQUIRED',
      rekey_reasons: '{MEMBER_REMOVED}',
    });
    expect(errorCode(await finalize(admin, roomId, started.operation.id, body))).toBe('REKEY_OPERATION_CLOSED');
    const restarted = startedOf(await startRekey(admin, roomId));
    expect(restarted.recipients.map((r) => r.userId).sort()).toEqual([owner.userId, admin.userId].sort());
    const fresh = await finalizeBody(admin, roomId, restarted);
    expect((await finalize(admin, roomId, restarted.operation.id, fresh.body)).status).toBe(200);
    expect(
      api.events.some((e) => e.name === 'REKEY_STALE' && e.details?.['operationId'] === started.operation.id),
    ).toBe(true);
  });

  it('a role change, an acceptance and an invitation revoked during a manual rotation all close it', async () => {
    const { owner, admin, member, roomId } = await team();
    const role = startedOf(await startRekey(owner, roomId));
    await owner.browser.request('POST', `/rooms/${roomId}/members/${member.userId}/role`, { role: 'VIEWER' });
    expect(await operationRow(role.operation.id)).toMatchObject({ status: 'STALE' });

    const invitee = await personWithVault(api, db);
    const invitation = await invite(owner, roomId, invitee, 'MEMBER');
    const id = (invitation.body['invitation'] as { id: string }).id;
    const accepting = startedOf(await startRekey(owner, roomId));
    // The pending invitee is in the snapshot (ADR-013 step 1).
    expect(accepting.recipients.find((r) => r.userId === invitee.userId)?.kind).toBe('INVITEE');
    expect((await invitee.browser.request('POST', `/invitations/${id}/accept`, {})).status).toBe(200);
    expect(await operationRow(accepting.operation.id)).toMatchObject({ status: 'STALE' });

    const third = await personWithVault(api, db);
    const open = await invite(admin, roomId, third, 'MEMBER');
    const openId = (open.body['invitation'] as { id: string }).id;
    const revoking = startedOf(await startRekey(owner, roomId));
    const { body } = await finalizeBody(owner, roomId, revoking);
    // Revoking an invitation changes no epoch, but the recomputed set no longer matches.
    expect((await owner.browser.request('POST', `/rooms/${roomId}/invitations/${openId}/revoke`, {})).status).toBe(200);
    expect(errorCode(await finalize(owner, roomId, revoking.operation.id, body))).toBe('REKEY_OPERATION_CLOSED');
    expect(await operationRow(revoking.operation.id)).toMatchObject({
      status: 'STALE',
      closed_reason: 'RECIPIENTS_CHANGED',
    });
    expect((await roomRow(db, roomId)).key_state).toBe('ACTIVE');
  });

  it('a pending invitee receives the new version and opens it after accepting', async () => {
    const { owner, roomId } = await team();
    const invitee = await personWithVault(api, db);
    const created = await invite(owner, roomId, invitee, 'MEMBER');
    const id = (created.body['invitation'] as { id: string }).id;
    expect(await rekey(owner, roomId)).toBe(2);
    const { rows } = await db.query(
      'SELECT key_version, status::text FROM key_envelopes WHERE room_id = $1 AND recipient_user_id = $2 ORDER BY key_version',
      [roomId, invitee.userId],
    );
    expect(rows).toEqual([
      { key_version: 1, status: 'PENDING' },
      { key_version: 2, status: 'PENDING' },
    ]);
    expect((await invitee.browser.request('POST', `/invitations/${id}/accept`, {})).status).toBe(200);
    const keys = await openRoom(invitee, roomId);
    expect(keys.map((k) => [k.keyVersion, k.authorization.kind])).toEqual([
      [1, 'grant'],
      [2, 'recipient-list'],
    ]);
  });
});

// ------------------------------------------------------------- atomicity (nothing partial)

describe('finalize commits everything or nothing', () => {
  it('a database failure inside finalize leaves the old version, the lock and the operation untouched', async () => {
    const { owner, admin, other, roomId } = await team();
    await stepUp(api, owner);
    await remove(owner, roomId, other);
    const started = startedOf(await startRekey(admin, roomId));
    const { body } = await finalizeBody(admin, roomId, started);
    const migrator = await testDatabase(inject('databaseName')).connect('migrator');
    const trigger = `cm_test_fail_${randomBytes(4).toString('hex')}`;
    try {
      // The envelope insert is the third write of the transaction; make exactly it fail.
      await migrator.query(`CREATE FUNCTION ${trigger}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.room_id = '${roomId}' AND NEW.key_version = 2 THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$`);
      await migrator.query(
        `CREATE TRIGGER ${trigger} BEFORE INSERT ON key_envelopes FOR EACH ROW EXECUTE FUNCTION ${trigger}()`,
      );
      const failed = await finalize(admin, roomId, started.operation.id, body);
      expect(failed.status).toBe(500);
    } finally {
      await migrator.query(`DROP TRIGGER IF EXISTS ${trigger} ON key_envelopes`);
      await migrator.query(`DROP FUNCTION IF EXISTS ${trigger}()`);
      await migrator.end();
    }
    expect((await versions(roomId)).map((v) => [v.version, v.status])).toEqual([[1, 'ACTIVE']]);
    expect(await roomRow(db, roomId)).toMatchObject({ key_state: 'REKEYING' });
    expect(await operationRow(started.operation.id)).toMatchObject({ status: 'PENDING' });
    // The same payload succeeds afterwards: the failure left nothing behind.
    expect((await finalize(admin, roomId, started.operation.id, body)).status).toBe(200);
  });
});

// ----------------------------------------------- the key state view, cryptoperiod, destruction

describe('key state, cryptoperiods (PC-14) and destruction of retired versions (CM-T052)', () => {
  it('every member sees the key state and the live operation; no key material is in it', async () => {
    const { owner, admin, member, other, roomId } = await team();
    await stepUp(api, owner);
    await remove(owner, roomId, other);
    const started = startedOf(await startRekey(admin, roomId));
    const view = await keyState(member, roomId);
    expect(view).toMatchObject({
      keyState: 'REKEYING',
      rekeyReasons: ['MEMBER_REMOVED'],
      currentKeyVersion: 1,
      cryptoperiodEndsAt: null,
      cryptoperiodReminder: false,
      operation: { id: started.operation.id, mode: 'MANDATORY', startedByUserId: admin.userId, status: 'PENDING' },
      membersNeedingKeys: [],
    });
    expect(Object.keys(view).sort()).toEqual(
      [
        'cryptoperiodEndsAt',
        'cryptoperiodReminder',
        'currentKeyVersion',
        'keyState',
        'membersNeedingKeys',
        'operation',
        'rekeyReasons',
        'rekeyRequiredSince',
      ].sort(),
    );
  });

  it('a CONFIDENTIAL room is reminded 14 days early and locked by the worker when its cryptoperiod ends', async () => {
    const owner = await mfaPersonWithVault(api, db);
    const roomId = await createRoom(owner, 'CONFIDENTIAL');
    expect(await keyState(owner, roomId)).toMatchObject({ cryptoperiodReminder: false });
    const DAY = 24 * 60 * 60_000;
    // Age the current version (created_at is metadata, not part of the signed statement).
    const age = async (days: number) =>
      db.query('UPDATE room_key_versions SET created_at = $2 WHERE room_id = $1 AND version = 1', [
        roomId,
        new Date(api.clock.now().getTime() - days * DAY),
      ]);
    await age(170);
    const reminded = await keyState(owner, roomId);
    expect(reminded).toMatchObject({ keyState: 'ACTIVE', cryptoperiodReminder: true });
    expect(new Date(reminded['cryptoperiodEndsAt'] as string).getTime()).toBeGreaterThan(api.clock.now().getTime());
    const worker = workerDatabase();
    try {
      await runRekeyMaintenance(worker.prisma, api.clock.now());
      expect((await roomRow(db, roomId)).key_state).toBe('ACTIVE');
      await age(181);
      expect((await runRekeyMaintenance(worker.prisma, api.clock.now())).cryptoperiodsExpired).toBeGreaterThanOrEqual(
        1,
      );
    } finally {
      await worker.close();
    }
    expect(await roomRow(db, roomId)).toMatchObject({
      key_state: 'REKEY_REQUIRED',
      rekey_reasons: '{CRYPTOPERIOD_EXPIRED}',
    });
  });

  it('a room locked by the wrap bound (R7) or an expired cryptoperiod (R6) is unlocked only by a rekey', async () => {
    const owner = await mfaPersonWithVault(api, db);
    const wrapRoom = await createRoom(owner, 'STANDARD');
    await db.query('UPDATE room_key_versions SET wrap_count = 1048576 WHERE room_id = $1', [wrapRoom]);
    const file = await encryptForRoom(owner, wrapRoom, randomBytes(8));
    expect(errorCode(await startUpload(owner, wrapRoom, file))).toBe('REKEY_REQUIRED');
    expect(await roomRow(db, wrapRoom)).toMatchObject({
      key_state: 'REKEY_REQUIRED',
      rekey_reasons: '{WRAP_LIMIT_REACHED}',
    });
    expect(await rekey(owner, wrapRoom)).toBe(2);
    // The new version starts with a fresh wrap count and the reason is gone.
    expect(await roomRow(db, wrapRoom)).toMatchObject({ key_state: 'ACTIVE', rekey_reasons: '{}' });
    expect((await versions(wrapRoom)).map((v) => [v.version, v.status, v.reasons])).toEqual([
      [1, 'RETIRED', '{INITIAL}'],
      [2, 'ACTIVE', '{WRAP_LIMIT_REACHED}'],
    ]);

    const periodRoom = await createRoom(owner, 'CONFIDENTIAL');
    const DAY = 24 * 60 * 60_000;
    await db.query('UPDATE room_key_versions SET created_at = $2 WHERE room_id = $1 AND version = 1', [
      periodRoom,
      new Date(api.clock.now().getTime() - 181 * DAY),
    ]);
    const worker = workerDatabase();
    try {
      await runRekeyMaintenance(worker.prisma, api.clock.now());
    } finally {
      await worker.close();
    }
    expect(await roomRow(db, periodRoom)).toMatchObject({ rekey_reasons: '{CRYPTOPERIOD_EXPIRED}' });
    expect(await rekey(owner, periodRoom)).toBe(2);
    expect(await roomRow(db, periodRoom)).toMatchObject({ key_state: 'ACTIVE', rekey_reasons: '{}' });
  });

  it('the worker destroys a retired version no live item names; it keeps one a note still names', async () => {
    const { owner, member, roomId } = await team();
    const noteV1 = await createdNote(member, roomId, 'Keeps v1', 'alive');
    expect(await rekey(owner, roomId)).toBe(2);
    expect(await rekey(owner, roomId)).toBe(3);
    const worker = workerDatabase();
    try {
      await runRekeyMaintenance(worker.prisma, new Date());
    } finally {
      await worker.close();
    }
    // v1 is still named by the note; v2 was never used and is destroyed: commitment and statement kept.
    const { rows } = await db.query<{ version: number; status: string; has_commitment: boolean; envelopes: number }>(
      `SELECT v.version, v.status::text, octet_length(v.commitment) = 32 AS has_commitment,
              (SELECT count(*)::int FROM key_envelopes e WHERE e.room_id = v.room_id AND e.key_version = v.version) AS envelopes
         FROM room_key_versions v WHERE v.room_id = $1 ORDER BY v.version`,
      [roomId],
    );
    expect(rows).toEqual([
      { version: 1, status: 'RETIRED', has_commitment: true, envelopes: 4 },
      { version: 2, status: 'DESTROYED', has_commitment: true, envelopes: 0 },
      { version: 3, status: 'ACTIVE', has_commitment: true, envelopes: 4 },
    ]);
    // Members still open what they need: v1 for the note, v3 for new content.
    expect((await readNote(member, roomId, noteV1)).body).toBe('alive');
    const keys = await openRoom(member, roomId);
    expect(keys.map((k) => k.keyVersion)).toEqual([1, 3]);
  });
});

// --------------------------------------------------------- browsers refuse what the server forged

describe('members refuse a forged rekeyed version even if the server stores it (T-36)', () => {
  it('a version activated in the database without the starter signature is refused by every member', async () => {
    const { owner, member, roomId } = await team();
    expect(await rekey(owner, roomId)).toBe(2);
    // An attacker with the API role replaces the signature of v2 (the write-once trigger refuses an
    // UPDATE, so the attacker would have to insert a forged version; simulated by a v3 below).
    const { rows } = await db.query<{ commitment: Buffer }>(
      'SELECT commitment FROM room_key_versions WHERE room_id = $1 AND version = 2',
      [roomId],
    );
    await db.query(
      `UPDATE room_key_versions SET status = 'RETIRED', retired_at = now() WHERE room_id = $1 AND version = 2`,
      [roomId],
    );
    await db.query(
      `INSERT INTO room_key_versions (room_id, version, status, commitment, algorithm_suite, reasons, created_by_id,
                                      created_by_key_id, previous_commitment, recipient_user_ids, recipient_key_ids, statement_signature)
       VALUES ($1, 3, 'ACTIVE', $2, 'CM1', '{MANUAL}', $3, $4, $5, $6, $7, $8)`,
      [
        roomId,
        randomBytes(32),
        owner.userId,
        owner.vault?.identity.keyId,
        rows[0]?.commitment,
        [member.userId],
        [member.vault?.identity.keyId],
        randomBytes(64),
      ],
    );
    await db.query('UPDATE rooms SET current_key_version = 3 WHERE id = $1', [roomId]);
    await db.query(
      `INSERT INTO key_envelopes (room_id, key_version, recipient_user_id, recipient_key_id, status, wrapped_key, algorithm, created_by_id)
       VALUES ($1, 3, $2, $3, 'ACTIVE', $4, 'RSA-OAEP-3072-SHA256', $5)`,
      [roomId, member.userId, member.vault?.identity.keyId, randomBytes(384), owner.userId],
    );
    const refused = await openRoom(member, roomId).catch((e: unknown) => e);
    expect(isCryptoError(refused, CryptoErrorCode.KEY_AUTHENTICATION_FAILED)).toBe(true);
  });
});
