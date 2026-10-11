import { CryptoErrorCode, isCryptoError } from '@ciphermesh/crypto';
import { NOTE_LIMITS } from '@ciphermesh/shared';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { runNoteCleanup } from '../../apps/api/src/db/note-cleanup';
import { runRoomCleanup } from '../../apps/api/src/db/room-cleanup';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { createLogger } from '../../apps/api/src/logging/logger';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { insert, noteRow } from '../helpers/db-fixtures';
import {
  createdNote,
  createNote,
  openView,
  readNote,
  updateBody,
  updateNote,
  wireOf,
  type NoteView,
} from '../helpers/notes';
import { inviteAndAccept } from '../helpers/room-crypto';
import { createRoom, personWithVault, stepUp, type Person } from '../helpers/rooms';

// Phase 8, CM-T042 (DF-12): client-side encrypted notes with per-revision keys and optimistic
// concurrency against the real API and PostgreSQL (as cm_api, and cm_worker for the cleanup).
// Notes are encrypted by packages/crypto with room keys opened as the browser opens them. Every
// title and body is synthetic.
let api: AuthTestApi;
let db: pg.Client;
let owner: Person;
let member: Person;
let viewer: Person;
let roomId: string;

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  owner = await personWithVault(api, db);
  member = await personWithVault(api, db);
  viewer = await personWithVault(api, db);
  roomId = await createRoom(owner, 'STANDARD', 'Notes lifecycle room');
  await inviteAndAccept(owner, roomId, member, 'MEMBER');
  await inviteAndAccept(owner, roomId, viewer, 'VIEWER');
}, 120_000);
afterAll(async () => {
  await api.close();
  await db.end();
});

async function rowOf(noteId: string) {
  const { rows } = await db.query<{
    revision: number;
    key_version: number;
    updated_by_id: string;
    wrapped_dek: Buffer | null;
    ciphertext: Buffer | null;
    ciphertext_sha256: Buffer;
    deleted_at: Date | null;
  }>('SELECT * FROM encrypted_notes WHERE id = $1', [noteId]);
  return rows[0];
}

const wrapCount = async (room: string): Promise<number> =>
  (
    await db.query<{ wrap_count: number }>(
      'SELECT wrap_count FROM room_key_versions WHERE room_id = $1 AND version = 1',
      [room],
    )
  ).rows[0]?.wrap_count ?? -1;

const getView = async (who: Person, noteId: string, room = roomId): Promise<NoteView> => {
  const response = await who.browser.request('GET', `/rooms/${room}/notes/${noteId}`);
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  return response.body['note'] as NoteView;
};

const rejectsWith = async (promise: Promise<unknown>, code: string): Promise<void> => {
  await expect(promise).rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.code === code);
};

describe('client-side encrypted notes (DF-12)', () => {
  it('stores only ciphertext; every member, including a VIEWER, decrypts the title and body', async () => {
    const before = await wrapCount(roomId);
    const noteId = await createdNote(member, roomId, 'Synthetic agenda', 'First line\nSecond line ✓');
    expect(await wrapCount(roomId), 'one more NEK wrapped under RWK_1 (CP-16)').toBe(before + 1);
    const row = await rowOf(noteId);
    expect(row).toMatchObject({ revision: 1, key_version: 1, updated_by_id: member.userId, deleted_at: null });
    expect(row?.wrapped_dek).toHaveLength(48);
    // The integrity reference is the SHA-256 of the ciphertext, computed by the API.
    expect(
      row?.ciphertext_sha256.equals(
        createHash('sha256')
          .update(row.ciphertext ?? Buffer.alloc(0))
          .digest(),
      ),
    ).toBe(true);
    for (const reader of [owner, member, viewer]) {
      expect(await readNote(reader, roomId, noteId)).toMatchObject({
        noteId,
        revision: 1,
        title: 'Synthetic agenda',
        body: 'First line\nSecond line ✓',
      });
    }
    const listed = await viewer.browser.request('GET', `/rooms/${roomId}/notes`);
    expect((listed.body['notes'] as NoteView[]).map((n) => n.id)).toContain(noteId);
  });

  it('accepts an empty body, Unicode and the largest document; the schema refuses larger ciphertext', async () => {
    const empty = await createdNote(member, roomId, 'Empty', '');
    expect((await readNote(viewer, roomId, empty)).body).toBe('');
    const overhead = '{"body":"","title":"Max","v":1}'.length;
    const largest = 'x'.repeat(NOTE_LIMITS.maxDocumentBytes - overhead);
    const big = await createdNote(member, roomId, 'Max', largest);
    expect((await rowOf(big))?.ciphertext).toHaveLength(NOTE_LIMITS.maxCiphertextBytes);
    expect((await readNote(owner, roomId, big)).body).toHaveLength(largest.length);
    const { response } = await createNote(member, roomId, 'Too big', 'x', {
      ciphertext: randomBytes(NOTE_LIMITS.maxCiphertextBytes + 1).toString('base64url'),
    });
    expect(response.status).toBe(400);
  });

  it('finds no title or body canary in the database or the log (EV-08-01, INV-01)', async () => {
    const titleCanary = `CANARY-TITLE-${randomBytes(6).toString('hex')}`;
    const bodyCanary = `CANARY-BODY-${randomBytes(6).toString('hex')}`;
    const noteId = await createdNote(member, roomId, titleCanary, `${bodyCanary}\n`.repeat(20));
    expect((await updateNote(owner, roomId, noteId, 1, `${titleCanary} v2`, `${bodyCanary} edited`)).status).toBe(200);
    await readNote(viewer, roomId, noteId);
    const forms = (text: string): string[] => [
      text,
      Buffer.from(text).toString('hex'),
      Buffer.from(text).toString('base64'),
      Buffer.from(text).toString('base64url'),
      Buffer.from(text, 'utf16le').toString('hex'),
    ];
    const tables = (
      await db.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name <> '_prisma_migrations'",
      )
    ).rows.map((r) => r.table_name);
    expect(tables).toContain('encrypted_notes');
    let dump = '';
    for (const table of tables) {
      dump += JSON.stringify((await db.query(`SELECT row_to_json(t)::text AS row FROM ${table} t`)).rows);
    }
    const log = `${api.logText()}${JSON.stringify(api.events)}`;
    for (const canary of [titleCanary, bodyCanary]) {
      for (const form of forms(canary)) {
        expect(dump.includes(form), `database contains ${form}`).toBe(false);
        expect(log.includes(form), `log contains ${form}`).toBe(false);
      }
    }
    // Events name identifiers and numbers only (INV-10).
    for (const event of api.events.filter((e) => e.name.startsWith('NOTE_'))) {
      expect(
        Object.keys(event.details ?? {}).every((k) =>
          ['roomId', 'noteId', 'revision', 'keyVersion', 'notes'].includes(k),
        ),
      ).toBe(true);
    }
  });
});

describe('revisions and optimistic concurrency (DF-12, T-32)', () => {
  it('increments the revision, uses a fresh NEK, and records the editor', async () => {
    const noteId = await createdNote(member, roomId, 'Draft', 'v1');
    const first = await rowOf(noteId);
    const saved = await updateNote(owner, roomId, noteId, 1, 'Draft', 'v2');
    expect(saved.status, JSON.stringify(saved.body)).toBe(200);
    expect(saved.body['note']).toMatchObject({
      id: noteId,
      revision: 2,
      authorId: member.userId,
      updatedById: owner.userId,
    });
    const second = await rowOf(noteId);
    expect(second?.revision).toBe(2);
    expect(second?.wrapped_dek?.equals(first?.wrapped_dek ?? Buffer.alloc(0))).toBe(false);
    expect(await readNote(viewer, roomId, noteId)).toMatchObject({ revision: 2, body: 'v2' });
  });

  it('refuses a stale revision with 409 and keeps the stored note intact', async () => {
    const noteId = await createdNote(member, roomId, 'Stale', 'v1');
    expect((await updateNote(member, roomId, noteId, 1, 'Stale', 'v2 by member')).status).toBe(200);
    const before = await rowOf(noteId);
    const stale = await updateNote(owner, roomId, noteId, 1, 'Stale', 'v2 by owner, from revision 1');
    expect(stale.status).toBe(409);
    expect(errorCode(stale)).toBe('REVISION_CONFLICT');
    expect(await rowOf(noteId)).toEqual(before);
    expect((await readNote(viewer, roomId, noteId)).body).toBe('v2 by member');
    // A revision from the future is just as stale.
    expect(errorCode(await updateNote(owner, roomId, noteId, 5, 'Stale', 'skip'))).toBe('REVISION_CONFLICT');
  });

  it('accepts exactly one of two concurrent saves from the same revision; the other gets 409', async () => {
    const noteId = await createdNote(member, roomId, 'Race', 'base');
    const [a, b] = await Promise.all([
      updateBody(owner, roomId, noteId, 1, 'Race', 'from owner'),
      updateBody(member, roomId, noteId, 1, 'Race', 'from member'),
    ]);
    const [fromOwner, fromMember] = await Promise.all([
      owner.browser.request('POST', `/rooms/${roomId}/notes/${noteId}/update`, a),
      member.browser.request('POST', `/rooms/${roomId}/notes/${noteId}/update`, b),
    ]);
    const results = [fromOwner, fromMember];
    expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
    const loser = results.find((r) => r.status === 409);
    expect(loser === undefined ? undefined : errorCode(loser)).toBe('REVISION_CONFLICT');
    const winner = fromOwner.status === 200 ? 'from owner' : 'from member';
    expect(await readNote(viewer, roomId, noteId)).toMatchObject({ revision: 2, body: winner });
    expect((await rowOf(noteId))?.revision).toBe(2);
  });

  it('refuses a duplicate of a save that already succeeded', async () => {
    const noteId = await createdNote(member, roomId, 'Duplicate', 'v1');
    const body = await updateBody(member, roomId, noteId, 1, 'Duplicate', 'v2');
    const path = `/rooms/${roomId}/notes/${noteId}/update`;
    expect((await member.browser.request('POST', path, body)).status).toBe(200);
    const again = await member.browser.request('POST', path, body);
    expect(errorCode(again)).toBe('REVISION_CONFLICT');
    expect((await rowOf(noteId))?.revision).toBe(2);
  });

  it('binds the revision cryptographically: a served record with another revision fails authentication', async () => {
    const noteId = await createdNote(member, roomId, 'Bound', 'v1');
    const revision1 = await getView(owner, noteId);
    expect((await updateNote(member, roomId, noteId, 1, 'Bound', 'v2')).status).toBe(200);
    const revision2 = await getView(owner, noteId);
    // A malicious server relabels revision 2 as 3, or serves revision 1's ciphertext as revision 2.
    await rejectsWith(
      openView(owner, roomId, { ...wireOf(revision2), revision: 3 }),
      CryptoErrorCode.AUTHENTICATION_FAILED,
    );
    await rejectsWith(
      openView(owner, roomId, { ...wireOf(revision1), revision: 2 }),
      CryptoErrorCode.AUTHENTICATION_FAILED,
    );
    await rejectsWith(
      openView(owner, roomId, {
        ...wireOf(revision2),
        ciphertext: revision1.ciphertext,
        contentIv: revision1.contentIv,
      }),
      CryptoErrorCode.AUTHENTICATION_FAILED,
    );
    // An older revision served under its own number still authenticates: the browser can only
    // notice it by remembering the newest revision it saw (T-32, L-10).
    expect((await openView(owner, roomId, wireOf(revision1))).revision).toBe(1);
  });

  it('refuses a note moved to another note ID or room', async () => {
    const a = await createdNote(member, roomId, 'Note A', 'a');
    const b = await createdNote(member, roomId, 'Note B', 'b');
    const viewA = await getView(owner, a);
    await rejectsWith(openView(owner, roomId, { ...wireOf(viewA), noteId: b }), CryptoErrorCode.AUTHENTICATION_FAILED);
    const otherRoom = await createRoom(owner, 'STANDARD', 'Other notes room');
    await rejectsWith(openView(owner, otherRoom, wireOf(viewA)), CryptoErrorCode.AUTHENTICATION_FAILED);
  });

  it('refuses expected revisions outside 1 .. 2^31 - 2, and an update of the last revision', async () => {
    const noteId = await createdNote(member, roomId, 'Bounds', 'v1');
    for (const expectedRevision of [0, -1, NOTE_LIMITS.maxRevision, 1.5]) {
      const body = { ...(await updateBody(member, roomId, noteId, 1, 'Bounds', 'v2')), expectedRevision };
      expect((await member.browser.request('POST', `/rooms/${roomId}/notes/${noteId}/update`, body)).status).toBe(400);
    }
    const top = noteRow({ roomId, ownerId: member.userId } as never, { revision: NOTE_LIMITS.maxRevision });
    await insert(db, 'encrypted_notes', top);
    const last = await member.browser.request('POST', `/rooms/${roomId}/notes/${top['id'] as string}/update`, {
      ...(await updateBody(member, roomId, top['id'] as string, 1, 'Bounds', 'v2')),
      expectedRevision: NOTE_LIMITS.maxRevision,
    });
    expect(last.status).toBe(400);
    expect((await rowOf(top['id'] as string))?.revision).toBe(NOTE_LIMITS.maxRevision);
  });

  it('refuses a reused note ID, in this room or another', async () => {
    const noteId = await createdNote(member, roomId, 'Original', 'v1');
    const before = await rowOf(noteId);
    // A well-formed request that reuses the ID is refused before anything is stored (CD-08).
    expect(errorCode((await createNote(member, roomId, 'Copy', 'v1', { noteId })).response)).toBe(
      'NOTE_ID_UNAVAILABLE',
    );
    const otherRoom = await createRoom(owner, 'STANDARD', 'ID reuse room');
    expect(errorCode((await createNote(owner, otherRoom, 'Copy', 'v1', { noteId })).response)).toBe(
      'NOTE_ID_UNAVAILABLE',
    );
    expect(await rowOf(noteId)).toEqual(before);
  });
});

describe('deletion, expiry and cleanup (INV-14, data-model 5)', () => {
  it('a deleted note is a tombstone: not listed, not readable, not updatable, not deletable again', async () => {
    const noteId = await createdNote(member, roomId, 'To delete', 'gone');
    expect((await member.browser.request('POST', `/rooms/${roomId}/notes/${noteId}/delete`, {})).status).toBe(200);
    const row = await rowOf(noteId);
    expect(row).toMatchObject({ wrapped_dek: null, ciphertext: null, revision: 1 });
    expect(row?.deleted_at).not.toBeNull();
    expect(errorCode(await member.browser.request('GET', `/rooms/${roomId}/notes/${noteId}`))).toBe('NOT_FOUND');
    expect(errorCode(await updateNote(member, roomId, noteId, 1, 'To delete', 'back'))).toBe('NOT_FOUND');
    expect(errorCode(await member.browser.request('POST', `/rooms/${roomId}/notes/${noteId}/delete`, {}))).toBe(
      'NOT_FOUND',
    );
    const listed = await owner.browser.request('GET', `/rooms/${roomId}/notes`);
    expect((listed.body['notes'] as NoteView[]).map((n) => n.id)).not.toContain(noteId);
    expect(api.events.some((e) => e.name === 'NOTE_DELETED' && e.details?.['noteId'] === noteId)).toBe(true);
  });

  it('refuses an expired note at once, then the worker turns it into a tombstone', async () => {
    const expiresAt = new Date(api.clock.now().getTime() + 60_000).toISOString();
    const { response, noteId } = await createNote(member, roomId, 'Short-lived', 'soon gone', { expiresAt });
    expect(response.status).toBe(201);
    expect((await readNote(viewer, roomId, noteId)).body).toBe('soon gone');
    api.clock.advance(61_000);
    try {
      expect(errorCode(await viewer.browser.request('GET', `/rooms/${roomId}/notes/${noteId}`))).toBe('NOT_FOUND');
      expect(errorCode(await updateNote(member, roomId, noteId, 1, 'Short-lived', 'later'))).toBe('NOT_FOUND');
      const listed = await viewer.browser.request('GET', `/rooms/${roomId}/notes`);
      expect((listed.body['notes'] as NoteView[]).map((n) => n.id)).not.toContain(noteId);
    } finally {
      api.clock.advance(-61_000);
    }
    const worker = workerDatabase();
    try {
      expect((await runNoteCleanup(worker.prisma, new Date(Date.now() + 61_000))).expired).toBeGreaterThanOrEqual(1);
    } finally {
      await worker.close();
    }
    expect(await rowOf(noteId)).toMatchObject({ wrapped_dek: null, ciphertext: null });
  });

  it('a deleted room keeps DELETING until its notes are tombstones, then becomes DELETED', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Notes room to delete');
    const noteId = await createdNote(owner, room, 'Inside', 'a room being deleted');
    await stepUp(api, owner);
    expect((await owner.browser.request('POST', `/rooms/${room}/delete`, {})).status).toBe(200);
    const worker = workerDatabase();
    try {
      // The note step runs first in the worker; without it the room must not become DELETED.
      await runRoomCleanup(worker.prisma);
      expect((await db.query('SELECT status FROM rooms WHERE id = $1', [room])).rows[0]).toEqual({
        status: 'DELETING',
      });
      expect((await runNoteCleanup(worker.prisma, new Date())).roomDeleted).toBeGreaterThanOrEqual(1);
      await runRoomCleanup(worker.prisma);
    } finally {
      await worker.close();
    }
    expect((await db.query('SELECT status FROM rooms WHERE id = $1', [room])).rows[0]).toEqual({ status: 'DELETED' });
    expect(await rowOf(noteId)).toMatchObject({ wrapped_dek: null, ciphertext: null });
  });

  it('refuses a new note beyond the D-08-01 limit of live notes per room', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Full notes room');
    const live = await db.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM encrypted_notes WHERE room_id = $1 AND deleted_at IS NULL',
      [room],
    );
    for (let i = live.rows[0]?.n ?? 0; i < NOTE_LIMITS.maxLiveNotesPerRoom; i += 1) {
      await insert(db, 'encrypted_notes', noteRow({ roomId: room, ownerId: owner.userId } as never));
    }
    const full = await createNote(owner, room, 'One too many', 'x');
    expect(full.response.status).toBe(409);
    expect(errorCode(full.response)).toBe('NOTE_LIMIT_REACHED');
    // Deleting one frees a place.
    const any = await db.query<{ id: string }>('SELECT id FROM encrypted_notes WHERE room_id = $1 LIMIT 1', [room]);
    expect(
      (await owner.browser.request('POST', `/rooms/${room}/notes/${any.rows[0]?.id ?? randomUUID()}/delete`, {}))
        .status,
    ).toBe(200);
    expect((await createNote(owner, room, 'Now it fits', 'x')).response.status).toBe(201);
  }, 120_000);
});

/** A Prisma client as cm_worker, as `pnpm worker:retention` connects (no DELETE on note rows). */
function workerDatabase(): Database {
  return createDatabase({
    url: new SecretValue(testDatabase(inject('databaseName')).url('worker')),
    logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
    poolMax: 1,
  });
}
