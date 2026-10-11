import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { createdNote, createNote, readNote, updateBody, updateNote, type NoteView } from '../helpers/notes';
import { inviteAndAccept, vaultOf } from '../helpers/room-crypto';
import { createRoom, mfaPersonWithVault, personWithVault, stepUp, type Person } from '../helpers/rooms';

// Phase 8, CM-T042: who may create, read, update and delete notes (AZ-19 to AZ-22, the actual
// matrix in packages/shared), the write lock after a member is lost (INV-07, PC-16), the current
// key version, and the profile rules PC-08 (expiry) and PC-13 (read audit). Cross-room access,
// outsiders, PLATFORM_ADMIN, suspended and former members and forged identity fields are attacked
// for every note route by tests/authz/bola.test.ts. Every title and body is synthetic.
let api: AuthTestApi;
let db: pg.Client;
let owner: Person;
let admin: Person;
let member: Person;
let otherMember: Person;
let viewer: Person;
let roomId: string;

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  [owner, admin, member, otherMember, viewer] = [
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
  ];
  roomId = await createRoom(owner, 'STANDARD', 'Notes access room');
  await inviteAndAccept(owner, roomId, admin, 'ADMIN');
  await inviteAndAccept(owner, roomId, member, 'MEMBER');
  await inviteAndAccept(owner, roomId, otherMember, 'MEMBER');
  await inviteAndAccept(owner, roomId, viewer, 'VIEWER');
}, 180_000);
afterAll(async () => {
  await api.close();
  await db.end();
});

const remove = (who: Person, noteId: string, room = roomId) =>
  who.browser.request('POST', `/rooms/${room}/notes/${noteId}/delete`, {});

const snapshot = async (noteId: string): Promise<string> =>
  JSON.stringify((await db.query('SELECT * FROM encrypted_notes WHERE id = $1', [noteId])).rows);

describe('AZ-19 to AZ-22: the matrix decides, the stored author decides "own"', () => {
  it('every role reads; VIEWERs cannot create', async () => {
    const noteId = await createdNote(member, roomId, 'Readable by all', 'body');
    for (const reader of [owner, admin, member, otherMember, viewer]) {
      expect((await readNote(reader, roomId, noteId)).title).toBe('Readable by all');
    }
    const { response } = await createNote(viewer, roomId, 'Viewer note', 'x');
    expect(errorCode(response)).toBe('FORBIDDEN');
  });

  it("a MEMBER updates and deletes only their own notes; another member's are refused unchanged", async () => {
    const theirs = await createdNote(otherMember, roomId, 'Not yours', 'v1');
    const before = await snapshot(theirs);
    expect(errorCode(await updateNote(member, roomId, theirs, 1, 'Hijacked', 'v2'))).toBe('FORBIDDEN');
    expect(errorCode(await remove(member, theirs))).toBe('FORBIDDEN');
    expect(await snapshot(theirs)).toBe(before);
    const mine = await createdNote(member, roomId, 'Mine', 'v1');
    expect((await updateNote(member, roomId, mine, 1, 'Mine', 'v2')).status).toBe(200);
    expect((await remove(member, mine)).status).toBe(200);
  });

  it('a VIEWER neither updates nor deletes, not even a note they wrote as a MEMBER before', async () => {
    const demoted = await personWithVault(api, db);
    await inviteAndAccept(owner, roomId, demoted, 'MEMBER');
    const noteId = await createdNote(demoted, roomId, 'Written as member', 'v1');
    await db.query("UPDATE room_members SET role = 'VIEWER' WHERE room_id = $1 AND user_id = $2", [
      roomId,
      demoted.userId,
    ]);
    const before = await snapshot(noteId);
    expect(errorCode(await updateNote(demoted, roomId, noteId, 1, 'Written as member', 'v2'))).toBe('FORBIDDEN');
    expect(errorCode(await remove(demoted, noteId))).toBe('FORBIDDEN');
    expect(errorCode(await updateNote(viewer, roomId, noteId, 1, 'x', 'y'))).toBe('FORBIDDEN');
    expect(errorCode(await remove(viewer, noteId))).toBe('FORBIDDEN');
    expect(await snapshot(noteId)).toBe(before);
  });

  it("OWNER and ADMIN update and delete anyone's notes", async () => {
    for (const editor of [owner, admin]) {
      const noteId = await createdNote(member, roomId, 'Moderated', 'v1');
      const saved = await updateNote(editor, roomId, noteId, 1, 'Moderated', 'edited');
      expect(saved.status).toBe(200);
      expect(saved.body['note']).toMatchObject({ authorId: member.userId, updatedById: editor.userId });
      expect((await remove(editor, noteId)).status).toBe(200);
    }
  });

  it('client-supplied revision, author or editor fields are refused by the schema', async () => {
    const noteId = await createdNote(member, roomId, 'Strict', 'v1');
    const body = await updateBody(member, roomId, noteId, 1, 'Strict', 'v2');
    for (const extra of [
      { revision: 7 },
      { authorId: owner.userId },
      { updatedById: owner.userId },
      { expiresAt: null },
    ]) {
      const response = await member.browser.request('POST', `/rooms/${roomId}/notes/${noteId}/update`, {
        ...body,
        ...extra,
      });
      expect(response.status, JSON.stringify(extra)).toBe(400);
    }
    const created = await createNote(member, roomId, 'Strict', 'x', { title: 'plaintext title' });
    expect(created.response.status).toBe(400);
  });
});

describe('membership loss and key state (INV-07, PC-16)', () => {
  it('a removed member loses all access; the room refuses new note content until a rekey, but reads and deletions work', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Notes removal room');
    const leaving = await personWithVault(api, db);
    const staying = await personWithVault(api, db);
    await inviteAndAccept(owner, room, leaving, 'MEMBER');
    await inviteAndAccept(owner, room, staying, 'MEMBER');
    const noteId = await createdNote(staying, room, 'Before removal', 'v1');
    const leavingNote = await createdNote(leaving, room, 'By the leaver', 'v1');
    // Prepared while still a member: the request is valid in every respect except membership.
    const prepared = await updateBody(leaving, room, leavingNote, 1, 'By the leaver', 'after removal');
    expect((await owner.browser.request('POST', `/rooms/${room}/members/${leaving.userId}/remove`, {})).status).toBe(
      200,
    );

    for (const response of [
      await leaving.browser.request('GET', `/rooms/${room}/notes`),
      await leaving.browser.request('GET', `/rooms/${room}/notes/${noteId}`),
      await leaving.browser.request('POST', `/rooms/${room}/notes/${leavingNote}/update`, prepared),
      await remove(leaving, leavingNote, room),
    ]) {
      expect(errorCode(response)).toBe('NOT_FOUND');
    }
    expect(errorCode((await createNote(staying, room, 'After removal', 'x')).response)).toBe('REKEY_REQUIRED');
    expect(errorCode(await updateNote(staying, room, noteId, 1, 'Before removal', 'v2'))).toBe('REKEY_REQUIRED');
    expect((await readNote(staying, room, noteId)).body).toBe('v1');
    expect((await remove(owner, leavingNote, room)).status).toBe(200);
  }, 120_000);

  it('refuses a write under a key version that is not current', async () => {
    const { response } = await createNote(member, roomId, 'Stale key', 'x', { keyVersion: 2 });
    expect(errorCode(response)).toBe('KEY_VERSION_STALE');
    const noteId = await createdNote(member, roomId, 'Stale key update', 'v1');
    const body = { ...(await updateBody(member, roomId, noteId, 1, 'Stale key update', 'v2')), keyVersion: 2 };
    const stale = await member.browser.request('POST', `/rooms/${roomId}/notes/${noteId}/update`, body);
    expect(errorCode(stale)).toBe('KEY_VERSION_STALE');
  });
});

describe('profile rules: PC-08 expiry and PC-13 read audit', () => {
  const DAY = 24 * 60 * 60_000;

  it('CONFIDENTIAL requires an expiry of at most 90 days and records every read', async () => {
    const confidentialOwner = await mfaPersonWithVault(api, db);
    const reader = await mfaPersonWithVault(api, db);
    const room = await createRoom(confidentialOwner, 'CONFIDENTIAL', 'Confidential notes room');
    await stepUp(api, confidentialOwner, confidentialOwner.secret);
    await inviteAndAccept(confidentialOwner, room, reader, 'VIEWER', {
      confirmedFingerprint: vaultOf(reader).identity.fingerprint,
    });
    const now = api.clock.now().getTime();
    const missing = await createNote(confidentialOwner, room, 'No expiry', 'x');
    expect(errorCode(missing.response)).toBe('EXPIRY_NOT_ALLOWED');
    const tooLate = await createNote(confidentialOwner, room, 'Too late', 'x', {
      expiresAt: new Date(now + 91 * DAY).toISOString(),
    });
    expect(errorCode(tooLate.response)).toBe('EXPIRY_NOT_ALLOWED');
    const past = await createNote(confidentialOwner, room, 'Past', 'x', {
      expiresAt: new Date(now - 1000).toISOString(),
    });
    expect(errorCode(past.response)).toBe('EXPIRY_NOT_ALLOWED');
    const ok = await createNote(confidentialOwner, room, 'Thirty days', 'x', {
      expiresAt: new Date(now + 30 * DAY).toISOString(),
    });
    expect(ok.response.status).toBe(201);
    api.events.length = 0;
    await readNote(reader, room, ok.noteId);
    await reader.browser.request('GET', `/rooms/${room}/notes`);
    expect(api.events.filter((e) => e.name === 'NOTE_READ').map((e) => e.details)).toEqual([
      { roomId: room, noteId: ok.noteId },
      { roomId: room, notes: 1 },
    ]);
  }, 120_000);

  it('STANDARD notes may have no expiry, and reads are not audit events (BASELINE)', async () => {
    api.events.length = 0;
    const noteId = await createdNote(member, roomId, 'Baseline', 'x');
    await readNote(viewer, roomId, noteId);
    expect(api.events.some((e) => e.name === 'NOTE_READ')).toBe(false);
    expect(api.events.some((e) => e.name === 'NOTE_CREATED' && e.details?.['noteId'] === noteId)).toBe(true);
  });

  it('lists only notes of the addressed room, in pages of at most 20', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Paged notes room');
    const ids = [];
    for (let i = 0; i < 23; i += 1) ids.push(await createdNote(owner, room, `Page ${String(i)}`, 'x'));
    const first = await owner.browser.request('GET', `/rooms/${room}/notes`);
    const page1 = first.body['notes'] as NoteView[];
    expect(page1).toHaveLength(20);
    const cursor = first.body['nextCursor'] as string;
    const second = await owner.browser.request('GET', `/rooms/${room}/notes?cursor=${encodeURIComponent(cursor)}`);
    const page2 = second.body['notes'] as NoteView[];
    expect(second.body['nextCursor']).toBeNull();
    expect([...page1, ...page2].map((n) => n.id).sort()).toEqual([...ids].sort());
    expect(errorCode(await owner.browser.request('GET', `/rooms/${room}/notes/${randomUUID()}`))).toBe('NOT_FOUND');
  }, 120_000);
});
