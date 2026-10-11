import { FILE_LIMITS, FILE_QUOTAS } from '@ciphermesh/shared';
import { randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { unavailableObjectStore } from '../../apps/api/src/storage/object-store';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { fileRow, insert } from '../helpers/db-fixtures';
import {
  downloadFile,
  encryptForRoom,
  putObject,
  requireStorageEnv,
  startUpload,
  storedObject,
  uploadFile,
  uploadUrlOf,
  writeObject,
} from '../helpers/files';
import { inviteAndAccept } from '../helpers/room-crypto';
import { createRoom, mfaPersonWithVault, personWithVault, type Person } from '../helpers/rooms';

// Phase 7, CM-T037 and CM-T038 (DF-07): client-side encrypted upload through presigned URLs to the
// real local object storage. Files are encrypted by packages/crypto with room keys opened as the
// browser opens them; the API, PostgreSQL (as cm_api) and storage are real. Content is synthetic.
let api: AuthTestApi;
let db: pg.Client;
let owner: Person;
let member: Person;
let viewer: Person;
let roomId: string;

beforeAll(async () => {
  loadDatabaseTestEnv();
  requireStorageEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  owner = await personWithVault(api, db);
  member = await personWithVault(api, db);
  viewer = await personWithVault(api, db);
  roomId = await createRoom(owner, 'STANDARD', 'Files upload room');
  await inviteAndAccept(owner, roomId, member, 'MEMBER');
  await inviteAndAccept(owner, roomId, viewer, 'VIEWER');
}, 120_000);
afterAll(async () => {
  await api.close();
  await db.end();
});

async function fileRowOf(fileId: string) {
  const { rows } = await db.query<{
    status: string;
    object_key: string;
    wrapped_dek: Buffer | null;
    manifest_ciphertext: Buffer | null;
    ciphertext_size: string;
    deleted_at: Date | null;
    object_deleted_at: Date | null;
  }>('SELECT * FROM encrypted_files WHERE id = $1', [fileId]);
  return rows[0];
}

const wrapCount = async (room: string): Promise<number> =>
  (
    await db.query<{ wrap_count: number }>(
      'SELECT wrap_count FROM room_key_versions WHERE room_id = $1 AND version = 1',
      [room],
    )
  ).rows[0]?.wrap_count ?? -1;

const complete = (who: Person, room: string, fileId: string) =>
  who.browser.request('POST', `/rooms/${room}/files/${fileId}/complete`, {});

describe('client-side encrypted upload and download (DF-07, DF-08)', () => {
  it('stores only ciphertext; another member downloads and decrypts the original bytes', async () => {
    const content = Buffer.concat([Buffer.from('Synthetic report, not real data.\n'), randomBytes(300_000)]);
    const before = await wrapCount(roomId);
    const { fileId, file } = await uploadFile(member, roomId, content, { name: 'report.pdf', type: 'application/pdf' });
    expect(await wrapCount(roomId), 'one more DEK wrapped under RWK_1 (CP-16)').toBe(before + 1);

    const row = await fileRowOf(fileId);
    expect(row).toMatchObject({ status: 'AVAILABLE', ciphertext_size: String(content.length + 16) });
    expect(row?.object_key).toMatch(/^f\/[A-Za-z0-9_-]{43}$/);
    const object = await storedObject(row?.object_key ?? '');
    expect(Buffer.from(object ?? []).equals(Buffer.from(file.content.ciphertext)), 'the object is the ciphertext').toBe(
      true,
    );
    expect(Buffer.from(object ?? []).includes(content.subarray(0, 32))).toBe(false);

    for (const reader of [owner, viewer]) {
      const downloaded = await downloadFile(reader, roomId, fileId);
      expect(downloaded.name).toBe('report.pdf');
      expect(downloaded.type).toBe('application/pdf');
      expect(Buffer.from(downloaded.bytes).equals(content)).toBe(true);
    }
  });

  it('round-trips an empty file and a file at the size limit boundary of the request schema', async () => {
    const { fileId } = await uploadFile(member, roomId, new Uint8Array(0), { name: 'empty.txt', type: 'text/plain' });
    expect((await downloadFile(owner, roomId, fileId)).bytes.length).toBe(0);
    const tooBig = await startUpload(member, roomId, await encryptForRoom(member, roomId, Buffer.from('x')), {
      ciphertextSize: FILE_LIMITS.maxCiphertextBytes + 1,
    });
    expect(tooBig.status).toBe(400);
  });

  it('finds no file name or content canary in the database, the bucket or the log (EV-07-05, INV-16)', async () => {
    const nameCanary = `CANARY-NAME-${randomBytes(6).toString('hex')}`;
    const contentCanary = `CANARY-CONTENT-${randomBytes(6).toString('hex')}`;
    const { fileId } = await uploadFile(member, roomId, Buffer.from(`${contentCanary}\n`.repeat(50)), {
      name: `${nameCanary}.txt`,
      type: 'text/plain',
    });
    const forms = (text: string): string[] => [
      text,
      Buffer.from(text).toString('hex'),
      Buffer.from(text).toString('base64'),
      Buffer.from(text).toString('base64url'),
    ];
    const tables = (
      await db.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name <> '_prisma_migrations'",
      )
    ).rows.map((r) => r.table_name);
    expect(tables).toContain('encrypted_files');
    let dump = '';
    for (const table of tables) {
      dump += JSON.stringify((await db.query(`SELECT row_to_json(t)::text AS row FROM ${table} t`)).rows);
    }
    const object = Buffer.from((await storedObject((await fileRowOf(fileId))?.object_key ?? '')) ?? []);
    const log = `${api.logText()}${JSON.stringify(api.events)}`;
    for (const canary of [nameCanary, contentCanary]) {
      for (const form of forms(canary)) {
        expect(dump.includes(form), `database contains ${form}`).toBe(false);
        expect(object.includes(Buffer.from(form)), `object contains ${form}`).toBe(false);
        expect(log.includes(form), `log contains ${form}`).toBe(false);
      }
    }
    // The plaintext hash exists only inside the encrypted manifest (CD-09).
    const plaintextHash = (await import('node:crypto')).createHash('sha256').update(`${contentCanary}\n`.repeat(50));
    const digest = plaintextHash.digest();
    for (const form of [digest.toString('hex'), digest.toString('base64url')]) expect(dump.includes(form)).toBe(false);
  });
});

describe('presigned storage URLs (CM-T037, CP-20, OL-07, EV-07-06)', () => {
  it('upload URLs are for one object and one size, valid five minutes; nothing else is accepted', async () => {
    const file = await encryptForRoom(member, roomId, randomBytes(2048));
    const started = await startUpload(member, roomId, file);
    expect(started.status).toBe(201);
    const url = new URL(uploadUrlOf(started));
    expect(url.searchParams.get('X-Amz-Expires')).toBe(String(FILE_LIMITS.uploadUrlSeconds));
    expect(url.searchParams.get('X-Amz-SignedHeaders')).toBe('content-length;host');
    expect(url.pathname).not.toContain(roomId);
    const objectKey = (await fileRowOf(file.fileId))?.object_key ?? '';
    // Storage refuses a body of another size: the signature covers content-length.
    expect((await putObject(url.toString(), file.content.ciphertext.subarray(1))).status).toBe(403);
    expect((await putObject(url.toString(), Buffer.concat([file.content.ciphertext, Buffer.from([0])]))).status).toBe(
      403,
    );
    expect(await storedObject(objectKey)).toBeNull();
    // Another object key, another method, or no signature: refused.
    const other = new URL(url);
    other.pathname = other.pathname.replace(/[^/]+$/, randomBytes(32).toString('base64url'));
    expect((await putObject(other.toString(), file.content.ciphertext)).status).toBe(403);
    expect((await fetch(url, { method: 'DELETE' })).status).toBe(403);
    expect((await fetch(`${url.origin}${url.pathname}`, { method: 'PUT', body: file.content.ciphertext })).status).toBe(
      403,
    );
    expect((await putObject(url.toString(), file.content.ciphertext)).status).toBe(200);
    expect((await complete(member, roomId, file.fileId)).status).toBe(200);
  });

  it('refuses expired upload and download URLs (EV-07-06)', async () => {
    const file = await encryptForRoom(member, roomId, randomBytes(64));
    api.clock.advance(-(FILE_LIMITS.uploadUrlSeconds + 30) * 1000);
    let started;
    try {
      started = await startUpload(member, roomId, file);
    } finally {
      api.clock.advance((FILE_LIMITS.uploadUrlSeconds + 30) * 1000);
    }
    expect(started.status).toBe(201);
    expect((await putObject(uploadUrlOf(started), file.content.ciphertext)).status, 'expired upload URL').toBe(403);

    const { fileId } = await uploadFile(member, roomId, randomBytes(64));
    api.clock.advance(-(FILE_LIMITS.downloadUrlSeconds + 30) * 1000);
    let issued;
    try {
      issued = await member.browser.request('POST', `/rooms/${roomId}/files/${fileId}/download-url`, {});
    } finally {
      api.clock.advance((FILE_LIMITS.downloadUrlSeconds + 30) * 1000);
    }
    expect(issued.status).toBe(200);
    const download = issued.body['download'] as { url: string; expiresAt: string };
    expect(new Date(download.expiresAt).getTime()).toBeLessThan(Date.now());
    expect((await fetch(download.url)).status, 'expired download URL').toBe(403);
  });

  it('download URLs force an octet-stream attachment, live 60 seconds and serve one object', async () => {
    const { fileId } = await uploadFile(member, roomId, Buffer.from('<html><script>alert(1)</script></html>'), {
      name: 'page.html',
      type: 'text/html',
    });
    const issued = await viewer.browser.request('POST', `/rooms/${roomId}/files/${fileId}/download-url`, {});
    const url = new URL((issued.body['download'] as { url: string }).url);
    expect(url.searchParams.get('X-Amz-Expires')).toBe(String(FILE_LIMITS.downloadUrlSeconds));
    const response = await fetch(url);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/octet-stream');
    expect(response.headers.get('content-disposition')).toBe('attachment');
    const other = new URL(url);
    other.pathname = other.pathname.replace(/[^/]+$/, randomBytes(32).toString('base64url'));
    expect((await fetch(other)).status).toBe(403);
    expect((await fetch(`${url.origin}${url.pathname}`)).status, 'no anonymous read').toBe(403);
    expect((await fetch(`${url.origin}${url.pathname.replace(/\/f\/.*$/, '')}?list-type=2`)).status, 'no listing').toBe(
      403,
    );
  });

  it('never writes a presigned URL or signature into the log or a security event (INV-10)', () => {
    const text = `${api.logText()}${JSON.stringify(api.events)}`;
    expect(text).not.toMatch(/X-Amz-(Signature|Credential)/i);
    expect(text).not.toContain(process.env['STORAGE_SECRET_ACCESS_KEY'] ?? 'unset');
    expect(text).not.toContain(process.env['STORAGE_ACCESS_KEY_ID'] ?? 'unset');
    expect(api.events.some((e) => e.name === 'FILE_UPLOADED')).toBe(true);
  });
});

describe('completion (DF-07: AVAILABLE only after storage confirms the upload)', () => {
  it('refuses completion before the ciphertext arrived, then completes once', async () => {
    const file = await encryptForRoom(member, roomId, randomBytes(512));
    const started = await startUpload(member, roomId, file);
    expect(errorCode(await complete(member, roomId, file.fileId))).toBe('UPLOAD_INCOMPLETE');
    expect((await fileRowOf(file.fileId))?.status).toBe('PENDING_UPLOAD');
    // A pending upload is in no list and has no download.
    const list = await owner.browser.request('GET', `/rooms/${roomId}/files`);
    expect(JSON.stringify(list.body)).not.toContain(file.fileId);
    expect((await owner.browser.request('GET', `/rooms/${roomId}/files/${file.fileId}`)).status).toBe(404);
    await putObject(uploadUrlOf(started), file.content.ciphertext);
    expect(errorCode(await complete(owner, roomId, file.fileId)), 'only the uploader completes').toBe('NOT_FOUND');
    expect(errorCode(await complete(viewer, roomId, file.fileId))).toBe('FORBIDDEN');
    expect((await complete(member, roomId, file.fileId)).status).toBe(200);
    expect(errorCode(await complete(member, roomId, file.fileId)), 'duplicate completion').toBe('FILE_NOT_PENDING');
    expect((await fileRowOf(file.fileId))?.status).toBe('AVAILABLE');
  });

  it('cancels an upload whose stored object has another size and deletes the object', async () => {
    const file = await encryptForRoom(member, roomId, randomBytes(4096));
    expect((await startUpload(member, roomId, file)).status).toBe(201);
    const objectKey = (await fileRowOf(file.fileId))?.object_key ?? '';
    // Written around the presigned URL (as by a compromised client with storage access).
    await writeObject(objectKey, file.content.ciphertext.subarray(0, 100));
    expect(errorCode(await complete(member, roomId, file.fileId))).toBe('UPLOAD_SIZE_MISMATCH');
    const row = await fileRowOf(file.fileId);
    expect(row).toMatchObject({ status: 'DELETED', wrapped_dek: null, manifest_ciphertext: null });
    expect(row?.object_deleted_at).not.toBeNull();
    expect(await storedObject(objectKey), 'the object is deleted').toBeNull();
    expect(errorCode(await complete(member, roomId, file.fileId))).toBe('FILE_NOT_PENDING');
    expect(
      api.events.some((e) => e.name === 'FILE_UPLOAD_CANCELLED' && e.details?.['reason'] === 'SIZE_MISMATCH'),
    ).toBe(true);
  });

  it('abandons an upload completed after the completion window', async () => {
    const file = await encryptForRoom(member, roomId, randomBytes(128));
    const started = await startUpload(member, roomId, file);
    await putObject(uploadUrlOf(started), file.content.ciphertext);
    api.clock.advance(FILE_LIMITS.completionWindowMs + 1000);
    expect(errorCode(await complete(member, roomId, file.fileId))).toBe('UPLOAD_EXPIRED');
    expect((await fileRowOf(file.fileId))?.status).toBe('DELETED');
  });

  it('cancels pending uploads when the room is write-locked before completion (PC-16)', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Files lock room');
    const uploader = await personWithVault(api, db);
    const leaving = await personWithVault(api, db);
    await inviteAndAccept(owner, room, uploader, 'MEMBER');
    await inviteAndAccept(owner, room, leaving, 'MEMBER');
    const file = await encryptForRoom(uploader, room, randomBytes(256));
    const started = await startUpload(uploader, room, file);
    await putObject(uploadUrlOf(started), file.content.ciphertext);
    const objectKey = (await fileRowOf(file.fileId))?.object_key ?? '';
    expect((await owner.browser.request('POST', `/rooms/${room}/members/${leaving.userId}/remove`, {})).status).toBe(
      200,
    );
    expect(errorCode(await complete(uploader, room, file.fileId))).toBe('REKEY_REQUIRED');
    expect((await fileRowOf(file.fileId))?.status).toBe('DELETED');
    expect(await storedObject(objectKey)).toBeNull();
    // New uploads are refused while the room is REKEY_REQUIRED, before anything is stored.
    const next = await encryptForRoom(uploader, room, randomBytes(16));
    expect(errorCode(await startUpload(uploader, room, next))).toBe('REKEY_REQUIRED');
    expect(await fileRowOf(next.fileId)).toBeUndefined();
  });

  it('a member removed during an upload cannot complete it; the worker removes it later', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Files removal room');
    const uploader = await personWithVault(api, db);
    await inviteAndAccept(owner, room, uploader, 'MEMBER');
    const file = await encryptForRoom(uploader, room, randomBytes(256));
    const started = await startUpload(uploader, room, file);
    await putObject(uploadUrlOf(started), file.content.ciphertext);
    expect((await owner.browser.request('POST', `/rooms/${room}/members/${uploader.userId}/remove`, {})).status).toBe(
      200,
    );
    expect(errorCode(await complete(uploader, room, file.fileId))).toBe('NOT_FOUND');
    expect((await fileRowOf(file.fileId))?.status).toBe('PENDING_UPLOAD');
  });
});

describe('upload refusals (AZ-16, PC-16, PC-08, CP-16, CM-T041)', () => {
  it('refuses VIEWERs, stale key versions and reused file IDs without storing anything', async () => {
    const file = await encryptForRoom(viewer, roomId, randomBytes(32));
    const before = await wrapCount(roomId);
    expect(errorCode(await startUpload(viewer, roomId, file))).toBe('FORBIDDEN');
    expect(errorCode(await startUpload(member, roomId, file, { keyVersion: 2 }))).toBe('KEY_VERSION_STALE');
    expect(await fileRowOf(file.fileId)).toBeUndefined();
    expect(await wrapCount(roomId)).toBe(before);
    const { fileId } = await uploadFile(member, roomId, randomBytes(32));
    const reuse = await encryptForRoom(member, roomId, randomBytes(32));
    expect(errorCode(await startUpload(member, roomId, reuse, { fileId }))).toBe('FILE_ID_UNAVAILABLE');
    const otherRoom = await createRoom(owner, 'STANDARD', 'Files other room');
    expect(
      errorCode(
        await startUpload(owner, otherRoom, await encryptForRoom(owner, otherRoom, randomBytes(8)), { fileId }),
      ),
    ).toBe('FILE_ID_UNAVAILABLE');
  });

  it('accepts no plaintext metadata, caller identity or storage path in the request', async () => {
    const file = await encryptForRoom(member, roomId, randomBytes(32));
    for (const field of [
      { name: 'secret-plan.docx' },
      { type: 'application/pdf' },
      { mimeType: 'text/plain' },
      { plaintextSha256: randomBytes(32).toString('base64url') },
      { fek: randomBytes(32).toString('base64url') },
      { objectKey: '../other-room/x' },
      { uploaderId: owner.userId },
      { roomId: randomUUID() },
      { suite: 'CM0' },
    ]) {
      const response = await startUpload(member, roomId, file, field);
      expect(response.status, JSON.stringify(field)).toBe(400);
    }
    expect(await fileRowOf(file.fileId)).toBeUndefined();
  });

  it('applies the expiry rules of each profile (PC-08)', async () => {
    const day = 24 * 60 * 60_000;
    const iso = (ms: number): string => new Date(api.clock.now().getTime() + ms).toISOString();
    const file = () => encryptForRoom(member, roomId, randomBytes(8));
    expect(errorCode(await startUpload(member, roomId, await file(), { expiresAt: iso(-1000) }))).toBe(
      'EXPIRY_NOT_ALLOWED',
    );
    expect((await startUpload(member, roomId, await file(), { expiresAt: iso(3650 * day) })).status).toBe(201);
    const mfaOwner = await mfaPersonWithVault(api, db);
    for (const [profile, max] of [
      ['CONFIDENTIAL', 90],
      ['RESTRICTED', 30],
    ] as const) {
      const room = await createRoom(mfaOwner, profile, `Files ${profile} room`);
      const encrypted = () => encryptForRoom(mfaOwner, room, randomBytes(8));
      expect(errorCode(await startUpload(mfaOwner, room, await encrypted())), profile).toBe('EXPIRY_NOT_ALLOWED');
      expect(
        errorCode(await startUpload(mfaOwner, room, await encrypted(), { expiresAt: iso((max + 1) * day) })),
        profile,
      ).toBe('EXPIRY_NOT_ALLOWED');
      expect(
        (await startUpload(mfaOwner, room, await encrypted(), { expiresAt: iso(max * day - 60_000) })).status,
        profile,
      ).toBe(201);
    }
  });

  it('enforces the pending-upload limit and the room and account quotas (CM-T041)', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Files quota room');
    const uploader = await personWithVault(api, db);
    await inviteAndAccept(owner, room, uploader, 'MEMBER');
    for (let i = 0; i < FILE_QUOTAS.pendingUploadsPerUser; i++) {
      expect((await startUpload(uploader, room, await encryptForRoom(uploader, room, randomBytes(8)))).status).toBe(
        201,
      );
    }
    expect(errorCode(await startUpload(uploader, room, await encryptForRoom(uploader, room, randomBytes(8))))).toBe(
      'FILE_QUOTA_EXCEEDED',
    );
    // Room quota: the room's stored ciphertext (fixture rows of the owner) leaves too little room.
    const filler = async (uploaderId: string, room2: string, size: number) =>
      insert(
        db,
        'encrypted_files',
        fileRow({ roomId: room2, ownerId: uploaderId } as never, {
          status: 'AVAILABLE',
          uploaded_at: new Date(),
          ciphertext_size: size,
        }),
      );
    const fullRoom = await createRoom(owner, 'STANDARD', 'Files full room');
    const max = FILE_LIMITS.maxCiphertextBytes;
    for (let used = 0; used + max <= FILE_QUOTAS.perRoomBytes; used += max) await filler(owner.userId, fullRoom, max);
    const big = await encryptForRoom(owner, fullRoom, randomBytes(8));
    expect(errorCode(await startUpload(owner, fullRoom, big, { ciphertextSize: max }))).toBe('FILE_QUOTA_EXCEEDED');
    expect((await startUpload(owner, fullRoom, big)).status, 'a small file still fits').toBe(201);
    // Account quota across rooms.
    const heavy = await personWithVault(api, db);
    const rooms = [
      await createRoom(heavy, 'STANDARD', 'Files heavy 1'),
      await createRoom(heavy, 'STANDARD', 'Files heavy 2'),
    ];
    let used = 0;
    for (let i = 0; used + max <= FILE_QUOTAS.perUserBytes; i++, used += max) {
      await filler(heavy.userId, rooms[i % 2] ?? '', max);
    }
    const third = await createRoom(heavy, 'STANDARD', 'Files heavy 3');
    expect(
      errorCode(
        await startUpload(heavy, third, await encryptForRoom(heavy, third, randomBytes(8)), { ciphertextSize: max }),
      ),
    ).toBe('FILE_QUOTA_EXCEEDED');
  }, 120_000);

  it('makes the room REKEY_REQUIRED when RWK_v reaches its wrap bound (CP-16)', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Files wrap room');
    await db.query('UPDATE room_key_versions SET wrap_count = 1048576 WHERE room_id = $1', [room]);
    const file = await encryptForRoom(owner, room, randomBytes(8));
    expect(errorCode(await startUpload(owner, room, file))).toBe('REKEY_REQUIRED');
    const state = await db.query<{ key_state: string; rekey_reasons: string }>(
      'SELECT key_state::text, rekey_reasons::text FROM rooms WHERE id = $1',
      [room],
    );
    expect(state.rows[0]).toEqual({ key_state: 'REKEY_REQUIRED', rekey_reasons: '{WRAP_LIMIT_REACHED}' });
    expect(await fileRowOf(file.fileId)).toBeUndefined();
  });

  it('answers STORAGE_UNAVAILABLE without storing anything when storage is not configured', async () => {
    const offline = await startAuthApi({ storage: unavailableObjectStore });
    try {
      const who = await personWithVault(offline, db);
      const room = await createRoom(who, 'STANDARD', 'Files offline room');
      const file = await encryptForRoom(who, room, randomBytes(8));
      const response = await startUpload(who, room, file);
      expect(response.status).toBe(503);
      expect(errorCode(response)).toBe('STORAGE_UNAVAILABLE');
      expect(await fileRowOf(file.fileId)).toBeUndefined();
    } finally {
      await offline.close();
    }
  });
});
