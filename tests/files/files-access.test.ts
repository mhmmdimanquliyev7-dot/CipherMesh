import { CryptoErrorCode, isCryptoError, openFile } from '@ciphermesh/crypto';
import { FILE_LIST_PAGE_SIZE } from '@ciphermesh/shared';
import { randomBytes } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { createS3ObjectStore, type ObjectStore } from '../../apps/api/src/storage/object-store';
import { loadConfig } from '../../apps/api/src/config/env';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { fileRow, insert } from '../helpers/db-fixtures';
import {
  currentRoomKey,
  downloadFile,
  recordOf,
  requireStorageEnv,
  storageTestEnv,
  storedObject,
  uploadFile,
  writeObject,
  type FileView,
} from '../helpers/files';
import { inviteAndAccept, vaultOf } from '../helpers/room-crypto';
import { createRoom, mfaPersonWithVault, personWithVault, stepUp, type Person } from '../helpers/rooms';

// Phase 7, CM-T039 to CM-T041 (DF-08, data-model 5): reading, downloading and deleting encrypted
// files. Real API, PostgreSQL as cm_api, real object storage, real crypto. Tampering is done to
// the stored object and to the records the API serves; the browser code must refuse every change.
let api: AuthTestApi;
let db: pg.Client;
let owner: Person;
let admin: Person;
let member: Person;
let other: Person;
let viewer: Person;
let roomId: string;

beforeAll(async () => {
  loadDatabaseTestEnv();
  requireStorageEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  owner = await personWithVault(api, db);
  [admin, member, other, viewer] = [
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
  ];
  roomId = await createRoom(owner, 'STANDARD', 'Files access room');
  await inviteAndAccept(owner, roomId, admin, 'ADMIN');
  await inviteAndAccept(owner, roomId, member, 'MEMBER');
  await inviteAndAccept(owner, roomId, other, 'MEMBER');
  await inviteAndAccept(owner, roomId, viewer, 'VIEWER');
}, 180_000);
afterAll(async () => {
  await api.close();
  await db.end();
});

const listOf = async (who: Person, room = roomId, cursor?: string) => {
  const response = await who.browser.request(
    'GET',
    `/rooms/${room}/files${cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`}`,
  );
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  return response.body as { files: FileView[]; nextCursor: string | null };
};
const remove = (who: Person, fileId: string, room = roomId) =>
  who.browser.request('POST', `/rooms/${room}/files/${fileId}/delete`, {});
const rowOf = async (fileId: string) =>
  (await db.query('SELECT * FROM encrypted_files WHERE id = $1', [fileId])).rows[0] as Record<string, unknown>;

describe('the file list (AZ-17, OL-08)', () => {
  it('shows readable files with key material and server-side metadata only', async () => {
    const { fileId } = await uploadFile(member, roomId, Buffer.from('listed'), {
      name: 'listed.txt',
      type: 'text/plain',
    });
    const { files } = await listOf(viewer);
    const view = files.find((f) => f.id === fileId);
    expect(view).toMatchObject({ uploaderId: member.userId, status: 'AVAILABLE', keyVersion: 1, suite: 'CM1' });
    expect(Object.keys(view ?? {}).sort()).toEqual([
      'ciphertextSha256',
      'ciphertextSize',
      'createdAt',
      'expiresAt',
      'id',
      'keyMaterial',
      'keyVersion',
      'status',
      'suite',
      'uploadedAt',
      'uploaderId',
    ]);
    expect(JSON.stringify(files)).not.toContain('listed.txt');
    // The browser decrypts the name from the list alone.
    const opened = await openFile(await currentRoomKey(viewer, roomId), recordOf(roomId, view as FileView));
    expect(opened.name).toBe('listed.txt');
  });

  it('pages newest first with a cursor', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Files paging room');
    const ids: string[] = [];
    for (let i = 0; i < FILE_LIST_PAGE_SIZE + 2; i++) {
      const row = fileRow({ roomId: room, ownerId: owner.userId } as never, {
        status: 'AVAILABLE',
        uploaded_at: new Date(),
        created_at: new Date(Date.now() - i * 1000),
      });
      await insert(db, 'encrypted_files', row);
      ids.push(row['id'] as string);
    }
    const first = await listOf(owner, room);
    expect(first.files.map((f) => f.id)).toEqual(ids.slice(0, FILE_LIST_PAGE_SIZE));
    const second = await listOf(owner, room, first.nextCursor ?? '');
    expect(second.files.map((f) => f.id)).toEqual(ids.slice(FILE_LIST_PAGE_SIZE));
    expect(second.nextCursor).toBeNull();
  });
});

describe('tampering is detected in the browser and releases no plaintext (CM-T039, T-07, EV-07-04)', () => {
  it('a bit flip in the stored object, the manifest or the wrapped FEK is an integrity error', async () => {
    const content = Buffer.from('Synthetic tamper target CM-TAMPER, no real data.\n'.repeat(20));
    const { fileId, file } = await uploadFile(member, roomId, content, { name: 'tamper.txt', type: 'text/plain' });
    const objectKey = (await rowOf(fileId))['object_key'] as string;
    const flipped = new Uint8Array(file.content.ciphertext);
    flipped[100] = (flipped[100] ?? 0) ^ 0x01;
    await writeObject(objectKey, flipped);
    await expect(downloadFile(viewer, roomId, fileId)).rejects.toSatisfy((e: unknown) =>
      isCryptoError(e, CryptoErrorCode.FILE_INTEGRITY_FAILED),
    );
    // Even if the stored ciphertext hash were changed to match, the AES-GCM tag refuses it.
    const meta = (await viewer.browser.request('GET', `/rooms/${roomId}/files/${fileId}`)).body['file'] as FileView;
    const forged = {
      ...recordOf(roomId, meta),
      ciphertextSha256: new Uint8Array((await import('node:crypto')).createHash('sha256').update(flipped).digest()),
    };
    const opened = await openFile(await currentRoomKey(viewer, roomId), forged);
    await expect(opened.decrypt(flipped)).rejects.toSatisfy((e: unknown) =>
      isCryptoError(e, CryptoErrorCode.AUTHENTICATION_FAILED),
    );
    // A manifest or wrapped FEK changed in the database fails before any content is decrypted.
    const key = await currentRoomKey(viewer, roomId);
    for (const part of ['manifest', 'wrappedFek'] as const) {
      const record = recordOf(roomId, meta);
      const changed = new Uint8Array(record[part].ciphertext);
      changed[3] = (changed[3] ?? 0) ^ 0x80;
      await expect(openFile(key, { ...record, [part]: { ...record[part], ciphertext: changed } })).rejects.toSatisfy(
        (e: unknown) => isCryptoError(e, CryptoErrorCode.AUTHENTICATION_FAILED),
      );
    }
    // The original object restored: the same download succeeds.
    await writeObject(objectKey, file.content.ciphertext);
    expect(Buffer.from((await downloadFile(viewer, roomId, fileId)).bytes).equals(content)).toBe(true);
  });

  it('an object swapped with another file of the room is refused', async () => {
    const a = await uploadFile(member, roomId, randomBytes(1000));
    const b = await uploadFile(member, roomId, randomBytes(1000));
    const keyA = (await rowOf(a.fileId))['object_key'] as string;
    await writeObject(keyA, b.file.content.ciphertext);
    await expect(downloadFile(owner, roomId, a.fileId)).rejects.toSatisfy((e: unknown) =>
      isCryptoError(e, CryptoErrorCode.FILE_INTEGRITY_FAILED),
    );
  });
});

describe('PC-12: VIEWERs in RESTRICTED rooms obtain no key material or ciphertext', () => {
  it('lists server-side metadata only and refuses key material and download URLs', async () => {
    const restrictedOwner = await mfaPersonWithVault(api, db);
    const restrictedViewer = await mfaPersonWithVault(api, db);
    const restrictedMember = await mfaPersonWithVault(api, db);
    const room = await createRoom(restrictedOwner, 'RESTRICTED', 'Files restricted room');
    await stepUp(api, restrictedOwner, restrictedOwner.secret);
    for (const [who, role] of [
      [restrictedViewer, 'VIEWER'],
      [restrictedMember, 'MEMBER'],
    ] as const) {
      await inviteAndAccept(restrictedOwner, room, who, role, {
        confirmedFingerprint: vaultOf(who).identity.fingerprint,
      });
    }
    const expiresAt = new Date(api.clock.now().getTime() + 24 * 60 * 60_000).toISOString();
    const { fileId } = await uploadFile(restrictedMember, room, Buffer.from('restricted'), {
      overrides: { expiresAt },
    });
    const { files } = await listOf(restrictedViewer, room);
    expect(files.map((f) => f.id)).toContain(fileId);
    expect(files.every((f) => f.keyMaterial === null)).toBe(true);
    expect(errorCode(await restrictedViewer.browser.request('GET', `/rooms/${room}/files/${fileId}`))).toBe(
      'FORBIDDEN',
    );
    // A download URL is also a PC-03 sensitive operation, checked first (evaluation order step 5):
    // with a fresh step-up the VIEWER still gets the PC-12 refusal.
    await stepUp(api, restrictedViewer, restrictedViewer.secret);
    expect(
      errorCode(await restrictedViewer.browser.request('POST', `/rooms/${room}/files/${fileId}/download-url`, {})),
    ).toBe('FORBIDDEN');
    expect(api.events.some((e) => e.name === 'ROOM_ACCESS_DENIED' && e.details?.['reason'] === 'PROFILE_PC_12')).toBe(
      true,
    );
    // Members of the same room still read, and the issuance is audited at the FULL level (PC-13).
    expect((await downloadFile(restrictedOwner, room, fileId)).bytes.length).toBe(10);
    expect(api.events.some((e) => e.name === 'FILE_DOWNLOAD_ISSUED' && e.details?.['fileId'] === fileId)).toBe(true);
  }, 120_000);

  it('does not audit download URLs in STANDARD rooms (BASELINE level)', async () => {
    const { fileId } = await uploadFile(member, roomId, Buffer.from('baseline'));
    await downloadFile(member, roomId, fileId);
    expect(api.events.some((e) => e.name === 'FILE_DOWNLOAD_ISSUED' && e.details?.['fileId'] === fileId)).toBe(false);
  });
});

describe('expiry is enforced at read time (INV-14, CM-T040)', () => {
  it('refuses an expired file immediately, before any cleanup runs', async () => {
    const expiresAt = new Date(api.clock.now().getTime() + 60_000).toISOString();
    const { fileId } = await uploadFile(member, roomId, Buffer.from('short-lived'), { overrides: { expiresAt } });
    expect((await downloadFile(viewer, roomId, fileId)).bytes.length).toBe(11);
    api.clock.advance(61_000);
    expect((await listOf(viewer)).files.map((f) => f.id)).not.toContain(fileId);
    expect(errorCode(await viewer.browser.request('GET', `/rooms/${roomId}/files/${fileId}`))).toBe('NOT_FOUND');
    expect(errorCode(await viewer.browser.request('POST', `/rooms/${roomId}/files/${fileId}/download-url`, {}))).toBe(
      'NOT_FOUND',
    );
    expect((await rowOf(fileId))['status'], 'the row is untouched until the worker runs').toBe('AVAILABLE');
  });
});

describe('deletion (AZ-18, data-model 5)', () => {
  it('lets the uploader, ADMINs and the OWNER delete; others and VIEWERs are refused', async () => {
    const mine = await uploadFile(member, roomId, Buffer.from('mine'));
    expect(errorCode(await remove(other, mine.fileId)), 'a MEMBER deletes only own files').toBe('FORBIDDEN');
    expect(errorCode(await remove(viewer, mine.fileId))).toBe('FORBIDDEN');
    expect((await rowOf(mine.fileId))['status']).toBe('AVAILABLE');
    expect((await remove(member, mine.fileId)).status).toBe(200);
    for (const deleter of [admin, owner]) {
      const theirs = await uploadFile(member, roomId, Buffer.from('theirs'));
      expect((await remove(deleter, theirs.fileId)).status).toBe(200);
    }
  });

  it('leaves no object, wrapped FEK or manifest in the live system; the tombstone stays', async () => {
    const { fileId } = await uploadFile(member, roomId, Buffer.from('to be deleted'));
    const objectKey = (await rowOf(fileId))['object_key'] as string;
    expect(await storedObject(objectKey)).not.toBeNull();
    expect((await remove(member, fileId)).status).toBe(200);
    const row = await rowOf(fileId);
    expect(row).toMatchObject({ status: 'DELETED', wrapped_dek: null, manifest_ciphertext: null });
    expect(row['deleted_at']).not.toBeNull();
    expect(row['object_deleted_at']).not.toBeNull();
    expect(await storedObject(objectKey)).toBeNull();
    expect((await listOf(owner)).files.map((f) => f.id)).not.toContain(fileId);
    expect(errorCode(await owner.browser.request('GET', `/rooms/${roomId}/files/${fileId}`))).toBe('NOT_FOUND');
    expect(errorCode(await remove(member, fileId)), 'a second deletion finds nothing').toBe('NOT_FOUND');
    expect(api.events.some((e) => e.name === 'FILE_DELETED' && e.details?.['fileId'] === fileId)).toBe(true);
  });

  it('allows deletion while the room is REKEY_REQUIRED (only content writes are locked)', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Files delete-while-locked room');
    const leaving = await personWithVault(api, db);
    await inviteAndAccept(owner, room, leaving, 'MEMBER');
    const { fileId } = await uploadFile(owner, room, Buffer.from('locked'));
    expect((await owner.browser.request('POST', `/rooms/${room}/members/${leaving.userId}/remove`, {})).status).toBe(
      200,
    );
    expect((await remove(owner, fileId, room)).status).toBe(200);
  });

  it('commits the tombstone even when storage fails; the object waits for the worker', async () => {
    const config = loadConfig({
      NODE_ENV: 'test',
      APP_ORIGIN: 'https://ciphermesh.test',
      DATABASE_URL: 'postgresql://cm_api:unused@127.0.0.1:1/unused',
      TOTP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
      TOTP_ENCRYPTION_KEY_ID: 'files-test',
      IDENTIFIER_HMAC_KEY: randomBytes(32).toString('base64url'),
      ...storageTestEnv(),
    });
    const real = createS3ObjectStore(
      config.storage ??
        (() => {
          throw new Error('no storage');
        })(),
    );
    const failingDelete: ObjectStore = { ...real, delete: () => Promise.reject(new Error('storage down')) };
    const flaky = await startAuthApi({ storage: failingDelete });
    try {
      const who = await personWithVault(flaky, db);
      const room = await createRoom(who, 'STANDARD', 'Files flaky storage room');
      const { fileId } = await uploadFile(who, room, Buffer.from('flaky'));
      expect((await who.browser.request('POST', `/rooms/${room}/files/${fileId}/delete`, {})).status).toBe(200);
      const row = await rowOf(fileId);
      expect(row).toMatchObject({ status: 'DELETED', wrapped_dek: null, object_deleted_at: null });
      expect(await storedObject(row['object_key'] as string), 'the object is still there').not.toBeNull();
    } finally {
      await flaky.close();
    }
  });
});
