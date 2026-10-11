import { FILE_LIMITS } from '@ciphermesh/shared';
import { randomBytes } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { runFileCleanup } from '../../apps/api/src/db/file-cleanup';
import { runRoomCleanup } from '../../apps/api/src/db/room-cleanup';
import { createLogger } from '../../apps/api/src/logging/logger';
import { startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import {
  encryptForRoom,
  putObject,
  requireStorageEnv,
  startUpload,
  storedObject,
  uploadFile,
  uploadUrlOf,
  writeObject,
} from '../helpers/files';
import { createRoom, personWithVault, stepUp, type Person } from '../helpers/rooms';

// Phase 7, CM-T040: the worker (as cm_worker, which cannot DELETE file rows) tombstones expired,
// abandoned and room-deleted files and deletes their storage objects with retries; a room becomes
// DELETED only when every file is a tombstone without an object. Real PostgreSQL and storage.
let api: AuthTestApi;
let db: pg.Client;
let worker: Database;
let owner: Person;

/** The real deletion the worker uses, with the runtime credential. */
async function deleteObject(objectKey: string): Promise<void> {
  const { storageClient, storageTarget } = await import('../../scripts/storage/lib.mjs');
  const { endpoint, bucket } = storageTarget();
  const response = await storageClient('runtime').fetch(`${endpoint}/${bucket}/${objectKey}`, { method: 'DELETE' });
  if (response.status !== 204 && response.status !== 404) throw new Error('delete failed');
}

beforeAll(async () => {
  loadDatabaseTestEnv();
  requireStorageEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  worker = createDatabase({
    url: new SecretValue(testDatabase(inject('databaseName')).url('worker')),
    logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
    poolMax: 1,
  });
  owner = await personWithVault(api, db);
}, 120_000);
afterAll(async () => {
  await api.close();
  await worker.close();
  await db.end();
});

const rowOf = async (fileId: string) =>
  (await db.query('SELECT * FROM encrypted_files WHERE id = $1', [fileId])).rows[0] as Record<string, unknown>;

describe('file cleanup by the worker (CM-T040)', () => {
  it('tombstones expired files and abandoned uploads and deletes their objects', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Cleanup room');
    const expiresAt = new Date(api.clock.now().getTime() + 60_000).toISOString();
    const expired = await uploadFile(owner, room, Buffer.from('expiring'), { overrides: { expiresAt } });
    const kept = await uploadFile(owner, room, Buffer.from('kept'));
    const abandoned = await encryptForRoom(owner, room, randomBytes(64));
    await putObject(uploadUrlOf(await startUpload(owner, room, abandoned)), abandoned.content.ciphertext);
    const keys = {
      expired: (await rowOf(expired.fileId))['object_key'] as string,
      kept: (await rowOf(kept.fileId))['object_key'] as string,
      abandoned: (await rowOf(abandoned.fileId))['object_key'] as string,
    };

    const later = new Date(Date.now() + FILE_LIMITS.completionWindowMs + 120_000);
    const result = await runFileCleanup(worker.prisma, later, deleteObject);
    expect(result.expired).toBeGreaterThanOrEqual(1);
    expect(result.abandoned).toBeGreaterThanOrEqual(1);
    expect(result.objectsFailed).toBe(0);
    for (const fileId of [expired.fileId, abandoned.fileId]) {
      expect(await rowOf(fileId)).toMatchObject({ status: 'DELETED', wrapped_dek: null, manifest_ciphertext: null });
      expect((await rowOf(fileId))['object_deleted_at']).not.toBeNull();
    }
    expect(await storedObject(keys.expired)).toBeNull();
    expect(await storedObject(keys.abandoned)).toBeNull();
    expect((await rowOf(kept.fileId))['status']).toBe('AVAILABLE');
    expect(await storedObject(keys.kept)).not.toBeNull();
  });

  it('retries object deletion on later runs when storage fails', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Cleanup retry room');
    const { fileId } = await uploadFile(owner, room, Buffer.from('retry'));
    const objectKey = (await rowOf(fileId))['object_key'] as string;
    await db.query(
      "UPDATE encrypted_files SET status = 'DELETED', wrapped_dek = NULL, manifest_ciphertext = NULL, deleted_at = now() WHERE id = $1",
      [fileId],
    );
    const failing = await runFileCleanup(worker.prisma, new Date(), () => Promise.reject(new Error('storage down')));
    expect(failing.objectsFailed).toBeGreaterThanOrEqual(1);
    expect((await rowOf(fileId))['object_deleted_at']).toBeNull();
    expect(await storedObject(objectKey)).not.toBeNull();
    const retried = await runFileCleanup(worker.prisma, new Date(), deleteObject);
    expect(retried.objectsDeleted).toBeGreaterThanOrEqual(1);
    expect((await rowOf(fileId))['object_deleted_at']).not.toBeNull();
    expect(await storedObject(objectKey)).toBeNull();
  });

  it('finishes a room deletion only after its files are tombstones without objects', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Cleanup deleted room');
    const { fileId } = await uploadFile(owner, room, Buffer.from('in a deleted room'));
    const objectKey = (await rowOf(fileId))['object_key'] as string;
    await stepUp(api, owner);
    expect((await owner.browser.request('POST', `/rooms/${room}/delete`, {})).status).toBe(200);
    const status = async () =>
      (await db.query<{ status: string }>('SELECT status::text FROM rooms WHERE id = $1', [room])).rows[0]?.status;

    // The room step alone waits: the file still has its key material and object.
    await runRoomCleanup(worker.prisma);
    expect(await status()).toBe('DELETING');
    // Files are tombstoned, but storage fails: the room still waits.
    await runFileCleanup(worker.prisma, new Date(), () => Promise.reject(new Error('storage down')));
    expect((await rowOf(fileId))['status']).toBe('DELETED');
    await runRoomCleanup(worker.prisma);
    expect(await status()).toBe('DELETING');
    // Objects deleted: the room becomes DELETED; the tombstone row stays for audit.
    await runFileCleanup(worker.prisma, new Date(), deleteObject);
    await runRoomCleanup(worker.prisma);
    expect(await status()).toBe('DELETED');
    expect(await storedObject(objectKey)).toBeNull();
    expect(await rowOf(fileId)).toMatchObject({ status: 'DELETED', wrapped_dek: null, manifest_ciphertext: null });
  });

  it('cannot delete file rows or resurrect a tombstone (cm_worker grants, guard trigger)', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Cleanup guard room');
    const { fileId } = await uploadFile(owner, room, Buffer.from('guarded'));
    const objectKey = (await rowOf(fileId))['object_key'] as string;
    await writeObject(objectKey, Buffer.from('x'));
    await expect(worker.prisma.$executeRaw`DELETE FROM encrypted_files WHERE id = ${fileId}::uuid`).rejects.toThrow();
    await db.query(
      "UPDATE encrypted_files SET status = 'DELETED', wrapped_dek = NULL, manifest_ciphertext = NULL, deleted_at = now() WHERE id = $1",
      [fileId],
    );
    await expect(db.query("UPDATE encrypted_files SET status = 'AVAILABLE' WHERE id = $1", [fileId])).rejects.toThrow(
      /status transition/,
    );
    await expect(
      db.query('UPDATE encrypted_files SET wrapped_dek = $2 WHERE id = $1', [fileId, randomBytes(48)]),
    ).rejects.toThrow(/key material/);
  });
});
