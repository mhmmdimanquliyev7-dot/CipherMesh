import {
  encryptedFileToWire,
  encryptFile,
  openFile,
  storedFileFromWire,
  type EncryptedFile,
  type EncryptedFileWire,
  type OpenedRoomKey,
} from '@ciphermesh/crypto';
import { randomUUID } from 'node:crypto';
import { expect } from 'vitest';
import { storageClient, storageTarget } from '../../scripts/storage/lib.mjs';
import { openRoom, type Identified } from './room-crypto';

// Encrypted files for the API suites (Phase 7). Files are encrypted by packages/crypto with the
// room key opened exactly as a browser opens it, uploaded to the real local object storage with
// the presigned URL the API issued, and downloaded and decrypted the same way. Content is
// synthetic; nothing here is a real document.

type Response = { readonly status: number; readonly body: Record<string, unknown> };

const STORAGE_VARIABLES = [
  'STORAGE_ENDPOINT',
  'STORAGE_PUBLIC_ENDPOINT',
  'STORAGE_BUCKET',
  'STORAGE_REGION',
  'STORAGE_ACCESS_KEY_ID',
  'STORAGE_SECRET_ACCESS_KEY',
] as const;

/** The storage configuration of the test environment (.env locally, masked values in CI), if any. */
export function storageTestEnv(): Record<string, string> {
  return Object.fromEntries(
    STORAGE_VARIABLES.flatMap((name) => {
      const value = process.env[name];
      return value === undefined || value === '' ? [] : [[name, value]];
    }),
  );
}

/** The files suites fail, not skip, without object storage (`pnpm services:up && pnpm storage:bootstrap`). */
export function requireStorageEnv(): void {
  for (const name of ['STORAGE_ENDPOINT', 'STORAGE_ACCESS_KEY_ID', 'STORAGE_SECRET_ACCESS_KEY'] as const) {
    if (!process.env[name]) throw new Error(`${name} is required for the files suite (see .env.example)`);
  }
}

/** The newest verified key version of the room, opened like the browser opens it. */
export async function currentRoomKey(who: Identified, roomId: string): Promise<OpenedRoomKey> {
  const key = (await openRoom(who, roomId)).at(-1);
  if (key === undefined) throw new Error('no room key');
  return key;
}

export async function encryptForRoom(
  who: Identified,
  roomId: string,
  content: Uint8Array,
  name = 'synthetic.bin',
  type = 'application/octet-stream',
): Promise<EncryptedFile> {
  return encryptFile(await currentRoomKey(who, roomId), {
    fileId: randomUUID(),
    name,
    type,
    content: new Uint8Array(content),
  });
}

/** POST /rooms/{roomId}/files with the encrypted record (fields may be overridden). */
export function startUpload(
  who: Identified,
  roomId: string,
  file: EncryptedFile,
  overrides: Record<string, unknown> = {},
): Promise<Response> {
  return who.browser.request('POST', `/rooms/${roomId}/files`, {
    ...encryptedFileToWire(file),
    expiresAt: null,
    ...overrides,
  });
}

/** PUT to a presigned URL, as the browser does: no credentials, only the bytes. */
export function putObject(url: string, bytes: Uint8Array): Promise<globalThis.Response> {
  return fetch(url, { method: 'PUT', body: new Uint8Array(bytes), redirect: 'error' });
}

export const uploadUrlOf = (response: Response): string => (response.body['upload'] as { url: string }).url;

/** The whole upload: encrypt, announce, PUT the ciphertext, complete. Returns the file ID. */
export async function uploadFile(
  who: Identified,
  roomId: string,
  content: Uint8Array,
  options: { readonly name?: string; readonly type?: string; readonly overrides?: Record<string, unknown> } = {},
): Promise<{ readonly fileId: string; readonly file: EncryptedFile }> {
  const file = await encryptForRoom(who, roomId, content, options.name, options.type);
  const started = await startUpload(who, roomId, file, options.overrides);
  expect(started.status, JSON.stringify(started.body)).toBe(201);
  const put = await putObject(uploadUrlOf(started), file.content.ciphertext);
  expect(put.status).toBe(200);
  const completed = await who.browser.request('POST', `/rooms/${roomId}/files/${file.fileId}/complete`, {});
  expect(completed.status, JSON.stringify(completed.body)).toBe(200);
  return { fileId: file.fileId, file };
}

export interface FileView {
  readonly id: string;
  readonly uploaderId: string;
  readonly keyVersion: number;
  readonly suite: string;
  readonly status: string;
  readonly ciphertextSize: number;
  readonly ciphertextSha256: string;
  readonly keyMaterial: Omit<
    EncryptedFileWire,
    'fileId' | 'keyVersion' | 'suite' | 'ciphertextSize' | 'ciphertextSha256'
  > | null;
}

/** The decoded record the browser builds from GET /rooms/{roomId}/files/{fileId}. */
export function recordOf(roomId: string, view: FileView) {
  if (view.keyMaterial === null) throw new Error('no key material');
  return storedFileFromWire(roomId, {
    fileId: view.id,
    keyVersion: view.keyVersion,
    suite: view.suite,
    ciphertextSize: view.ciphertextSize,
    ciphertextSha256: view.ciphertextSha256,
    ...view.keyMaterial,
  });
}

/** The whole download: key material, presigned GET, authenticated decryption. Returns the plaintext. */
export async function downloadFile(
  who: Identified,
  roomId: string,
  fileId: string,
): Promise<{ readonly name: string; readonly type: string; readonly bytes: Uint8Array }> {
  const meta = await who.browser.request('GET', `/rooms/${roomId}/files/${fileId}`);
  expect(meta.status, JSON.stringify(meta.body)).toBe(200);
  const view = meta.body['file'] as FileView;
  const url = await who.browser.request('POST', `/rooms/${roomId}/files/${fileId}/download-url`, {});
  expect(url.status, JSON.stringify(url.body)).toBe(200);
  const object = await fetch((url.body['download'] as { url: string }).url, { redirect: 'error' });
  expect(object.status).toBe(200);
  const keys = await openRoom(who, roomId);
  const key = keys.find((k) => k.keyVersion === view.keyVersion);
  if (key === undefined) throw new Error('no key for the file version');
  const opened = await openFile(key, recordOf(roomId, view));
  return {
    name: opened.name,
    type: opened.type,
    bytes: await opened.decrypt(new Uint8Array(await object.arrayBuffer())),
  };
}

/** An object's stored bytes, read with the runtime credential (test inspection of storage only). */
export async function storedObject(objectKey: string): Promise<Uint8Array | null> {
  const { endpoint, bucket } = storageTarget();
  const response = await storageClient('runtime').fetch(`${endpoint}/${bucket}/${objectKey}`);
  if (response.status === 404) return null;
  expect(response.status).toBe(200);
  return new Uint8Array(await response.arrayBuffer());
}

/** Writes an object directly (test setup for tampering and cleanup tests only). */
export async function writeObject(objectKey: string, bytes: Uint8Array): Promise<void> {
  const { endpoint, bucket } = storageTarget();
  const response = await storageClient('runtime').fetch(`${endpoint}/${bucket}/${objectKey}`, {
    method: 'PUT',
    body: new Uint8Array(bytes),
  });
  expect(response.status).toBe(200);
}
